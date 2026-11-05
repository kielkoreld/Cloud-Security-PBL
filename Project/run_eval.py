"""시나리오를 실행하고 그래프 탐지의 오탐·미탐을 집계한다."""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from detect_graph import judge
from parse_events import Event, dedupe, parse_line, parse_time

PROJECT = Path(__file__).resolve().parent
REPO = PROJECT.parent
RESULTS = PROJECT / "results"


# types는 채점용 정답이다. judge()에는 넘기지 않는다.
SCENARIOS = [
    {
        "id": "normal",
        "role": "benign",
        "script": REPO / "category1" / "normal.sh",
        "types": set(),
        "note": "설정 읽기, /tmp 기록, health check",
    },
    {
        "id": "benign_repeat",
        "role": "benign",
        "script": PROJECT / "scenarios" / "benign_repeat.sh",
        "types": set(),
        "note": "다른 이름의 임시 파일을 쓰고 읽기만 함",
    },
    {
        "id": "benign_debug_env",
        "role": "benign",
        "script": PROJECT / "scenarios" / "benign_debug_env.sh",
        "types": set(),
        "note": "운영 확인으로 환경변수만 출력",
    },
    {
        "id": "benign_tmp_tool",
        "role": "benign",
        "script": PROJECT / "scenarios" / "benign_tmp_tool.sh",
        "types": set(),
        "note": "로컬 점검 스크립트를 /tmp에 쓰고 실행",
    },
    {
        "id": "abnormal_1",
        "role": "attack",
        "script": REPO / "category1" / "abnormal_1.sh",
        "types": {"environment_discovery", "credential_access"},
        "note": "환경변수 출력, environ 읽기, 자격증명 경로 확인",
    },
    {
        "id": "abnormal_2",
        "role": "attack",
        "script": REPO / "category1" / "abnormal_2.sh",
        "types": {"token_access"},
        "note": "backend의 ServiceAccount 토큰 읽기",
    },
    {
        "id": "abnormal_3",
        "role": "attack",
        "script": REPO / "category1" / "abnormal_3.sh",
        "types": {"payload_execution"},
        "note": "/tmp 스크립트를 쓴 뒤 sh로 실행",
    },
    {
        "id": "attack_token_head",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_token_head.sh",
        "types": {"token_access"},
        "note": "frontend에서 head로 토큰 1바이트만 읽기",
    },
    {
        "id": "attack_env_frontend",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_env_frontend.sh",
        "types": {"environment_discovery"},
        "note": "frontend에서 env와 /proc/self/environ",
    },
    {
        "id": "attack_shadow_read",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_shadow_read.sh",
        "types": {"credential_access"},
        "note": "컨테이너 /etc/shadow 읽기",
    },
    {
        "id": "attack_payload_other_name",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_payload_other_name.sh",
        "types": {"payload_execution"},
        "note": "다른 이름의 /tmp 스크립트 작성 후 실행",
    },
    {
        "id": "attack_inline_payload",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_inline_payload.sh",
        "types": {"payload_execution"},
        "note": "파일 내용을 셸 문자열로 실행하고 경로는 직접 실행하지 않음",
    },
    {
        "id": "attack_ls_only",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_ls_only.sh",
        "types": {"credential_access"},
        "note": "자격증명 경로의 존재만 확인",
    },
    {
        "id": "attack_host_recon",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_host_recon.sh",
        "types": {"host_discovery"},
        "note": "커널 버전과 CPU 정보 읽기",
    },
    {
        "id": "attack_cron_persist",
        "role": "attack",
        "script": PROJECT / "scenarios" / "attack_cron_persist.sh",
        "types": {"persistence"},
        "note": "네트워크 없는 cron 등록 후 삭제",
    },
]


def _run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def collect_events(start: datetime, end: datetime, pad: int = 1, since_pad: int = 3) -> list[Event]:
    since = (start - timedelta(seconds=since_pad)).strftime("%Y-%m-%dT%H:%M:%SZ")
    logs = _run(
        [
            "kubectl",
            "logs",
            "-n",
            "falco",
            "-l",
            "app.kubernetes.io/name=falco",
            "-c",
            "falco",
            "--prefix",
            f"--since-time={since}",
        ],
        timeout=90,
    )
    if logs.returncode != 0:
        raise RuntimeError(logs.stderr.strip() or "kubectl logs failed")
    events: list[Event] = []
    for line in logs.stdout.splitlines():
        if "PBL_EVENT" not in line and "PBL File" not in line and "PBL Process" not in line:
            continue
        event = parse_line(line)
        if event is None or not event.time:
            continue
        try:
            stamped = parse_time(event.time)
        except ValueError:
            continue
        if start - timedelta(seconds=pad) <= stamped <= end + timedelta(seconds=pad):
            events.append(event)
    return dedupe(events)


def compare(judgment: dict, spec: dict) -> dict:
    predicted = set(judgment["types"])
    truth = set(spec["types"])
    verdict_fp = spec["role"] == "benign" and judgment["verdict"] == "attack"
    verdict_fn = spec["role"] == "attack" and judgment["verdict"] == "benign"
    return {
        "verdict_false_positive": verdict_fp,
        "verdict_false_negative": verdict_fn,
        "type_false_positives": sorted(predicted - truth),
        "type_false_negatives": sorted(truth - predicted),
    }


def run_scenario(spec: dict, retry: bool = True) -> dict:
    start = datetime.now(timezone.utc)
    since = (start - timedelta(seconds=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    log_path = RESULTS / f".{spec['id']}.log"
    RESULTS.mkdir(parents=True, exist_ok=True)
    stream = log_path.open("w", encoding="utf-8")
    follower = subprocess.Popen(
        [
            "stdbuf",
            "-oL",
            "kubectl",
            "logs",
            "-n",
            "falco",
            "-l",
            "app.kubernetes.io/name=falco",
            "-c",
            "falco",
            "--prefix",
            f"--since-time={since}",
            "--follow",
        ],
        stdout=stream,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    time.sleep(2)
    completed = _run(["bash", str(spec["script"])], timeout=120)
    time.sleep(4)
    end = datetime.now(timezone.utc)
    follower.terminate()
    try:
        follower.wait(timeout=5)
    except subprocess.TimeoutExpired:
        follower.kill()
    stream.close()
    events = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "PBL_EVENT" not in line and "PBL File" not in line and "PBL Process" not in line and "PBL Path" not in line:
            continue
        event = parse_line(line)
        if event is None or not event.time:
            continue
        try:
            stamped = parse_time(event.time)
        except ValueError:
            continue
        if start - timedelta(seconds=1) <= stamped <= end + timedelta(seconds=1):
            events.append(event)
    events = dedupe(events)
    if not events:
        events = collect_events(start, end, pad=15, since_pad=20)
    log_path.unlink(missing_ok=True)
    if not events and retry:
        time.sleep(2)
        return run_scenario(spec, retry=False)
    # 시나리오 이름과 정답은 여기 들어오지 않는다.
    judgment = judge(events)
    scored = compare(judgment, spec)
    return {
        "id": spec["id"],
        "truth_role": spec["role"],
        "truth_types": sorted(spec["types"]),
        "note": spec["note"],
        "script_exit": completed.returncode,
        "script_stderr": completed.stderr[-1000:],
        "event_count": len(events),
        "predicted_verdict": judgment["verdict"],
        "predicted_types": judgment["types"],
        "evidence": judgment["evidence"],
        "graph": judgment["graph"],
        "alerts": judgment["alerts"],
        **scored,
    }


def _edge_lines(edges: list[dict], limit: int = 12) -> list[str]:
    interesting = [edge for edge in edges if edge["rel"] != "runs_in"]
    lines = []
    for edge in interesting[:limit]:
        lines.append(f"- `{edge['src']}` {edge['rel']} `{edge['dst']}`")
    if len(interesting) > limit:
        lines.append(f"- 그 외 {len(interesting) - limit}개")
    if not lines:
        lines.append("- 기록된 파일·프로세스 엣지 없음")
    return lines


def write_report(rows: list[dict], order: list[str]) -> None:
    benign = [row for row in rows if row["truth_role"] == "benign"]
    attack = [row for row in rows if row["truth_role"] == "attack"]
    verdict_fp = [row for row in benign if row["verdict_false_positive"]]
    verdict_fn = [row for row in attack if row["verdict_false_negative"]]
    type_fp_n = sum(len(row["type_false_positives"]) for row in rows)
    type_fn_n = sum(len(row["type_false_negatives"]) for row in rows)

    lines = [
        "# 카테고리 1 그래프 탐지 결과",
        "",
        "판단기는 시나리오 이름을 받지 않는다. Falco 이벤트만으로 그래프를 만들고, 정상인지 공격인지와 공격 유형을 정한 뒤 정답과 비교했다. 실행 순서는 seed 21로 섞었다.",
        "",
        "공격 유형은 그래프 경로에서 나온다.",
        "",
        "- `environment_discovery`: `/proc/.../environ` 읽기. `env`/`printenv`는 같은 컨테이너에 다른 공격 경로가 있을 때만 포함",
        "- `host_discovery`: `/proc/version` 또는 `/proc/cpuinfo` 읽기",
        "- `credential_access`: `/etc/shadow`나 홈 디렉터리 자격증명 경로를 읽거나, 그 경로를 확인하는 프로세스가 실행됨",
        "- `token_access`: ServiceAccount 토큰 파일 읽기",
        "- `payload_execution`: 셸이 `/tmp` 파일을 읽거나 그 경로를 실행하거나, `/tmp` 파일을 읽은 뒤 새 셸이 시작. 내용은 `echo ok`만 있는 점검 스크립트는 제외",
        "- `persistence`: cron 설정 경로에 기록",
        "",
        "웹 파일 읽기, `/tmp`에 쓰고 읽기만 하는 행위, health check 쓰기, `id`와 `uname`은 정상 기준선에도 있으므로 공격 경로가 아니다.",
        "",
        f"실행 순서: {', '.join(order)}",
        "",
        "## 판단과 채점",
        "",
        "| 시나리오 | 판단 | 판단한 유형 | 정답 | 정답 유형 | 판정 | 유형 오탐 | 유형 미탐 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if row["verdict_false_positive"]:
            mark = "오탐"
        elif row["verdict_false_negative"]:
            mark = "미탐"
        else:
            mark = "맞음"
        lines.append(
            "| {id} | {predicted_verdict} | {predicted_types} | {truth_role} | {truth_types} | {mark} | {type_false_positives} | {type_false_negatives} |".format(
                mark=mark, **row
            )
        )

    lines.extend(["", "## 로그에서 본 근거", ""])
    for row in rows:
        lines.append(f"### {row['id']}")
        lines.append("")
        lines.append(f"판단: **{row['predicted_verdict']}**. 유형: {row['predicted_types'] or '없음'}.")
        lines.append("")
        if row["evidence"]:
            for item in row["evidence"]:
                lines.append(f"- `{item}`")
        else:
            lines.append("- 공격 경로가 없다. 기록된 엣지는 파일 읽기·쓰기와 프로세스 생성뿐이다.")
        lines.append("")
        lines.extend(_edge_lines(row["graph"]["edges"]))
        lines.append("")
        lines.append(f"채점 후 정답: {row['truth_role']} / {row['truth_types'] or '없음'}. {row['note']}.")
        lines.append("")

    lines.extend(
        [
            "## 오탐과 미탐",
            "",
            f"- 판정 오탐 {len(verdict_fp)}/{len(benign)}. 정상인데 공격으로 봄.",
            f"- 판정 미탐 {len(verdict_fn)}/{len(attack)}. 공격인데 정상으로 봄.",
            f"- 유형 오탐 {type_fp_n}개. 정답에 없는 공격 유형을 붙임.",
            f"- 유형 미탐 {type_fn_n}개. 정답 공격 유형을 빠뜨림.",
            "",
        ]
    )
    if verdict_fp:
        lines.append("판정 오탐:")
        lines.append("")
        for row in verdict_fp:
            lines.append(f"- `{row['id']}`: {', '.join(row['predicted_types'])}. {row['note']}.")
        lines.append("")
    if verdict_fn:
        lines.append("판정 미탐:")
        lines.append("")
        for row in verdict_fn:
            lines.append(f"- `{row['id']}`: 정답 유형 {', '.join(row['truth_types'])}. {row['note']}.")
        lines.append("")
    typed = [row for row in rows if row["type_false_negatives"] or row["type_false_positives"]]
    if typed:
        lines.append("유형이 어긋난 경우:")
        lines.append("")
        for row in typed:
            lines.append(
                f"- `{row['id']}`: 놓친 유형 {row['type_false_negatives'] or '없음'}, 잘못 붙인 유형 {row['type_false_positives'] or '없음'}."
            )
        lines.append("")

    lines.extend(
        [
            "## 공격 행위를 나눈 근거",
            "",
            "구분 기준은 OpenMetadata 침해 이후 파드 안에서 관찰된 파일·프로세스 행위다. 네트워크 접속, 외부 다운로드, 리버스 셸은 카테고리 1 밖이라 시나리오에 넣지 않았다.",
            "",
            "- 환경 조회는 `/proc/.../environ`을 읽는 행위다. 정상 스크립트의 `env` 단독 실행은 같은 유형으로 보지 않는다.",
            "- 호스트 정찰은 `/proc/version`과 `/proc/cpuinfo`를 읽는 행위다. 정상 스크립트의 `id`와 `uname`, `ls -l`이 여는 `/etc/passwd`는 공격으로 보지 않는다.",
            "- 자격증명 접근은 shadow, AWS, SSH, kubeconfig 경로를 열거나 그 경로를 인자로 확인하는 행위다.",
            "- 토큰 접근은 마운트된 ServiceAccount 토큰 파일을 여는 행위다. 프로세스 이름이 `cat`이 아니어도 같은 파일을 열면 같은 유형이다.",
            "- 페이로드 실행은 `/tmp`에 만든 스크립트를 셸이 실행하거나, 그 파일을 읽은 뒤 새 셸이 시작하는 행위다. 내용이 `echo ok`뿐인 점검은 정상 기준선 쪽의 로컬 확인으로 둔다.",
            "- 지속 실행은 cron 설정 파일에 기록하는 행위다. 실제 crond를 띄우거나 외부로 연결하지 않는다.",
            "",
            "## 한계",
            "",
            "- `id`, `uname`, `whoami`와 `ls -l`이 여는 `/etc/passwd`는 정상 운영에도 있어 공격 엣지로 쓰지 않는다. 호스트 정찰은 `/proc/version`과 `/proc/cpuinfo` 읽기만 본다.",
            "- `env`만 실행한 경우는 정상으로 둔다. 같은 컨테이너에서 환경 파일, 자격증명, 토큰, 페이로드, 호스트 정보, cron 기록이 같이 보이면 그때 환경 조회로 남긴다.",
            "- OAST 도메인 접속, 원격 페이로드 다운로드, Netcat 리버스 셸은 네트워크 행위이거나 실습에서 금지된 행위라 이 시스템이 다루지 않는다.",
            "- cron은 설정 파일 쓰기만 본다. 이미 떠 있는 crond가 그 파일을 실행하는지는 보지 않는다.",
            "- `/tmp` 실행 중 파일 내용이 `echo ok`만인 경우는 로컬 점검으로 본다. 공격 스크립트가 그 문구만 실행하면 정상으로 본다.",
            "- `/tmp` 파일을 읽은 뒤 그 내용과 무관한 새 셸이 같은 컨테이너에서 시작해도 페이로드로 본다. 이번 정상 시나리오에는 그 형태가 없다.",
            "- 한 시나리오의 이벤트가 수집 창에 빠지면 남은 이벤트만으로 판단한다. 로그가 비면 정상으로 둔다.",
            "- 이 비율은 여기 포함된 시나리오 집합에서의 결과다.",
            "",
        ]
    )
    (RESULTS / "결과.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    RESULTS.mkdir(parents=True, exist_ok=True)
    order = SCENARIOS[:]
    random.Random(21).shuffle(order)
    print("order", [item["id"] for item in order])
    rows = []
    for spec in order:
        print(f"== {spec['id']} ==")
        row = run_scenario(spec)
        rows.append(row)
        print(
            f"verdict={row['predicted_verdict']} types={row['predicted_types']} "
            f"vfp={row['verdict_false_positive']} vfn={row['verdict_false_negative']} "
            f"tfp={row['type_false_positives']} tfn={row['type_false_negatives']}"
        )
        if row["script_exit"] != 0:
            print(row["script_stderr"])
    summary = {
        "order": [row["id"] for row in rows],
        "verdict_false_positives": sum(1 for row in rows if row["verdict_false_positive"]),
        "verdict_false_negatives": sum(1 for row in rows if row["verdict_false_negative"]),
        "type_false_positives": sum(len(row["type_false_positives"]) for row in rows),
        "type_false_negatives": sum(len(row["type_false_negatives"]) for row in rows),
        "scenarios": rows,
    }
    (RESULTS / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    write_report(rows, summary["order"])
    print(
        "verdict_fp",
        summary["verdict_false_positives"],
        "verdict_fn",
        summary["verdict_false_negatives"],
        "type_fp",
        summary["type_false_positives"],
        "type_fn",
        summary["type_false_negatives"],
    )
    print(f"wrote {RESULTS / '결과.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
