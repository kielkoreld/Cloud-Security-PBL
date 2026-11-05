"""시나리오를 실행하고 그래프 탐지의 오탐·미탐을 집계한다."""

from __future__ import annotations

import random
import subprocess
import sys
import tempfile
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


def _parse_pbl_line(line: str) -> Event | None:
    if "PBL_EVENT" not in line and "PBL File" not in line and "PBL Process" not in line and "PBL Path" not in line:
        return None
    event = parse_line(line)
    if event is None or not event.time:
        return None
    return event


def filter_by_window(events: list[Event], start: datetime, end: datetime, pad: int = 2) -> list[Event]:
    """호스트와 Falco 시계가 어긋나도 이번 구간의 이벤트만 남긴다."""
    if not events:
        return []
    stamped: list[tuple[Event, datetime]] = []
    for event in events:
        try:
            stamped.append((event, parse_time(event.time)))
        except ValueError:
            continue
    if not stamped:
        return []
    pad_delta = timedelta(seconds=pad)
    selected = [event for event, when in stamped if start - pad_delta <= when <= end + pad_delta]
    if selected:
        return selected
    # Falco 시계가 호스트보다 느리거나 빠른 경우, 가장 최근 이벤트 기준으로 창을 옮긴다.
    latest = max(when for _, when in stamped)
    mid = start + (end - start) / 2
    skew = mid - latest
    if abs(skew) < timedelta(seconds=5):
        return []
    return [event for event, when in stamped if start - skew - pad_delta <= when <= end - skew + pad_delta]


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
    events = []
    for line in logs.stdout.splitlines():
        event = _parse_pbl_line(line)
        if event is not None:
            events.append(event)
    return dedupe(filter_by_window(events, start, end, pad=pad))


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
    # /mnt/c 에 쓰면 follow 출력이 늦게 디스크에 남아 이벤트를 놓친다.
    with tempfile.NamedTemporaryFile(
        mode="w+",
        encoding="utf-8",
        prefix=f"pbl-{spec['id']}-",
        suffix=".log",
        delete=False,
    ) as stream:
        log_path = Path(stream.name)
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
        time.sleep(3)
        completed = _run(["bash", str(spec["script"])], timeout=120)
        time.sleep(5)
        end = datetime.now(timezone.utc)
        follower.terminate()
        try:
            follower.wait(timeout=5)
        except subprocess.TimeoutExpired:
            follower.kill()
        stream.flush()
    events = []
    for line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        event = _parse_pbl_line(line)
        if event is not None:
            events.append(event)
    events = dedupe(filter_by_window(events, start, end, pad=2))
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


def write_report(rows: list[dict]) -> None:
    benign = [row for row in rows if row["truth_role"] == "benign"]
    attack = [row for row in rows if row["truth_role"] == "attack"]
    verdict_fp = sum(1 for row in benign if row["verdict_false_positive"])
    verdict_fn = sum(1 for row in attack if row["verdict_false_negative"])

    lines = [
        "# 카테고리 1 탐지 결과",
        "",
        f"오탐 {verdict_fp}/{len(benign)}, 미탐 {verdict_fn}/{len(attack)}. "
        "시나리오 이름은 판단에 쓰지 않았고, Falco 이벤트만으로 정상/공격을 나눈 뒤 정답과 비교했다.",
        "",
        "| 시나리오 | 판단 | 정답 | 결과 | 근거 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in rows:
        if row["verdict_false_positive"]:
            mark = "오탐"
        elif row["verdict_false_negative"]:
            mark = "미탐"
        else:
            mark = "맞음"
        if row["event_count"] == 0:
            reason = "이벤트 0건"
        elif row["evidence"]:
            reason = row["evidence"][0]
        elif row["predicted_types"]:
            reason = ", ".join(row["predicted_types"])
        else:
            reason = "공격 경로 없음"
        predicted = row["predicted_verdict"]
        if row["predicted_types"]:
            predicted = f"{predicted} ({', '.join(row['predicted_types'])})"
        truth = row["truth_role"]
        if row["truth_types"]:
            truth = f"{truth} ({', '.join(row['truth_types'])})"
        lines.append(
            f"| {row['id']} | {predicted} | {truth} | {mark} | {reason} |"
        )

    lines.extend(
        [
            "",
            "## 한계",
            "",
            "- 로그가 비면 정상으로 본다. 수집이 실패하면 공격도 미탐으로 집계된다.",
            "- `id`/`uname`/`env` 단독, `/etc/passwd` 읽기는 정상 기준선에도 있어 공격으로 보지 않는다.",
            "- 네트워크 행위(OAST, 다운로드, 리버스 셸)와 cron 실제 실행은 다루지 않는다.",
            "- `/tmp`에서 `echo ok`만 실행하면 로컬 점검으로 본다.",
            "- 이 숫자는 여기 포함된 시나리오 집합에서의 결과다.",
            "",
        ]
    )
    (RESULTS / "결과.md").write_text("\n".join(lines), encoding="utf-8")


def parse_seed(argv: list[str]) -> int:
    """기본 시드는 21. `--21`, `--7`처럼 숫자 플래그로 바꾼다."""
    seed = 21
    for arg in argv:
        if arg in ("-h", "--help"):
            print(
                "usage: python3 Project/run_eval.py [--SEED]\n"
                f"  기본 시드: {seed}\n"
                "  예: python3 Project/run_eval.py --21\n"
                "      python3 Project/run_eval.py --7"
            )
            raise SystemExit(0)
        if arg.startswith("--") and arg[2:].isdigit():
            seed = int(arg[2:])
        elif arg.startswith("-") and not arg.startswith("--") and arg[1:].isdigit():
            seed = int(arg[1:])
        else:
            print(f"unknown argument: {arg}", file=sys.stderr)
            print("use --help", file=sys.stderr)
            raise SystemExit(2)
    return seed


def main(argv: list[str] | None = None) -> int:
    seed = parse_seed(sys.argv[1:] if argv is None else argv)
    RESULTS.mkdir(parents=True, exist_ok=True)
    order = SCENARIOS[:]
    random.Random(seed).shuffle(order)
    print("seed", seed)
    print("order", [item["id"] for item in order])
    rows = []
    for spec in order:
        print(f"== {spec['id']} ==")
        row = run_scenario(spec)
        rows.append(row)
        print(
            f"verdict={row['predicted_verdict']} types={row['predicted_types']} "
            f"events={row['event_count']} "
            f"vfp={row['verdict_false_positive']} vfn={row['verdict_false_negative']}"
        )
        if row["script_exit"] != 0:
            print(row["script_stderr"])
    verdict_fp = sum(1 for row in rows if row["verdict_false_positive"])
    verdict_fn = sum(1 for row in rows if row["verdict_false_negative"])
    write_report(rows)
    print("verdict_fp", verdict_fp, "verdict_fn", verdict_fn)
    print(f"wrote {RESULTS / '결과.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
