"""Falco 이벤트로 행위 그래프를 만들고, 기준에 없는 공격 경로만 고른다."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from parse_events import Event


SHELLS = {"sh", "bash", "ash", "dash"}
ENV_TOOLS = {"env", "printenv"}

MOTIVES = (
    "environ_read",
    "host_recon",
    "credential_read",
    "token_read",
    "env_dump",
    "tmp_exec",
    "cron_write",
)

REASONS = {
    "environ_read": "프로세스가 /proc 환경 파일을 읽었고, 정상 실행의 그래프에는 그 엣지가 없다.",
    "host_recon": "프로세스가 커널 버전이나 CPU 정보를 읽었고, 정상 실행의 id·uname은 그 파일을 열지 않는다.",
    "credential_read": "프로세스가 shadow 또는 홈 디렉터리 자격증명 경로를 열거나 상태만 확인했다.",
    "token_read": "프로세스가 ServiceAccount 토큰 파일을 열었고, 정상 실행의 그래프에는 그 엣지가 없다.",
    "env_dump": "환경변수 출력과 다른 공격 경로가 같은 컨테이너에 같이 있다.",
    "tmp_exec": "/tmp에 쓴 파일을 셸이 경로로 실행했거나, 그 파일을 읽은 뒤 새 셸이 시작했다.",
    "cron_write": "프로세스가 cron 설정 경로에 기록을 남겼고, 정상 실행에는 예약 작업 등록이 없다.",
}

TYPE_BY_MOTIVE = {
    "environ_read": "environment_discovery",
    "env_dump": "environment_discovery",
    "host_recon": "host_discovery",
    "credential_read": "credential_access",
    "token_read": "token_access",
    "tmp_exec": "payload_execution",
    "cron_write": "persistence",
}


@dataclass
class Alert:
    motive: str
    container: str
    process: str
    file: str
    time: str
    reason: str
    evidence: str

    def to_dict(self) -> dict:
        return {
            "motive": self.motive,
            "attack_type": TYPE_BY_MOTIVE[self.motive],
            "container": self.container,
            "process": self.process,
            "file": self.file,
            "time": self.time,
            "reason": self.reason,
            "evidence": self.evidence,
        }


@dataclass
class Graph:
    nodes: list[str] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"nodes": self.nodes, "edges": self.edges}


def _node_process(event: Event) -> str:
    return f"proc:{event.container}/{event.process}"


def _node_file(path: str) -> str:
    return f"file:{path}"


def _node_container(name: str) -> str:
    return f"container:{name}"


def build_graph(events: list[Event]) -> Graph:
    nodes: set[str] = set()
    edges: list[dict] = []
    seen: set[tuple] = set()
    for event in events:
        process_node = _node_process(event)
        container_node = _node_container(event.container)
        nodes.add(process_node)
        nodes.add(container_node)
        run_edge = (process_node, "runs_in", container_node)
        if run_edge not in seen:
            seen.add(run_edge)
            edges.append(
                {
                    "src": process_node,
                    "rel": "runs_in",
                    "dst": container_node,
                    "time": event.time,
                }
            )
        if event.parent:
            parent_node = f"proc:{event.container}/{event.parent}"
            nodes.add(parent_node)
            spawn_edge = (parent_node, "spawns", process_node)
            if spawn_edge not in seen:
                seen.add(spawn_edge)
                edges.append(
                    {
                        "src": parent_node,
                        "rel": "spawns",
                        "dst": process_node,
                        "time": event.time,
                    }
                )
        if event.kind in ("file_open", "path_stat") and event.file:
            file_node = _node_file(event.file)
            nodes.add(file_node)
            if event.write:
                relation = "writes"
            elif event.kind == "path_stat":
                relation = "stats"
            else:
                relation = "reads"
            file_edge = (process_node, relation, file_node)
            if file_edge not in seen:
                seen.add(file_edge)
                edges.append(
                    {
                        "src": process_node,
                        "rel": relation,
                        "dst": file_node,
                        "time": event.time,
                    }
                )
            if (
                event.kind == "file_open"
                and not event.write
                and event.process in SHELLS
                and event.file.startswith("/tmp/")
            ):
                exec_edge = (process_node, "execs", file_node)
                if exec_edge not in seen:
                    seen.add(exec_edge)
                    edges.append(
                        {
                            "src": process_node,
                            "rel": "execs",
                            "dst": file_node,
                            "time": event.time,
                        }
                    )
        if event.kind == "process_spawn":
            for path in _credential_mentions(event.args):
                file_node = _node_file(path)
                nodes.add(file_node)
                stat_edge = (process_node, "stats", file_node)
                if stat_edge not in seen:
                    seen.add(stat_edge)
                    edges.append(
                        {
                            "src": process_node,
                            "rel": "stats",
                            "dst": file_node,
                            "time": event.time,
                        }
                    )
            target = _executed_tmp_path(event)
            if target:
                file_node = _node_file(target)
                nodes.add(file_node)
                exec_edge = (process_node, "execs", file_node)
                if exec_edge not in seen:
                    seen.add(exec_edge)
                    edges.append(
                        {
                            "src": process_node,
                            "rel": "execs",
                            "dst": file_node,
                            "time": event.time,
                        }
                    )
    for shell, path in _shells_after_tmp_read(events):
        process_node = _node_process(shell)
        file_node = _node_file(path)
        nodes.add(process_node)
        nodes.add(file_node)
        follow_edge = (process_node, "follows", file_node)
        if follow_edge not in seen:
            seen.add(follow_edge)
            edges.append(
                {
                    "src": process_node,
                    "rel": "follows",
                    "dst": file_node,
                    "time": shell.time,
                }
            )
    return Graph(nodes=sorted(nodes), edges=edges)


def _is_environ(path: str) -> bool:
    return "/environ" in path and path.startswith("/proc/")


def _is_credential(path: str) -> bool:
    return (
        path == "/etc/shadow"
        or path.startswith("/root/.aws/")
        or path.startswith("/root/.ssh/")
        or path.startswith("/root/.kube/")
    )


def _is_token(path: str) -> bool:
    return "/serviceaccount/token" in path


def _is_host(path: str) -> bool:
    return path in {"/proc/version", "/proc/cpuinfo"}


def _is_cron(path: str) -> bool:
    return (
        path == "/etc/crontab"
        or path.startswith("/etc/cron.d/")
        or path.startswith("/etc/crontabs/")
        or path.startswith("/var/spool/cron/")
    )


def _credential_mentions(text: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    cleaned = text.replace("\n", " ").replace(";", " ").replace(",", " ")
    for raw in cleaned.split():
        token = raw.strip("'\"()[]{}")
        if not _is_credential(token) or token in seen:
            continue
        seen.add(token)
        found.append(token)
    return found


def _tmp_writes(events: list[Event]) -> dict[str, str]:
    writes: dict[str, str] = {}
    for event in events:
        if event.kind == "file_open" and event.write and event.file.startswith("/tmp/"):
            writes.setdefault(event.file, event.time)
    return writes


def _shells_after_tmp_read(events: list[Event]) -> list[tuple[Event, str]]:
    """/tmp 파일을 읽은 시각 이후에 시작한 셸을 고른다."""
    reads: list[tuple[str, str, str]] = []
    for event in events:
        if event.kind != "file_open" or event.write or not event.file.startswith("/tmp/"):
            continue
        reads.append((event.container, event.file, event.time))
    found: list[tuple[Event, str]] = []
    seen: set[tuple] = set()
    for event in events:
        if event.kind != "process_spawn" or event.process not in SHELLS:
            continue
        for container, path, read_at in reads:
            if event.container != container or event.time < read_at:
                continue
            key = (event.container, event.process, path, event.time)
            if key in seen:
                continue
            seen.add(key)
            found.append((event, path))
            break
    return found


def _executed_tmp_path(event: Event) -> str:
    if event.exepath.startswith("/tmp/"):
        return event.exepath
    if event.process not in SHELLS:
        return ""
    token = event.args.strip().split()[0] if event.args.strip() else ""
    if token.startswith("/tmp/"):
        return token
    return ""


_HEREDOC = re.compile(
    r">\s*(/tmp/\S+)\s*<<-?\s*['\"]?(\w+)['\"]?\s*\n(.*?)\n\s*\2\b",
    re.DOTALL,
)


def _is_health_body(text: str) -> bool:
    """로컬 점검 스크립트는 echo ok만 출력한다."""
    lines = []
    for raw in text.replace("\x00", "").replace("\r", "\n").split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    body = "\n".join(lines)
    return re.fullmatch(r"echo\s+['\"]?ok['\"]?", body) is not None


def _health_script_paths(events: list[Event]) -> set[str]:
    chunks: dict[str, list[str]] = {}
    paths: set[str] = set()
    for event in events:
        if event.kind == "script_write" and event.file.startswith("/tmp/") and event.args:
            chunks.setdefault(event.file, []).append(event.args)
        text = "\n".join(part for part in (event.command, event.args) if part)
        for match in _HEREDOC.finditer(text):
            path, _marker, body = match.group(1), match.group(2), match.group(3)
            if _is_health_body(body):
                paths.add(path)
    for path, parts in chunks.items():
        if _is_health_body("".join(parts)):
            paths.add(path)
    return paths


def detect(events: list[Event]) -> list[Alert]:
    """정상 그래프에 없는 읽기·실행 경로를 공격 모티프로 반환한다."""
    writes = _tmp_writes(events)
    alerts: list[Alert] = []
    seen: set[tuple] = set()

    def add(motive: str, event: Event, file_name: str, evidence: str) -> None:
        key = (motive, event.container, event.process, file_name)
        if key in seen:
            return
        seen.add(key)
        alerts.append(
            Alert(
                motive=motive,
                container=event.container,
                process=event.process,
                file=file_name,
                time=event.time,
                reason=REASONS[motive],
                evidence=evidence,
            )
        )

    for event in events:
        accessed = (event.kind == "file_open" and not event.write) or event.kind == "path_stat"
        if accessed:
            verb = "stats" if event.kind == "path_stat" else "reads"
            if _is_environ(event.file):
                add(
                    "environ_read",
                    event,
                    event.file,
                    f"{event.container}/{event.process} {verb} {event.file}",
                )
            elif _is_credential(event.file):
                add(
                    "credential_read",
                    event,
                    event.file,
                    f"{event.container}/{event.process} {verb} {event.file}",
                )
            elif _is_token(event.file):
                add(
                    "token_read",
                    event,
                    event.file,
                    f"{event.container}/{event.process} {verb} {event.file}",
                )
            elif _is_host(event.file) and event.kind == "file_open":
                add(
                    "host_recon",
                    event,
                    event.file,
                    f"{event.container}/{event.process} reads {event.file}",
                )
            if (
                event.kind == "file_open"
                and not event.write
                and event.process in SHELLS
                and event.file.startswith("/tmp/")
            ):
                add(
                    "tmp_exec",
                    event,
                    event.file,
                    f"{event.container}/{event.process} reads {event.file}",
                )
        if event.kind == "file_open" and event.write and _is_cron(event.file):
            add(
                "cron_write",
                event,
                event.file,
                f"{event.container}/{event.process} writes {event.file}",
            )
        if event.kind == "process_spawn":
            for path in _credential_mentions(event.args):
                add(
                    "credential_read",
                    event,
                    path,
                    f"{event.container}/{event.process} stats {path}",
                )
            if event.process in ENV_TOOLS:
                parent = event.parent or "unknown"
                add(
                    "env_dump",
                    event,
                    event.process,
                    f"{event.container}/{parent} spawns {event.process}",
                )
        if event.kind == "process_spawn":
            path = _executed_tmp_path(event)
            if path and path in writes and writes[path] <= event.time:
                add(
                    "tmp_exec",
                    event,
                    path,
                    f"write {path} at {writes[path]} -> {event.container}/{event.process} execs {path}",
                )
            elif path:
                add(
                    "tmp_exec",
                    event,
                    path,
                    f"{event.container}/{event.process} execs {path}",
                )
    for shell, path in _shells_after_tmp_read(events):
        read_at = next(
            (
                event.time
                for event in events
                if event.kind == "file_open"
                and not event.write
                and event.container == shell.container
                and event.file == path
            ),
            "",
        )
        add(
            "tmp_exec",
            shell,
            path,
            f"read {path} at {read_at} -> {shell.container}/{shell.process} starts at {shell.time}",
        )
    accompanied = {alert.container for alert in alerts if alert.motive != "env_dump"}
    kept = [alert for alert in alerts if alert.motive != "env_dump" or alert.container in accompanied]
    health_paths = _health_script_paths(events)
    return [
        alert
        for alert in kept
        if not (alert.motive == "tmp_exec" and alert.file in health_paths)
    ]


def judge(events: list[Event]) -> dict:
    """시나리오 이름 없이 이벤트 그래프만 보고 정상/공격과 공격 유형을 정한다."""
    graph = build_graph(events)
    alerts = detect(events)
    types: list[str] = []
    for alert in alerts:
        attack_type = TYPE_BY_MOTIVE[alert.motive]
        if attack_type not in types:
            types.append(attack_type)
    return {
        "verdict": "attack" if types else "benign",
        "types": types,
        "evidence": [alert.evidence for alert in alerts],
        "alerts": [alert.to_dict() for alert in alerts],
        "graph": graph.to_dict(),
    }
