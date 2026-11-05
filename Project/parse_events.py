"""Falco JSON 한 줄을 행위 이벤트로 바꾼다."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone


RULE_KIND = {
    "PBL File Read": "file_open",
    "PBL File Write": "file_open",
    "PBL Path Stat": "path_stat",
    "PBL Script Bytes": "script_write",
    "PBL Process Spawn": "process_spawn",
}


@dataclass
class Event:
    kind: str
    write: bool
    file: str
    process: str
    parent: str
    args: str
    command: str
    exepath: str
    container: str
    container_id: str
    pod: str
    namespace: str
    time: str
    rule: str
    hostname: str

    def to_dict(self) -> dict:
        return asdict(self)


def parse_time(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    if "." in text:
        head, tail = text.split(".", 1)
        sign = len(tail)
        for index, char in enumerate(tail):
            if char in "+-":
                sign = index
                break
        fraction = (tail[:sign] + "000000")[:6]
        text = f"{head}.{fraction}{tail[sign:]}"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _clean(value: object) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if text in ("<NA>", "None", "null"):
        return ""
    return text


def parse_line(line: str) -> Event | None:
    raw = line.strip()
    if not raw:
        return None
    if raw.startswith("[pod/"):
        bracket = raw.find("] ")
        if bracket == -1:
            return None
        raw = raw[bracket + 2 :]
    if "PBL_EVENT" not in raw and '"rule":"PBL ' not in raw:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    rule = _clean(payload.get("rule"))
    kind = RULE_KIND.get(rule)
    if kind is None:
        return None
    fields = payload.get("output_fields") or {}
    namespace = _clean(fields.get("k8s.ns.name"))
    container = _clean(fields.get("container.name"))
    if namespace != "pbl-security":
        return None
    if container not in ("frontend", "backend", "curl-client"):
        return None
    if rule == "PBL Path Stat":
        file_name = _clean(fields.get("fs.path.name")) or _clean(fields.get("fd.name"))
    elif rule == "PBL Script Bytes":
        file_name = _clean(fields.get("fd.name"))
    else:
        file_name = _clean(fields.get("fd.name")) or _clean(fields.get("proc.exepath"))
    return Event(
        kind=kind,
        write=rule == "PBL File Write",
        file=file_name,
        process=_clean(fields.get("proc.name")),
        parent=_clean(fields.get("proc.pname")),
        args=_clean(fields.get("evt.buffer")) or _clean(fields.get("proc.args")),
        command=_clean(fields.get("proc.cmdline")),
        exepath=_clean(fields.get("proc.exepath")),
        container=container,
        container_id=_clean(fields.get("container.id")),
        pod=_clean(fields.get("k8s.pod.name")),
        namespace=namespace,
        time=_clean(payload.get("time")),
        rule=rule,
        hostname=_clean(payload.get("hostname")),
    )


def _bucket(event: Event) -> str:
    try:
        stamped = parse_time(event.time)
    except ValueError:
        return event.time
    clipped = stamped - timedelta(microseconds=stamped.microsecond % 50000)
    return clipped.isoformat()


def dedupe(events: list[Event]) -> list[Event]:
    """같은 시스템 콜이 노드 여러 개의 Falco에 찍힌 경우 한 건으로 묶는다."""
    chosen: dict[tuple, Event] = {}
    for event in events:
        key = (
            event.rule,
            event.container_id,
            event.container,
            event.process,
            event.file,
            event.args,
            _bucket(event),
        )
        current = chosen.get(key)
        if current is None or (not current.pod and event.pod):
            chosen[key] = event
    return sorted(chosen.values(), key=lambda item: item.time)
