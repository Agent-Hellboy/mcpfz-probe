from __future__ import annotations

import json
import subprocess
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class RuntimeEvent:
    type: str
    bucket: str = "ambient"
    call_id: str | None = None
    pid: int | None = None
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_json(cls, line: str) -> "RuntimeEvent":
        raw = json.loads(line)
        known = {"type", "bucket", "call_id", "pid"}
        return cls(
            type=raw["type"],
            bucket=raw.get("bucket", "ambient"),
            call_id=raw.get("call_id"),
            pid=raw.get("pid"),
            data={key: value for key, value in raw.items() if key not in known},
        )

    def to_json(self) -> str:
        payload: dict[str, Any] = {
            "type": self.type,
            "bucket": self.bucket,
            **self.data,
        }
        if self.call_id is not None:
            payload["call_id"] = self.call_id
        if self.pid is not None:
            payload["pid"] = self.pid
        return json.dumps(payload, separators=(",", ":"))


@dataclass(frozen=True)
class RuntimeSummary:
    call_id: str
    events: tuple[RuntimeEvent, ...]
    truncated: bool = False

    @property
    def counts(self) -> dict[str, int]:
        out: dict[str, int] = defaultdict(int)
        for event in self.events:
            out[event.type] += 1
        return dict(out)

    def compact(self, limit: int = 10) -> dict[str, Any]:
        notable = []
        for event in self.events[:limit]:
            item = {"type": event.type, **event.data}
            if event.pid is not None:
                item["pid"] = event.pid
            notable.append(item)
        return {
            "counts": self.counts,
            "notable": notable,
            "truncated": self.truncated,
        }


class SidecarRuntimeMonitor:
    def __init__(self, command: list[str], raw_path: Path | None = None) -> None:
        self._command = command
        self._raw_path = raw_path
        self._process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()
        self._events_by_call: dict[str, list[RuntimeEvent]] = defaultdict(list)
        self._ambient_events: list[RuntimeEvent] = []
        self._dropped = 0

    def start(self) -> None:
        if self._process is not None:
            return
        raw_file = self._raw_path.open("a", encoding="utf-8") if self._raw_path else None
        self._process = subprocess.Popen(
            self._command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._reader = threading.Thread(
            target=self._read_stdout,
            args=(raw_file,),
            name="mcpfz-probe-reader",
            daemon=True,
        )
        self._reader.start()

    def stop(self) -> None:
        if self._process is None:
            return
        self._send({"op": "shutdown"})
        self._process.terminate()
        try:
            self._process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self._process.kill()
            self._process.wait(timeout=2)
        self._process = None

    def set_scope_pgid(self, pgid: int, generation: int) -> None:
        self._send({"op": "scope", "pgid": pgid, "generation": generation})

    def begin_call(self, call_id: str, tool: str) -> None:
        self._send({"op": "mark", "phase": "begin", "call_id": call_id, "tool": tool})

    def end_call(self, call_id: str) -> RuntimeSummary:
        self._send({"op": "mark", "phase": "end", "call_id": call_id})
        with self._lock:
            events = tuple(self._events_by_call.pop(call_id, []))
            truncated = any(event.type == "drop" for event in events) or self._dropped > 0
        return RuntimeSummary(call_id=call_id, events=events, truncated=truncated)

    def ambient_events(self) -> tuple[RuntimeEvent, ...]:
        with self._lock:
            return tuple(self._ambient_events)

    def _send(self, payload: dict[str, Any]) -> None:
        if self._process is None:
            raise RuntimeError("runtime monitor is not started")
        if self._process.stdin is None:
            raise RuntimeError("runtime sidecar stdin is closed")
        self._process.stdin.write(json.dumps(payload, separators=(",", ":")) + "\n")
        self._process.stdin.flush()

    def _read_stdout(self, raw_file: Any) -> None:
        assert self._process is not None
        assert self._process.stdout is not None
        try:
            for line in self._process.stdout:
                if raw_file is not None:
                    raw_file.write(line)
                    raw_file.flush()
                event = RuntimeEvent.from_json(line)
                with self._lock:
                    if event.type == "drop":
                        self._dropped += int(event.data.get("count", 1))
                    if event.call_id:
                        self._events_by_call[event.call_id].append(event)
                    else:
                        self._ambient_events.append(event)
        finally:
            if raw_file is not None:
                raw_file.close()


class FakeRuntimeMonitor:
    def __init__(self, scripted_events: Iterable[RuntimeEvent] = ()) -> None:
        self._scripted_events = list(scripted_events)
        self._active_call: str | None = None
        self._events_by_call: dict[str, list[RuntimeEvent]] = defaultdict(list)
        self._ambient_events: list[RuntimeEvent] = []

    def start(self) -> None:
        for event in self._scripted_events:
            self.record(event)

    def stop(self) -> None:
        return

    def set_scope_pgid(self, pgid: int, generation: int) -> None:
        return

    def begin_call(self, call_id: str, tool: str) -> None:
        self._active_call = call_id

    def end_call(self, call_id: str) -> RuntimeSummary:
        self._active_call = None
        return RuntimeSummary(call_id=call_id, events=tuple(self._events_by_call.pop(call_id, [])))

    def record(self, event: RuntimeEvent) -> None:
        if event.call_id:
            self._events_by_call[event.call_id].append(event)
        elif self._active_call:
            attributed = RuntimeEvent(
                type=event.type,
                bucket="call",
                call_id=self._active_call,
                pid=event.pid,
                data=event.data,
            )
            self._events_by_call[self._active_call].append(attributed)
        else:
            self._ambient_events.append(event)

    def ambient_events(self) -> tuple[RuntimeEvent, ...]:
        return tuple(self._ambient_events)

