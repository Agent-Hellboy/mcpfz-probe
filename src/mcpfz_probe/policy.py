from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .monitor import RuntimeEvent


DEFAULT_SENSITIVE_PATTERNS = (
    "*/.ssh/*",
    "*/.aws/credentials",
    "*/.config/gcloud/*",
    "*/.kube/config",
    "*/.gnupg/*",
    "*/.env",
    "*/.env.*",
    "*/Library/Application Support/Google/Chrome/*",
    "*/.mozilla/firefox/*",
)


@dataclass(frozen=True)
class RuntimePolicy:
    workspace: Path
    tmpdir: Path
    exec_allow: tuple[str, ...] = ()
    net_allow: tuple[str, ...] = ()
    fs_write_allow: tuple[str, ...] = ()
    sensitive_patterns: tuple[str, ...] = DEFAULT_SENSITIVE_PATTERNS

    def __post_init__(self) -> None:
        if not self.fs_write_allow:
            object.__setattr__(
                self,
                "fs_write_allow",
                (str(self.workspace.resolve()), str(self.tmpdir.resolve())),
            )


@dataclass(frozen=True)
class FindingDraft:
    category: str
    severity: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)


def evaluate_events(events: Iterable[RuntimeEvent], policy: RuntimePolicy) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    for event in events:
        if event.type == "exec":
            argv = event.data.get("argv", [])
            executable = argv[0] if argv else event.data.get("path", "<unknown>")
            if executable not in policy.exec_allow:
                findings.append(
                    FindingDraft(
                        category="runtime.exec",
                        severity="high",
                        detail=f"process executed {executable}",
                        evidence={"event": event.data, "call_id": event.call_id},
                    )
                )
        elif event.type == "connect":
            dst = str(event.data.get("dst", ""))
            if dst and dst not in policy.net_allow:
                findings.append(
                    FindingDraft(
                        category="runtime.net_connect",
                        severity="medium",
                        detail=f"network connection to {dst}",
                        evidence={"event": event.data, "call_id": event.call_id},
                    )
                )
        elif event.type == "file_open":
            findings.extend(_evaluate_file_event(event, policy))
    return findings


def _evaluate_file_event(event: RuntimeEvent, policy: RuntimePolicy) -> list[FindingDraft]:
    path = str(event.data.get("path", ""))
    flags = str(event.data.get("flags", ""))
    findings: list[FindingDraft] = []
    if any(fnmatch.fnmatch(path, pattern) for pattern in policy.sensitive_patterns):
        findings.append(
            FindingDraft(
                category="runtime.sensitive_read",
                severity="critical",
                detail=f"sensitive file opened: {path}",
                evidence={"event": event.data, "call_id": event.call_id},
            )
        )
    if _is_write_flag(flags) and not _is_allowed_write(path, policy.fs_write_allow):
        findings.append(
            FindingDraft(
                category="runtime.fs_write",
                severity="high",
                detail=f"file opened for write outside allowed paths: {path}",
                evidence={"event": event.data, "call_id": event.call_id},
            )
        )
    return findings


def _is_write_flag(flags: str) -> bool:
    return any(flag in flags for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))


def _is_allowed_write(path: str, allowed_roots: Iterable[str]) -> bool:
    try:
        resolved = Path(path).resolve()
    except OSError:
        return False
    for root in allowed_roots:
        try:
            resolved.relative_to(Path(root).resolve())
            return True
        except ValueError:
            continue
    return False

