# mcpfz-probe

Standalone runtime probe for MCP server fuzzing. It runs beside
`mcp-server-fuzzer`: the fuzzer owns process launch and per-call timing; this
repo owns runtime event collection, per-call attribution, and the sidecar
protocol. The privileged sidecar is Rust (small, auditable, static Linux
artifact); the integration layer is Python (a simple `RuntimeMonitor`).

## Repo layout

```text
crates/mcpfz-probe/            Rust sidecar binary (fake + eBPF backends)
crates/mcpfz-probe-ebpf/       BPF program (compiled to bytecode, Linux only)
crates/mcpfz-probe-ebpf-common/ #[repr(C)] event type shared kernel<->userspace
src/mcpfz_probe/               Python monitor + policy engine
tests/                         CI-friendly Python tests (fake backend, no root)
examples/                      Sample events + live eBPF demo
docs/                          Architecture and protocol notes
```

## Status

- **Python monitor + policy engine**: complete and tested.
- **`fake` backend**: complete. A deterministic test double that replays scripted
  events into the correct bucket (`startup`/`call`/`ambient`) attributed to the
  active `call_id` — the whole pipeline runs on any OS without root.
- **`ebpf` backend**: real exec-events MVP. Loads a CO-RE BPF program on
  `sys_enter_execve`, attributes captured execs to the active call window, and
  emits the same NDJSON as the fake backend. Verified on Ubuntu 24.04 / kernel 6.8
  capturing a real `curl` exec that the policy engine flagged. Connect and
  `file_open` probes are next.

## Sidecar protocol (NDJSON)

Python → sidecar stdin (control):

```json
{"op":"scope","pgid":1234,"generation":1}
{"op":"mark","phase":"begin","call_id":"...","tool":"get_weather"}
{"op":"mark","phase":"end","call_id":"..."}
```

Sidecar → Python stdout (events); `bucket` is `startup`/`call`/`ambient`:

```json
{"type":"exec","bucket":"call","call_id":"...","pid":1234,"argv":["/bin/sh","-c","curl ..."]}
{"type":"connect","bucket":"ambient","pid":1234,"dst":"203.0.113.7:443"}
```

Full spec in `docs/protocol.md`.

## Using it (Python)

```python
monitor.set_scope_pgid(server_pgid, generation=1)
monitor.begin_call(call_id, tool_name)
try:
    result = call_tool(...)
finally:
    summary = monitor.end_call(call_id)      # events attributed to this call
findings = evaluate_events(summary.events, policy)
```

## CLI

```sh
mcpfz-probe --backend fake --events-file examples/events.sample.json
mcpfz-probe --backend ebpf          # Linux, needs root/CAP_BPF
mcpfz-probe --help
```

The `fake` backend reads an events script (`{"events":[...]}` or a bare `[...]`),
each entry a `trigger` (`startup`/`scope`/`begin`/`end`, optional `tool` filter)
and an `event` object the sidecar passes through, filling in `bucket`, `call_id`,
and `ts_ns`. See `examples/events.sample.json`.

## mcp-server-fuzzer integration

The probe plugs into `mcp-server-fuzzer` through three small, opt-in hooks
(module `mcp_fuzzer/runtime_probe.py`): scope the sidecar to the server's process
group when the stdio server launches, `begin`/`end` marks around each
`_execute_tool_call`, and merge the resulting findings into the session at the
end. When `MCP_FUZZER_RUNTIME_PROBE` is unset the hooks are no-ops.

```sh
export MCP_FUZZER_RUNTIME_PROBE=1
export MCPFZ_PROBE_BIN=/path/to/mcpfz-probe        # the sidecar binary
export MCPFZ_PROBE_BACKEND=ebpf                     # or "fake"
sudo -E mcp-fuzzer --mode tools --protocol stdio \
  --endpoint "python examples/vulnerable_server.py" \
  --runs 3 --max-concurrency 1
```

Kernel-observed execs become `high`-severity `runtime.exec` findings attributed
to the exact tool + run. Verified on Linux against `examples/vulnerable_server.py`
(a tool that shells out): every fuzzed `fetch_url` call's `/bin/sh` and `curl`
execs were captured and flagged, and merged into the fuzzer's report.

Per-call attribution assumes stdio calls run serialized (`--max-concurrency 1`),
matching the design in `docs/architecture.md`; execs from overlapping calls still
get caught, but land in the `ambient` bucket.

## Development

```sh
# Python tests
PYTHONPATH=src python3 -m unittest discover -s tests

# Rust sidecar (portable, fake backend)
cargo build
cargo test
```

### eBPF backend (Linux)

Needs a BTF-enabled kernel and this toolchain:

```sh
rustup toolchain install nightly --component rust-src
cargo install bpf-linker            # needs LLVM dev libs (e.g. llvm-18-dev)
cargo build --features ebpf         # build.rs compiles the BPF crate to bytecode
sudo ./target/debug/mcpfz-probe --backend ebpf
```

Live end-to-end demo (real kernel capture + real policy), run as root:

```sh
python3 examples/ebpf_live_demo.py
```

Known limitation: scope filtering resolves a process's group via
`/proc/<pid>/stat` in userspace, which races short-lived processes. Per
`docs/architecture.md`, this should move into the kernel program
(`task->group_leader` via CO-RE) — next step alongside the connect/file_open
probes.
