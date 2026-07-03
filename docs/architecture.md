# Architecture

## Boundary

`mcpfz-probe` is a separate repo because it has a different release and trust
profile from `mcp-server-fuzzer`:

- It ships a privileged Linux sidecar binary.
- It has kernel and architecture compatibility constraints.
- It can be versioned independently from fuzzer protocol logic.

The fuzzer integration should depend only on the Python `RuntimeMonitor`
surface:

```python
monitor.set_scope_pgid(server_pgid, generation=1)
monitor.begin_call(call_id, tool_name)
try:
    result = call_tool(...)
finally:
    summary = monitor.end_call(call_id)
```

## Components

- Rust sidecar: owns event collection, process-group filtering, descendant
  tracking, mark timestamping, and NDJSON output.
- Python monitor: owns sidecar lifecycle, policy evaluation, event summaries,
  raw event capture, and conversion into fuzzer findings.
- Policy engine: stays in Python so allowlists and severities are testable
  without root or Linux.

## Backends

The sidecar should expose backend choices while keeping the stdout/stdin
protocol stable:

- `fake`: deterministic local development and CI.
- `ebpf`: Linux CO-RE backend using `aya` or `libbpf-rs`.
- Later: a lossy `/proc` snapshot backend or a Tetragon JSON adapter.

## Event attribution

For stdio MCP servers, `mcp-server-fuzzer` serializes calls through its IO lock.
That means at most one `tools/call` is active. The monitor sends begin/end marks
around the call; the sidecar assigns events inside the mark window to that
`call_id`.

Events outside a call window are retained in an `ambient` bucket. Ambient events
are not noise by default; delayed exfiltration and persistence attempts often
appear there.

## Linux eBPF MVP

The first eBPF backend should implement:

- `sched_process_exec` plus fork tracking for exec events and descendants.
- TCP connect state and UDP send hooks for network events.
- `security_file_open` with path resolution for file events.

The kernel side should only capture and filter. It should not make policy
decisions.

