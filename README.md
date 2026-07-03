# mcpfz-probe

Standalone runtime probe for MCP server fuzzing.

`mcpfz-probe` is intended to run beside `mcp-server-fuzzer`, not inside it. The
fuzzer owns process launch and per-call timing; this repo owns runtime event
collection, event attribution, and the sidecar protocol.

## Language choice

Use Rust for the sidecar.

Rust is the best fit here because the sidecar is a privileged boundary that must
be small, auditable, and shippable as static Linux artifacts. The first Linux
backend should use `aya` or `libbpf-rs` for CO-RE eBPF probes. Python should
remain the integration layer because `mcp-server-fuzzer` is Python and needs a
simple `RuntimeMonitor` abstraction.

Rejected options:

- Python/BCC: fragile runtime compiler and kernel-header dependency.
- Falco/Tetragon first: too heavy for `pip install` workflows and awkward for
  per-call marks.
- C-only sidecar: viable for the eBPF object, but worse for the long-lived
  control plane and release safety.

## Repo layout

```text
crates/mcpfz-probe/       Rust sidecar binary
src/mcpfz_probe/          Python monitor/client integration package
tests/                    CI-friendly Python tests using a fake backend
docs/                     Design and protocol notes
```

## Sidecar protocol

The Python monitor writes newline-delimited JSON marks to sidecar stdin:

```json
{"op":"mark","phase":"begin","call_id":"...","tool":"get_weather"}
{"op":"mark","phase":"end","call_id":"..."}
```

The sidecar writes newline-delimited JSON runtime events to stdout:

```json
{"type":"exec","bucket":"call","call_id":"...","pid":1234,"argv":["/bin/sh","-c","curl ..."]}
{"type":"connect","bucket":"ambient","pid":1234,"dst":"203.0.113.7:443"}
```

In the eBPF backend, the sidecar timestamps marks and kernel events in the same
clock domain and tags events between begin/end marks with the active `call_id`.

## MVP scope

1. Process exec events.
2. TCP/UDP connect events.
3. File open events, with sensitive read and out-of-workspace write policy in
   Python.

The current scaffold includes the stable process/protocol boundary and a fake
backend. The Linux eBPF backend should be added behind the same Rust interface.

## Development

Run Python tests:

```sh
python3 -m unittest discover -s tests
```

Build the Rust sidecar scaffold:

```sh
cargo build
```

