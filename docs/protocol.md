# Sidecar NDJSON Protocol

All messages are newline-delimited JSON.

## Control messages

Sent from Python monitor to sidecar stdin.

### Scope

```json
{"op":"scope","pgid":1234,"generation":1}
```

Sets the process group to monitor. `generation` increments every time the MCP
server restarts.

### Mark begin

```json
{"op":"mark","phase":"begin","call_id":"uuid","tool":"tool_name"}
```

Starts attributing in-scope runtime events to `call_id`.

### Mark end

```json
{"op":"mark","phase":"end","call_id":"uuid"}
```

Ends the active call window. The sidecar may continue assigning a small trailing
grace window to the call before returning to ambient.

## Event messages

Sent from sidecar stdout to Python monitor.

Common fields:

- `type`: `exec`, `connect`, `file_open`, `drop`, or `status`.
- `bucket`: `startup`, `call`, or `ambient`.
- `call_id`: present for call-attributed events.
- `pid`, `ppid`, `pgid`, `generation`: process metadata when available.
- `ts_ns`: sidecar timestamp.

### Exec

```json
{"type":"exec","bucket":"call","call_id":"uuid","pid":42,"argv":["/bin/sh","-c","curl example.com"]}
```

### Connect

```json
{"type":"connect","bucket":"call","call_id":"uuid","pid":42,"proto":"tcp","dst":"203.0.113.7:443"}
```

### File open

```json
{"type":"file_open","bucket":"call","call_id":"uuid","pid":42,"path":"/home/me/.ssh/id_ed25519","flags":"O_RDONLY"}
```

### Drop

```json
{"type":"drop","count":17,"reason":"ring_buffer_full"}
```

