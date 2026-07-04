//! Linux CO-RE eBPF backend.
//!
//! Loads the compiled BPF program (see `crates/mcpfz-probe-ebpf`), attaches it to
//! a set of `syscalls:sys_enter_*` tracepoints, and turns the ring-buffer events
//! into the same NDJSON protocol the fake backend speaks. A control thread reads
//! marks and scope on stdin; the kernel only captures, and userspace does scope
//! filtering (by process group, via `/proc`), call attribution, and emission.
//!
//! Probes: exec (`execve`), network (`connect`, `sendto`), file open (`openat`),
//! delete (`unlink`, `unlinkat`), chmod (`chmod`, `fchmodat`), and `ptrace`.
//!
//! This is compiled only with `--features ebpf` on Linux. Without the feature the
//! stub at the bottom returns a clear error, keeping the portable build free of
//! aya/LLVM/nightly.
//!
//! Known limitations: the tracepoints are system-wide and [`process_pgid`]
//! resolves a process's group via `/proc/<pid>/stat` in userspace, which races
//! short-lived processes and adds per-event overhead. Per `docs/architecture.md`,
//! scope filtering should move into the kernel program (read `task->group_leader`
//! via CO-RE) so the ring only ever carries in-scope events.

#[cfg(feature = "ebpf")]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, Stdout, Write};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use aya::Ebpf;

    use crate::fake::Control;

    // All tracepoints this backend attaches: (program name, category, event).
    const PROGRAMS: &[(&str, &str, &str)] = &[
        ("sys_enter_execve", "syscalls", "sys_enter_execve"),
        ("sys_enter_connect", "syscalls", "sys_enter_connect"),
        ("sys_enter_sendto", "syscalls", "sys_enter_sendto"),
        ("sys_enter_openat", "syscalls", "sys_enter_openat"),
        ("sys_enter_unlinkat", "syscalls", "sys_enter_unlinkat"),
        ("sys_enter_unlink", "syscalls", "sys_enter_unlink"),
        ("sys_enter_fchmodat", "syscalls", "sys_enter_fchmodat"),
        ("sys_enter_chmod", "syscalls", "sys_enter_chmod"),
        ("sys_enter_ptrace", "syscalls", "sys_enter_ptrace"),
    ];

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mcpfz-probe-ebpf.bpf.o"
    )))?;

    for (name, category, event) in PROGRAMS {
        let program: &mut TracePoint = bpf
            .program_mut(name)
            .ok_or_else(|| format!("bpf program '{name}' not found"))?
            .try_into()?;
        program.load()?;
        program.attach(category, event)?;
    }

    let mut ring = RingBuf::try_from(bpf.take_map("EVENTS").ok_or("map 'EVENTS' not found")?)?;

    #[derive(Default)]
    struct State {
        active_call: Option<String>,
        scope_pgid: Option<i32>,
        scoped: bool,
        // End marks are queued here and applied by the main loop *after* it
        // drains the ring, so events captured during the call attribute to it.
        pending_ends: Vec<Option<String>>,
    }
    let state = Arc::new(Mutex::new(State::default()));
    let shutdown = Arc::new(AtomicBool::new(false));
    // Both threads emit NDJSON; share one locked handle so lines never interleave.
    let out = Arc::new(Mutex::new(std::io::stdout()));

    fn write_line(out: &Mutex<Stdout>, value: serde_json::Value) {
        if let Ok(mut handle) = out.lock() {
            let _ = writeln!(handle, "{value}");
            let _ = handle.flush();
        }
    }

    // Control thread: apply scope and begin/end marks from stdin, echo status.
    let control = {
        let state = Arc::clone(&state);
        let shutdown = Arc::clone(&shutdown);
        let out = Arc::clone(&out);
        std::thread::Builder::new()
            .name("mcpfz-probe-control".into())
            .spawn(move || {
                let stdin = std::io::stdin();
                for line in stdin.lock().lines() {
                    let Ok(line) = line else { break };
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<Control>(line) {
                        Ok(Control::Scope { pgid, generation }) => {
                            {
                                let mut s = state.lock().unwrap();
                                s.scope_pgid = Some(pgid as i32);
                                s.scoped = true;
                            }
                            write_line(&out, serde_json::json!({
                                "type": "status", "bucket": "ambient", "message": "scope",
                                "pgid": pgid, "generation": generation, "ts_ns": crate::now_ns() as u64,
                            }));
                        }
                        Ok(Control::Mark { phase, call_id, .. }) => match phase.as_str() {
                            "begin" => {
                                state.lock().unwrap().active_call = call_id.clone();
                                write_line(&out, serde_json::json!({
                                    "type": "status", "bucket": "call", "message": "begin",
                                    "call_id": call_id, "ts_ns": crate::now_ns() as u64,
                                }));
                            }
                            "end" => {
                                // Defer to the main loop; it drains the ring first
                                // so in-flight execs still attribute to this call.
                                state.lock().unwrap().pending_ends.push(call_id);
                            }
                            _ => {}
                        },
                        Ok(Control::Shutdown) => break,
                        Err(_) => {}
                    }
                }
                shutdown.store(true, Ordering::SeqCst);
            })?
    };

    write_line(
        &out,
        serde_json::json!({
            "type": "status", "bucket": "startup", "message": "ready",
            "backend": "ebpf", "ts_ns": crate::now_ns() as u64,
        }),
    );

    let ring_fd = ring.as_raw_fd();
    // The tracepoints are system-wide, so the ring is fed by every process's
    // syscalls; on a busy host it may never fully drain. Bound the batch so the
    // queued end marks below are always processed, and only sleep when idle.
    // The ring holds far fewer than this, so an in-scope call's events are drained
    // before its end mark is applied. `pgid_cache` avoids re-reading /proc for
    // the same pid within a batch.
    const DRAIN_BATCH: usize = 8192;
    while !shutdown.load(Ordering::SeqCst) {
        let mut drained = 0usize;
        let mut pgid_cache: std::collections::HashMap<u32, Option<i32>> =
            std::collections::HashMap::new();
        while drained < DRAIN_BATCH {
            let Some(item) = ring.next() else { break };
            drained += 1;
            let bytes: &[u8] = &item;
            // Every event starts with `kind: u32, pid: u32`.
            if bytes.len() < 8 {
                continue;
            }
            let kind = u32::from_ne_bytes(bytes[0..4].try_into().unwrap());
            let pid = u32::from_ne_bytes(bytes[4..8].try_into().unwrap());

            let (bucket, call_id, scoped, scope_pgid) = {
                let s = state.lock().unwrap();
                let bucket = if s.active_call.is_some() {
                    "call"
                } else if s.scoped {
                    "ambient"
                } else {
                    "startup"
                };
                (bucket, s.active_call.clone(), s.scoped, s.scope_pgid)
            };

            // Scope filter: only report events from the monitored process group.
            if scoped {
                let pgid = *pgid_cache.entry(pid).or_insert_with(|| process_pgid(pid));
                if pgid != scope_pgid {
                    continue;
                }
            }

            // Decode the type-specific fields (returns None to skip the record).
            let mut obj = match decode(kind, bytes) {
                Some(obj) => obj,
                None => continue,
            };
            obj.insert("bucket".into(), serde_json::Value::from(bucket));
            if let Some(cid) = call_id {
                obj.insert("call_id".into(), serde_json::Value::from(cid));
            }
            obj.insert("pid".into(), serde_json::Value::from(pid));
            obj.insert(
                "ts_ns".into(),
                serde_json::Value::from(crate::now_ns() as u64),
            );
            write_line(&out, serde_json::Value::Object(obj));
        }

        // Ring is drained; now apply any queued end marks and emit their status.
        let ends = {
            let mut s = state.lock().unwrap();
            std::mem::take(&mut s.pending_ends)
        };
        for end_call_id in ends {
            let ended = {
                let mut s = state.lock().unwrap();
                s.active_call.take().or(end_call_id)
            };
            write_line(
                &out,
                serde_json::json!({
                    "type": "status", "bucket": "call", "message": "end",
                    "call_id": ended, "ts_ns": crate::now_ns() as u64,
                }),
            );
        }

        // If we hit the batch cap the ring likely still has data — keep draining;
        // otherwise block until the next event (or 200ms) instead of spinning.
        if drained < DRAIN_BATCH {
            poll_readable(ring_fd, 200);
        }
    }

    let _ = control.join();
    Ok(())
}

/// Decode a ring-buffer record's type-specific fields into a JSON object.
/// Common fields (bucket/call_id/pid/ts_ns) are added by the caller.
#[cfg(feature = "ebpf")]
fn decode(kind: u32, bytes: &[u8]) -> Option<serde_json::Map<String, serde_json::Value>> {
    use mcpfz_probe_ebpf_common::{
        as_str, ExecEvent, NetEvent, PathEvent, PtraceEvent, KIND_CHMOD, KIND_CONNECT, KIND_EXEC,
        KIND_FILE_OPEN, KIND_PTRACE, KIND_SENDTO, KIND_UNLINK,
    };
    use serde_json::Value;

    fn read<T: Copy>(bytes: &[u8]) -> Option<T> {
        if bytes.len() < std::mem::size_of::<T>() {
            return None;
        }
        // Safety: the kernel wrote this exact repr(C) struct; read_unaligned
        // tolerates the ring buffer's arbitrary alignment.
        Some(unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const T) })
    }

    let mut o = serde_json::Map::new();
    match kind {
        KIND_EXEC => {
            let ev: ExecEvent = read(bytes)?;
            o.insert("type".into(), Value::from("exec"));
            o.insert("comm".into(), Value::from(as_str(&ev.comm)));
            o.insert(
                "argv".into(),
                Value::from(vec![as_str(&ev.filename).to_string()]),
            );
        }
        KIND_CONNECT | KIND_SENDTO => {
            let ev: NetEvent = read(bytes)?;
            if ev.af != 2 && ev.af != 10 {
                return None; // no usable destination (e.g. unconnected sendto)
            }
            let dst = format!("{}:{}", fmt_addr(ev.af, &ev.addr), u16::from_be(ev.port_be));
            o.insert("type".into(), Value::from("connect"));
            o.insert(
                "proto".into(),
                Value::from(if kind == KIND_SENDTO { "udp" } else { "tcp" }),
            );
            o.insert("dst".into(), Value::from(dst));
            o.insert("comm".into(), Value::from(as_str(&ev.comm)));
        }
        KIND_FILE_OPEN => {
            let ev: PathEvent = read(bytes)?;
            o.insert("type".into(), Value::from("file_open"));
            o.insert("path".into(), Value::from(as_str(&ev.filename)));
            o.insert("flags".into(), Value::from(flags_to_string(ev.arg as i32)));
            o.insert("comm".into(), Value::from(as_str(&ev.comm)));
        }
        KIND_UNLINK => {
            let ev: PathEvent = read(bytes)?;
            o.insert("type".into(), Value::from("file_delete"));
            o.insert("path".into(), Value::from(as_str(&ev.filename)));
            o.insert("comm".into(), Value::from(as_str(&ev.comm)));
        }
        KIND_CHMOD => {
            let ev: PathEvent = read(bytes)?;
            o.insert("type".into(), Value::from("chmod"));
            o.insert("path".into(), Value::from(as_str(&ev.filename)));
            o.insert("mode".into(), Value::from(format!("{:o}", ev.arg & 0o7777)));
            o.insert("comm".into(), Value::from(as_str(&ev.comm)));
        }
        KIND_PTRACE => {
            let ev: PtraceEvent = read(bytes)?;
            o.insert("type".into(), Value::from("ptrace"));
            o.insert("request".into(), Value::from(ev.request));
            o.insert("target_pid".into(), Value::from(ev.target_pid));
            o.insert("comm".into(), Value::from(as_str(&ev.comm)));
        }
        _ => return None,
    }
    Some(o)
}

/// Render open(2) flags as a `|`-joined string the policy engine understands.
#[cfg(feature = "ebpf")]
fn flags_to_string(flags: i32) -> String {
    let mut parts = vec![match flags & 0o3 {
        1 => "O_WRONLY",
        2 => "O_RDWR",
        _ => "O_RDONLY",
    }
    .to_string()];
    for (bit, name) in [
        (0o100, "O_CREAT"),
        (0o200, "O_EXCL"),
        (0o1000, "O_TRUNC"),
        (0o2000, "O_APPEND"),
    ] {
        if flags & bit != 0 {
            parts.push(name.to_string());
        }
    }
    parts.join("|")
}

/// Format a captured address as a string for the given address family.
#[cfg(feature = "ebpf")]
fn fmt_addr(af: u16, addr: &[u8; 16]) -> String {
    match af {
        2 => std::net::Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string(),
        10 => std::net::Ipv6Addr::from(*addr).to_string(),
        _ => "?".to_string(),
    }
}

/// Read a process's process-group id from `/proc/<pid>/stat`.
///
/// The `comm` field (2nd) is parenthesized and may itself contain spaces or
/// parens, so parsing resumes after the final `)`.
#[cfg(feature = "ebpf")]
fn process_pgid(pid: u32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.get(stat.rfind(')')? + 1..)?;
    // Fields after comm: state, ppid, pgrp, ...
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?;
    let _ppid = fields.next()?;
    fields.next()?.parse::<i32>().ok()
}

#[cfg(feature = "ebpf")]
fn poll_readable(fd: std::os::fd::RawFd, timeout_ms: i32) {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // Best-effort wait; spurious wakeups just re-check the ring and shutdown flag.
    unsafe {
        libc::poll(&mut pfd, 1, timeout_ms);
    }
}

#[cfg(not(feature = "ebpf"))]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("eBPF backend not compiled in; rebuild on Linux with --features ebpf".into())
}
