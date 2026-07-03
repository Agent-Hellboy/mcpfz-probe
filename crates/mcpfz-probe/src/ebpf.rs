//! Linux CO-RE eBPF backend.
//!
//! Loads the compiled BPF program (see `crates/mcpfz-probe-ebpf`), attaches it
//! to `syscalls:sys_enter_execve`, and turns the ring-buffer exec events into the
//! same NDJSON protocol the fake backend speaks. A control thread reads marks and
//! scope on stdin; the kernel only captures, and userspace does scope filtering
//! (by process group, via `/proc`), call attribution, and emission.
//!
//! This is compiled only with `--features ebpf` on Linux. Without the feature the
//! stub at the bottom returns a clear error, keeping the portable build free of
//! aya/LLVM/nightly.
//!
//! MVP status: exec events are implemented. TCP/UDP connect and `file_open`
//! probes are the next additions behind the same ring buffer and emit path.
//!
//! Known limitation: [`process_pgid`] resolves a process's group via
//! `/proc/<pid>/stat` in userspace, which races short-lived processes that exit
//! before the read. Per `docs/architecture.md`, scope filtering should move into
//! the kernel program (read `task->group_leader` via CO-RE); that is the next
//! step alongside the additional probes.

#[cfg(feature = "ebpf")]
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{BufRead, Stdout, Write};
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use aya::maps::RingBuf;
    use aya::programs::TracePoint;
    use aya::Ebpf;
    use mcpfz_probe_ebpf_common::ExecEvent;

    use crate::fake::Control;

    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mcpfz-probe-ebpf.bpf.o"
    )))?;

    let program: &mut TracePoint = bpf
        .program_mut("sys_enter_execve")
        .ok_or("bpf program 'sys_enter_execve' not found")?
        .try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;

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
    while !shutdown.load(Ordering::SeqCst) {
        while let Some(item) = ring.next() {
            let bytes: &[u8] = &item;
            if bytes.len() < std::mem::size_of::<ExecEvent>() {
                continue;
            }
            // Safety: the kernel program writes exactly an ExecEvent (repr(C)).
            let event: ExecEvent =
                unsafe { std::ptr::read_unaligned(bytes.as_ptr() as *const ExecEvent) };

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
                match process_pgid(event.pid) {
                    Some(pgid) if Some(pgid) == scope_pgid => {}
                    _ => continue,
                }
            }

            let filename = ExecEvent::as_str(&event.filename);
            let comm = ExecEvent::as_str(&event.comm);
            let mut obj = serde_json::Map::new();
            obj.insert("type".into(), serde_json::Value::from("exec"));
            obj.insert("bucket".into(), serde_json::Value::from(bucket));
            if let Some(cid) = call_id {
                obj.insert("call_id".into(), serde_json::Value::from(cid));
            }
            obj.insert("pid".into(), serde_json::Value::from(event.pid));
            obj.insert("comm".into(), serde_json::Value::from(comm));
            obj.insert(
                "argv".into(),
                serde_json::Value::from(vec![filename.to_string()]),
            );
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

        poll_readable(ring_fd, 200);
    }

    let _ = control.join();
    Ok(())
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
