//! eBPF kernel program: capture process exec events.
//!
//! Attaches to the `syscalls:sys_enter_execve` tracepoint, records the calling
//! pid/tid, comm, and target filename, and pushes an [`ExecEvent`] onto a ring
//! buffer for the userspace loader to attribute and emit. The kernel side only
//! captures — all scope filtering, call attribution, and policy live in
//! userspace (see `docs/architecture.md`).
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use mcpfz_probe_ebpf_common::ExecEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

// Offset of the `filename` argument in the sys_enter_execve tracepoint record:
// 8 bytes of common fields + 8 bytes for the (padded) __syscall_nr.
const FILENAME_ARG_OFFSET: usize = 16;

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = try_exec(&ctx);
    0
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = EVENTS.reserve::<ExecEvent>(0).ok_or(0i64)?;
    let event = entry.as_mut_ptr();

    unsafe {
        let pid_tgid = bpf_get_current_pid_tgid();
        (*event).pid = (pid_tgid >> 32) as u32;
        (*event).tid = pid_tgid as u32;

        match bpf_get_current_comm() {
            Ok(comm) => (*event).comm = comm,
            Err(_) => (*event).comm = [0u8; 16],
        }

        (*event).filename[0] = 0;
        let filename_ptr = match ctx.read_at::<*const u8>(FILENAME_ARG_OFFSET) {
            Ok(ptr) => ptr,
            Err(_) => {
                entry.submit(0);
                return Ok(());
            }
        };
        let _ = bpf_probe_read_user_str_bytes(filename_ptr, &mut (*event).filename);
    }

    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // BPF programs cannot unwind; this is unreachable in practice.
    unsafe { core::hint::unreachable_unchecked() }
}
