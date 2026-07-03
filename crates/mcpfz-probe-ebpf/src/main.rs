//! eBPF kernel program: capture security-relevant syscalls.
//!
//! Attaches to `syscalls:sys_enter_*` tracepoints and pushes a tagged event onto
//! a ring buffer for the userspace loader to attribute and emit. Reading syscall
//! arguments (and, for network events, the user-supplied `sockaddr`) avoids
//! kernel-struct CO-RE entirely. The kernel side only captures — scope
//! filtering, call attribution, and policy live in userspace.
//!
//! Probes: execve, connect, sendto, openat, unlinkat, fchmodat, ptrace.
#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user, bpf_probe_read_user_str_bytes},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use mcpfz_probe_ebpf_common::{
    ExecEvent, NetEvent, PathEvent, PtraceEvent, KIND_CHMOD, KIND_CONNECT, KIND_FILE_OPEN,
    KIND_PTRACE, KIND_SENDTO, KIND_UNLINK,
};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

// In syscall-enter tracepoints the payload is: 8 bytes of common fields, a
// (padded) __syscall_nr, then each argument in an 8-byte slot from offset 16.
const ARG0: usize = 16;
const ARG1: usize = 24;
const ARG2: usize = 32;
const ARG4: usize = 48;

#[inline(always)]
fn pid_tid() -> (u32, u32) {
    let v = bpf_get_current_pid_tgid();
    ((v >> 32) as u32, v as u32)
}

#[inline(always)]
fn comm() -> [u8; 16] {
    bpf_get_current_comm().unwrap_or([0u8; 16])
}

// ---- exec ----------------------------------------------------------------

#[tracepoint]
pub fn sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = try_exec(&ctx);
    0
}

fn try_exec(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = EVENTS.reserve::<ExecEvent>(0).ok_or(0i64)?;
    let e = entry.as_mut_ptr();
    unsafe {
        let (pid, tid) = pid_tid();
        (*e).kind = mcpfz_probe_ebpf_common::KIND_EXEC;
        (*e).pid = pid;
        (*e).tid = tid;
        (*e).comm = comm();
        (*e).filename[0] = 0;
        if let Ok(p) = ctx.read_at::<*const u8>(ARG0) {
            let _ = bpf_probe_read_user_str_bytes(p, &mut (*e).filename);
        }
    }
    entry.submit(0);
    Ok(())
}

// ---- network (connect / sendto) ------------------------------------------

#[tracepoint]
pub fn sys_enter_connect(ctx: TracePointContext) -> u32 {
    let _ = try_net(&ctx, KIND_CONNECT, ARG1);
    0
}

#[tracepoint]
pub fn sys_enter_sendto(ctx: TracePointContext) -> u32 {
    let _ = try_net(&ctx, KIND_SENDTO, ARG4);
    0
}

fn try_net(ctx: &TracePointContext, kind: u32, addr_off: usize) -> Result<(), i64> {
    let uaddr = unsafe { ctx.read_at::<u64>(addr_off) }.unwrap_or(0) as *const u8;
    if uaddr.is_null() {
        return Ok(());
    }
    let mut entry = EVENTS.reserve::<NetEvent>(0).ok_or(0i64)?;
    let e = entry.as_mut_ptr();
    unsafe {
        let (pid, tid) = pid_tid();
        (*e).kind = kind;
        (*e).pid = pid;
        (*e).tid = tid;
        (*e).comm = comm();
        (*e).addr = [0u8; 16];
        let af = bpf_probe_read_user(uaddr as *const u16).unwrap_or(0);
        (*e).af = af;
        (*e).port_be = bpf_probe_read_user((uaddr as usize + 2) as *const u16).unwrap_or(0);
        if af == AF_INET {
            let a = bpf_probe_read_user((uaddr as usize + 4) as *const [u8; 4]).unwrap_or([0u8; 4]);
            (*e).addr[0] = a[0];
            (*e).addr[1] = a[1];
            (*e).addr[2] = a[2];
            (*e).addr[3] = a[3];
        } else if af == AF_INET6 {
            (*e).addr =
                bpf_probe_read_user((uaddr as usize + 8) as *const [u8; 16]).unwrap_or([0u8; 16]);
        }
    }
    entry.submit(0);
    Ok(())
}

// ---- path syscalls (openat / unlinkat / fchmodat) ------------------------

#[tracepoint]
pub fn sys_enter_openat(ctx: TracePointContext) -> u32 {
    // openat(dfd, filename@ARG1, flags@ARG2, mode)
    let _ = try_path(&ctx, KIND_FILE_OPEN, ARG1, ARG2);
    0
}

#[tracepoint]
pub fn sys_enter_unlinkat(ctx: TracePointContext) -> u32 {
    // unlinkat(dfd, pathname@ARG1, flag)
    let _ = try_path(&ctx, KIND_UNLINK, ARG1, ARG2);
    0
}

#[tracepoint]
pub fn sys_enter_fchmodat(ctx: TracePointContext) -> u32 {
    // fchmodat(dfd, filename@ARG1, mode@ARG2)
    let _ = try_path(&ctx, KIND_CHMOD, ARG1, ARG2);
    0
}

#[tracepoint]
pub fn sys_enter_unlink(ctx: TracePointContext) -> u32 {
    // unlink(pathname@ARG0)
    let _ = try_path(&ctx, KIND_UNLINK, ARG0, ARG0);
    0
}

#[tracepoint]
pub fn sys_enter_chmod(ctx: TracePointContext) -> u32 {
    // chmod(filename@ARG0, mode@ARG1)
    let _ = try_path(&ctx, KIND_CHMOD, ARG0, ARG1);
    0
}

fn try_path(ctx: &TracePointContext, kind: u32, path_off: usize, arg_off: usize) -> Result<(), i64> {
    let mut entry = EVENTS.reserve::<PathEvent>(0).ok_or(0i64)?;
    let e = entry.as_mut_ptr();
    unsafe {
        let (pid, tid) = pid_tid();
        (*e).kind = kind;
        (*e).pid = pid;
        (*e).tid = tid;
        (*e).comm = comm();
        (*e).arg = ctx.read_at::<i64>(arg_off).unwrap_or(0);
        (*e).filename[0] = 0;
        if let Ok(p) = ctx.read_at::<*const u8>(path_off) {
            let _ = bpf_probe_read_user_str_bytes(p, &mut (*e).filename);
        }
    }
    entry.submit(0);
    Ok(())
}

// ---- ptrace --------------------------------------------------------------

#[tracepoint]
pub fn sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    let _ = try_ptrace(&ctx);
    0
}

fn try_ptrace(ctx: &TracePointContext) -> Result<(), i64> {
    let mut entry = EVENTS.reserve::<PtraceEvent>(0).ok_or(0i64)?;
    let e = entry.as_mut_ptr();
    unsafe {
        let (pid, tid) = pid_tid();
        (*e).kind = KIND_PTRACE;
        (*e).pid = pid;
        (*e).tid = tid;
        (*e).comm = comm();
        (*e).request = ctx.read_at::<i64>(ARG0).unwrap_or(0);
        (*e).target_pid = ctx.read_at::<i64>(ARG1).unwrap_or(0);
    }
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
