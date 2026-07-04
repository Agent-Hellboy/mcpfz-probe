//! Types shared between the eBPF kernel program and the userspace loader.
//!
//! This crate is `no_std` so it can be compiled both for the BPF target and for
//! the host. It contains only plain-old-data laid out with `#[repr(C)]` so the
//! same bytes written by the kernel program are read back by userspace. Every
//! event begins with a `kind` discriminant so the loader can decode a mixed
//! ring-buffer stream.
#![no_std]

pub const FILENAME_LEN: usize = 256;
pub const COMM_LEN: usize = 16;
pub const ADDR_LEN: usize = 16;

pub const KIND_EXEC: u32 = 1;
pub const KIND_CONNECT: u32 = 2;
pub const KIND_SENDTO: u32 = 3;
pub const KIND_FILE_OPEN: u32 = 4;
pub const KIND_UNLINK: u32 = 5;
pub const KIND_CHMOD: u32 = 6;
pub const KIND_PTRACE: u32 = 7;

/// A process-exec event captured on `sys_enter_execve`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    pub kind: u32,
    /// Thread-group id (the "pid" as userspace means it).
    pub pid: u32,
    /// Kernel thread id of the caller.
    pub tid: u32,
    /// execve target path (from the syscall's first argument).
    pub filename: [u8; FILENAME_LEN],
    /// Task comm at exec time.
    pub comm: [u8; COMM_LEN],
}

/// A network destination event: `connect` (`KIND_CONNECT`) or `sendto`
/// (`KIND_SENDTO`). The destination is read from the user-supplied `sockaddr`,
/// so no kernel struct access is needed. `port_be` is network byte order;
/// `addr` holds 4 bytes for `AF_INET` and 16 for `AF_INET6`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NetEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub af: u16,
    pub port_be: u16,
    pub addr: [u8; ADDR_LEN],
    pub comm: [u8; COMM_LEN],
}

/// A path-based syscall event: `openat` (`KIND_FILE_OPEN`), `unlinkat`
/// (`KIND_UNLINK`), or `fchmodat` (`KIND_CHMOD`). `arg` carries the open flags,
/// the chmod mode, or is unused for unlink.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PathEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub arg: i64,
    pub filename: [u8; FILENAME_LEN],
    pub comm: [u8; COMM_LEN],
}

/// A `ptrace` event (`KIND_PTRACE`) — potential process injection.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PtraceEvent {
    pub kind: u32,
    pub pid: u32,
    pub tid: u32,
    pub request: i64,
    pub target_pid: i64,
    pub comm: [u8; COMM_LEN],
}

/// Interpret a NUL-padded field as a `&str`, dropping the trailing NULs.
pub fn as_str(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    core::str::from_utf8(&buf[..end]).unwrap_or("")
}
