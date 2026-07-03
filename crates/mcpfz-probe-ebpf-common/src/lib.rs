//! Types shared between the eBPF kernel program and the userspace loader.
//!
//! This crate is `no_std` so it can be compiled both for the BPF target and for
//! the host. It contains only plain-old-data laid out with `#[repr(C)]` so the
//! same bytes written by the kernel program are read back by userspace.
#![no_std]

pub const FILENAME_LEN: usize = 256;
pub const COMM_LEN: usize = 16;

/// A process-exec event captured on `sys_enter_execve`.
///
/// `filename` and `comm` are NUL-padded byte buffers; use [`ExecEvent::str`] to
/// read them as `&str` on the userspace side.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ExecEvent {
    /// Thread-group id (the "pid" as userspace means it).
    pub pid: u32,
    /// Kernel thread id of the caller.
    pub tid: u32,
    /// execve target path (from the syscall's first argument).
    pub filename: [u8; FILENAME_LEN],
    /// Task comm at exec time.
    pub comm: [u8; COMM_LEN],
}

impl ExecEvent {
    /// Interpret a NUL-padded field as a `&str`, dropping the trailing NULs.
    pub fn as_str(buf: &[u8]) -> &str {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        core::str::from_utf8(&buf[..end]).unwrap_or("")
    }
}
