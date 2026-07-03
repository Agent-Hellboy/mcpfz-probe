use std::env;
use std::io::{self, BufRead, Write};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Fake,
    Ebpf,
}

fn main() -> ExitCode {
    let backend = parse_backend();
    match backend {
        Backend::Fake => run_fake(),
        Backend::Ebpf => {
            eprintln!("mcpfz-probe: eBPF backend is not implemented in this scaffold");
            ExitCode::from(78)
        }
    }
}

fn parse_backend() -> Backend {
    let mut backend = Backend::Ebpf;
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--backend" {
            if let Some(value) = args.next() {
                backend = match value.as_str() {
                    "fake" => Backend::Fake,
                    "ebpf" => Backend::Ebpf,
                    _ => Backend::Ebpf,
                };
            }
        }
    }
    backend
}

fn run_fake() -> ExitCode {
    let stdin = io::stdin();
    let mut stdout = io::stdout().lock();
    let mut active_call: Option<String> = None;
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            return ExitCode::from(1);
        };
        if line.contains("\"op\":\"shutdown\"") {
            return ExitCode::SUCCESS;
        }
        if line.contains("\"op\":\"mark\"") && line.contains("\"phase\":\"begin\"") {
            active_call = extract_json_string(&line, "call_id");
            let _ = writeln!(
                stdout,
                "{{\"type\":\"status\",\"bucket\":\"call\",\"call_id\":\"{}\",\"ts_ns\":{},\"message\":\"begin\"}}",
                active_call.as_deref().unwrap_or(""),
                now_ns()
            );
            let _ = stdout.flush();
        } else if line.contains("\"op\":\"mark\"") && line.contains("\"phase\":\"end\"") {
            let call_id = extract_json_string(&line, "call_id").or(active_call.take());
            let _ = writeln!(
                stdout,
                "{{\"type\":\"status\",\"bucket\":\"call\",\"call_id\":\"{}\",\"ts_ns\":{},\"message\":\"end\"}}",
                call_id.as_deref().unwrap_or(""),
                now_ns()
            );
            let _ = stdout.flush();
        } else if line.contains("\"op\":\"scope\"") {
            let _ = writeln!(
                stdout,
                "{{\"type\":\"status\",\"bucket\":\"ambient\",\"ts_ns\":{},\"message\":\"scope\"}}",
                now_ns()
            );
            let _ = stdout.flush();
        }
    }
    ExitCode::SUCCESS
}

fn extract_json_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\":\"", key);
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

