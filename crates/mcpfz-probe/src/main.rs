//! `mcpfz-probe` — runtime probe sidecar for MCP server fuzzing.
//!
//! The sidecar reads newline-delimited JSON control messages from stdin and
//! writes newline-delimited JSON runtime events to stdout. See `docs/protocol.md`.
//!
//! Two backends are selectable with `--backend`:
//! - `fake`: deterministic replay for CI and local development (this file wires
//!   it up; the logic lives in [`fake`]).
//! - `ebpf`: Linux CO-RE backend (not yet implemented; see [`ebpf`]).

mod ebpf;
mod fake;

use std::env;
use std::fs;
use std::io::{self, BufReader};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

const USAGE: &str = "\
mcpfz-probe — runtime probe sidecar for MCP server fuzzing

USAGE:
    mcpfz-probe [OPTIONS]

OPTIONS:
    --backend <fake|ebpf>   Backend to run (default: ebpf)
    --events-file <PATH>    Fake backend: JSON script of events to replay
    --grace-ms <MS>         Trailing window after a call end mark (default: 100)
    -h, --help              Print this help and exit
    -V, --version           Print version and exit

The sidecar reads NDJSON control messages on stdin and writes NDJSON runtime
events on stdout. See docs/protocol.md.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    Fake,
    Ebpf,
}

struct Args {
    backend: Backend,
    events_file: Option<String>,
    grace_ms: u64,
}

enum Parsed {
    Run(Args),
    Help,
    Version,
    Error(String),
}

fn main() -> ExitCode {
    match parse_args(env::args().skip(1)) {
        Parsed::Help => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Parsed::Version => {
            println!("mcpfz-probe {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Parsed::Error(message) => {
            eprintln!("mcpfz-probe: {message}");
            eprintln!("try 'mcpfz-probe --help'");
            ExitCode::from(2)
        }
        Parsed::Run(args) => run(args),
    }
}

fn run(args: Args) -> ExitCode {
    match args.backend {
        Backend::Fake => run_fake(args),
        Backend::Ebpf => match ebpf::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("mcpfz-probe: {err}");
                // EX_UNAVAILABLE: backend not available on this platform/build.
                ExitCode::from(69)
            }
        },
    }
}

fn run_fake(args: Args) -> ExitCode {
    let script = match &args.events_file {
        Some(path) => match fs::read_to_string(path) {
            Ok(text) => match fake::parse_script(&text) {
                Ok(script) => script,
                Err(err) => {
                    eprintln!("mcpfz-probe: failed to parse events file '{path}': {err}");
                    return ExitCode::from(2);
                }
            },
            Err(err) => {
                eprintln!("mcpfz-probe: failed to read events file '{path}': {err}");
                return ExitCode::from(2);
            }
        },
        None => Vec::new(),
    };

    let backend = fake::FakeBackend::new(script, args.grace_ms);
    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    let mut stdout = io::stdout().lock();
    match fake::run(backend, reader, &mut stdout) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("mcpfz-probe: io error: {err}");
            ExitCode::from(1)
        }
    }
}

fn parse_args<I: Iterator<Item = String>>(mut args: I) -> Parsed {
    let mut backend = Backend::Ebpf;
    let mut events_file = None;
    let mut grace_ms = 100u64;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => return Parsed::Help,
            "-V" | "--version" => return Parsed::Version,
            "--backend" => match args.next() {
                Some(value) => match value.as_str() {
                    "fake" => backend = Backend::Fake,
                    "ebpf" => backend = Backend::Ebpf,
                    other => return Parsed::Error(format!("unknown backend '{other}'")),
                },
                None => return Parsed::Error("--backend requires a value".to_string()),
            },
            "--events-file" => match args.next() {
                Some(value) => events_file = Some(value),
                None => return Parsed::Error("--events-file requires a value".to_string()),
            },
            "--grace-ms" => match args.next() {
                Some(value) => match value.parse::<u64>() {
                    Ok(ms) => grace_ms = ms,
                    Err(_) => return Parsed::Error(format!("invalid --grace-ms value '{value}'")),
                },
                None => return Parsed::Error("--grace-ms requires a value".to_string()),
            },
            other => return Parsed::Error(format!("unexpected argument '{other}'")),
        }
    }

    Parsed::Run(Args {
        backend,
        events_file,
        grace_ms,
    })
}

/// Wall-clock timestamp in nanoseconds since the Unix epoch.
pub fn now_ns() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Parsed {
        parse_args(args.iter().map(|s| s.to_string()))
    }

    #[test]
    fn defaults_to_ebpf_backend() {
        match parse(&[]) {
            Parsed::Run(args) => {
                assert_eq!(args.backend, Backend::Ebpf);
                assert_eq!(args.grace_ms, 100);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn parses_fake_backend_options() {
        match parse(&[
            "--backend",
            "fake",
            "--events-file",
            "e.json",
            "--grace-ms",
            "250",
        ]) {
            Parsed::Run(args) => {
                assert_eq!(args.backend, Backend::Fake);
                assert_eq!(args.events_file.as_deref(), Some("e.json"));
                assert_eq!(args.grace_ms, 250);
            }
            _ => panic!("expected Run"),
        }
    }

    #[test]
    fn help_and_version_short_circuit() {
        assert!(matches!(parse(&["--help"]), Parsed::Help));
        assert!(matches!(parse(&["-V"]), Parsed::Version));
    }

    #[test]
    fn rejects_unknown_backend_and_bad_grace() {
        assert!(matches!(parse(&["--backend", "nope"]), Parsed::Error(_)));
        assert!(matches!(parse(&["--grace-ms", "abc"]), Parsed::Error(_)));
        assert!(matches!(parse(&["--stray"]), Parsed::Error(_)));
    }
}
