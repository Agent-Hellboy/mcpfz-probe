//! Deterministic fake backend.
//!
//! The fake backend does not touch the kernel. It replays a scripted list of
//! runtime events in response to the control messages (`scope`, `mark`,
//! `shutdown`) that the Python monitor writes to stdin. This gives
//! `mcp-server-fuzzer` a backend that produces realistic `exec` / `connect` /
//! `file_open` events — correctly placed in the `startup`, `call`, and
//! `ambient` buckets and attributed to the active `call_id` — without root,
//! Linux, or eBPF. It is the backend used by CI and local development.

use std::io::{BufRead, Write};

use serde::Deserialize;
use serde_json::{Map, Value};

/// A control message sent by the Python monitor to sidecar stdin.
#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Control {
    Scope {
        pgid: i64,
        #[serde(default)]
        generation: i64,
    },
    Mark {
        phase: String,
        #[serde(default)]
        call_id: Option<String>,
        #[serde(default)]
        tool: Option<String>,
    },
    Shutdown,
}

/// A single scripted event and the trigger that fires it.
///
/// `trigger` is one of:
/// - `startup`: emitted once when the sidecar starts, bucket `startup`.
/// - `scope`:   emitted when a `scope` message is received, bucket `ambient`.
/// - `begin`:   emitted when a `begin` mark is received, bucket `call`.
/// - `end`:     emitted when an `end` mark is received, bucket `call`
///              (the trailing grace window of the just-ended call).
///
/// For `begin`/`end` triggers an optional `tool` filter restricts the event to
/// marks carrying that tool name. The `event` object is passed through verbatim
/// with `bucket`, `call_id`, and `ts_ns` filled in by the sidecar.
#[derive(Debug, Deserialize, Clone)]
pub struct ScriptEntry {
    pub trigger: String,
    #[serde(default)]
    pub tool: Option<String>,
    pub event: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
struct ScriptFile {
    #[serde(default)]
    events: Vec<ScriptEntry>,
}

/// Parse an events file. Accepts either `{"events": [...]}` or a bare `[...]`.
pub fn parse_script(text: &str) -> Result<Vec<ScriptEntry>, serde_json::Error> {
    if let Ok(file) = serde_json::from_str::<ScriptFile>(text) {
        return Ok(file.events);
    }
    serde_json::from_str::<Vec<ScriptEntry>>(text)
}

/// The fake backend state machine.
pub struct FakeBackend {
    script: Vec<ScriptEntry>,
    active_call: Option<String>,
    active_tool: Option<String>,
    grace_ms: u64,
    clock: Box<dyn FnMut() -> u128>,
}

impl FakeBackend {
    pub fn new(script: Vec<ScriptEntry>, grace_ms: u64) -> Self {
        Self {
            script,
            active_call: None,
            active_tool: None,
            grace_ms,
            clock: Box::new(super::now_ns),
        }
    }

    /// Override the clock; used by tests to make timestamps deterministic.
    #[cfg(test)]
    pub fn with_clock(mut self, clock: Box<dyn FnMut() -> u128>) -> Self {
        self.clock = clock;
        self
    }

    fn now(&mut self) -> u128 {
        (self.clock)()
    }

    /// Emit an event object, filling in bucket / call_id / ts_ns.
    fn emit<W: Write>(
        &mut self,
        out: &mut W,
        mut obj: Map<String, Value>,
        bucket: &str,
        call_id: Option<&str>,
    ) -> std::io::Result<()> {
        if !obj.contains_key("type") {
            // A scripted event with no `type` is unusable; skip it rather than
            // emit a malformed line.
            return Ok(());
        }
        obj.entry("bucket")
            .or_insert_with(|| Value::String(bucket.to_string()));
        if let Some(cid) = call_id {
            obj.entry("call_id")
                .or_insert_with(|| Value::String(cid.to_string()));
        }
        let ts = self.now();
        obj.insert("ts_ns".to_string(), Value::from(ts as u64));
        writeln!(out, "{}", Value::Object(obj))?;
        out.flush()
    }

    fn emit_status<W: Write>(
        &mut self,
        out: &mut W,
        bucket: &str,
        call_id: Option<&str>,
        message: &str,
    ) -> std::io::Result<()> {
        let mut obj = Map::new();
        obj.insert("type".to_string(), Value::from("status"));
        obj.insert("message".to_string(), Value::from(message));
        self.emit(out, obj, bucket, call_id)
    }

    /// Replay every entry matching `trigger` (and, when given, `tool`).
    fn fire<W: Write>(
        &mut self,
        out: &mut W,
        trigger: &str,
        tool: Option<&str>,
        bucket: &str,
        call_id: Option<&str>,
    ) -> std::io::Result<()> {
        let matches: Vec<Map<String, Value>> = self
            .script
            .iter()
            .filter(|e| e.trigger == trigger)
            .filter(|e| match (&e.tool, tool) {
                (Some(want), Some(have)) => want == have,
                (Some(_), None) => false,
                (None, _) => true,
            })
            .map(|e| e.event.clone())
            .collect();
        for obj in matches {
            self.emit(out, obj, bucket, call_id)?;
        }
        Ok(())
    }

    /// Emitted once when the sidecar starts.
    pub fn on_start<W: Write>(&mut self, out: &mut W) -> std::io::Result<()> {
        let grace = self.grace_ms;
        let mut obj = Map::new();
        obj.insert("type".to_string(), Value::from("status"));
        obj.insert("message".to_string(), Value::from("ready"));
        obj.insert("backend".to_string(), Value::from("fake"));
        obj.insert("grace_ms".to_string(), Value::from(grace));
        self.emit(out, obj, "startup", None)?;
        self.fire(out, "startup", None, "startup", None)
    }

    /// Handle one control line. Returns `Ok(false)` to stop the loop.
    pub fn handle_line<W: Write>(&mut self, line: &str, out: &mut W) -> std::io::Result<bool> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Ok(true);
        }
        let control: Control = match serde_json::from_str(trimmed) {
            Ok(control) => control,
            Err(err) => {
                let mut obj = Map::new();
                obj.insert("type".to_string(), Value::from("status"));
                obj.insert("message".to_string(), Value::from("parse_error"));
                obj.insert("error".to_string(), Value::from(err.to_string()));
                self.emit(out, obj, "ambient", None)?;
                return Ok(true);
            }
        };

        match control {
            Control::Scope { pgid, generation } => {
                let mut obj = Map::new();
                obj.insert("type".to_string(), Value::from("status"));
                obj.insert("message".to_string(), Value::from("scope"));
                obj.insert("pgid".to_string(), Value::from(pgid));
                obj.insert("generation".to_string(), Value::from(generation));
                self.emit(out, obj, "ambient", None)?;
                self.fire(out, "scope", None, "ambient", None)?;
            }
            Control::Mark {
                phase,
                call_id,
                tool,
            } => match phase.as_str() {
                "begin" => {
                    self.active_call = call_id.clone();
                    self.active_tool = tool.clone();
                    let cid = call_id.as_deref();
                    self.emit_status(out, "call", cid, "begin")?;
                    self.fire(out, "begin", tool.as_deref(), "call", cid)?;
                }
                "end" => {
                    let cid = call_id.clone().or_else(|| self.active_call.clone());
                    // End marks carry only the call_id, so fall back to the tool
                    // remembered from the matching begin mark for tool filtering.
                    let tool = tool.or_else(|| self.active_tool.clone());
                    // Trailing grace window: end-triggered events are still
                    // attributed to the call that just ended.
                    self.fire(out, "end", tool.as_deref(), "call", cid.as_deref())?;
                    self.emit_status(out, "call", cid.as_deref(), "end")?;
                    self.active_call = None;
                    self.active_tool = None;
                }
                other => {
                    let mut obj = Map::new();
                    obj.insert("type".to_string(), Value::from("status"));
                    obj.insert("message".to_string(), Value::from("unknown_phase"));
                    obj.insert("phase".to_string(), Value::from(other));
                    self.emit(out, obj, "ambient", None)?;
                }
            },
            Control::Shutdown => return Ok(false),
        }
        Ok(true)
    }
}

/// Drive the fake backend over a reader/writer pair. Reused by `main` and tests.
pub fn run<R: BufRead, W: Write>(
    mut backend: FakeBackend,
    reader: R,
    out: &mut W,
) -> std::io::Result<()> {
    backend.on_start(out)?;
    for line in reader.lines() {
        let line = line?;
        if !backend.handle_line(&line, out)? {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(script: &str, input: &str) -> Vec<Value> {
        let entries = parse_script(script).expect("script parses");
        let mut counter = 0u128;
        let backend = FakeBackend::new(entries, 50).with_clock(Box::new(move || {
            counter += 1;
            counter
        }));
        let mut out: Vec<u8> = Vec::new();
        run(backend, input.as_bytes(), &mut out).expect("run ok");
        String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn parses_both_script_shapes() {
        assert_eq!(parse_script("[]").unwrap().len(), 0);
        assert_eq!(parse_script(r#"{"events":[]}"#).unwrap().len(), 0);
        let bare = r#"[{"trigger":"scope","event":{"type":"connect","dst":"1.2.3.4:53"}}]"#;
        assert_eq!(parse_script(bare).unwrap().len(), 1);
    }

    #[test]
    fn attributes_begin_events_to_active_call() {
        let script = r#"[
            {"trigger":"begin","tool":"get_weather","event":{"type":"exec","argv":["/bin/sh","-c","curl x"]}}
        ]"#;
        let input = concat!(
            "{\"op\":\"mark\",\"phase\":\"begin\",\"call_id\":\"c1\",\"tool\":\"get_weather\"}\n",
            "{\"op\":\"mark\",\"phase\":\"end\",\"call_id\":\"c1\"}\n",
            "{\"op\":\"shutdown\"}\n",
        );
        let out = drive(script, input);
        let exec = out
            .iter()
            .find(|e| e["type"] == "exec")
            .expect("exec emitted");
        assert_eq!(exec["bucket"], "call");
        assert_eq!(exec["call_id"], "c1");
        assert_eq!(exec["argv"][0], "/bin/sh");
    }

    #[test]
    fn tool_filter_excludes_other_tools() {
        let script = r#"[
            {"trigger":"begin","tool":"only_this","event":{"type":"exec","argv":["/bin/sh"]}}
        ]"#;
        let input = concat!(
            "{\"op\":\"mark\",\"phase\":\"begin\",\"call_id\":\"c1\",\"tool\":\"other\"}\n",
            "{\"op\":\"shutdown\"}\n",
        );
        let out = drive(script, input);
        assert!(out.iter().all(|e| e["type"] != "exec"));
    }

    #[test]
    fn startup_and_scope_events_land_in_right_buckets() {
        let script = r#"[
            {"trigger":"startup","event":{"type":"exec","argv":["/init"]}},
            {"trigger":"scope","event":{"type":"connect","dst":"10.0.0.1:53"}}
        ]"#;
        let input = concat!(
            "{\"op\":\"scope\",\"pgid\":42,\"generation\":1}\n",
            "{\"op\":\"shutdown\"}\n",
        );
        let out = drive(script, input);
        let exec = out.iter().find(|e| e["type"] == "exec").unwrap();
        assert_eq!(exec["bucket"], "startup");
        assert!(exec.get("call_id").is_none());
        let connect = out.iter().find(|e| e["type"] == "connect").unwrap();
        assert_eq!(connect["bucket"], "ambient");
    }

    #[test]
    fn end_events_keep_call_id_as_grace_window() {
        let script = r#"[
            {"trigger":"end","event":{"type":"connect","dst":"203.0.113.7:443"}}
        ]"#;
        let input = concat!(
            "{\"op\":\"mark\",\"phase\":\"begin\",\"call_id\":\"c9\",\"tool\":\"t\"}\n",
            "{\"op\":\"mark\",\"phase\":\"end\",\"call_id\":\"c9\"}\n",
            "{\"op\":\"shutdown\"}\n",
        );
        let out = drive(script, input);
        let connect = out.iter().find(|e| e["type"] == "connect").unwrap();
        assert_eq!(connect["call_id"], "c9");
        assert_eq!(connect["bucket"], "call");
    }

    #[test]
    fn malformed_control_line_reports_parse_error() {
        let out = drive("[]", "not json\n{\"op\":\"shutdown\"}\n");
        assert!(out
            .iter()
            .any(|e| e["type"] == "status" && e["message"] == "parse_error"));
    }
}
