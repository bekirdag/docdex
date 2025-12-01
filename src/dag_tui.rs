use crate::dag::{DagDataSource, DagLoadResult, DagNode, DagStatus, NO_TRACE_MESSAGE};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use tracing::warn;

#[cfg(unix)]
use nix::sys::termios;
#[cfg(unix)]
use std::os::fd::AsRawFd;

const LIST_SUMMARY_WIDTH: usize = 72;
const DETAIL_WIDTH: usize = 96;

pub fn run_dag_tui(session_id: &str, dag: DagLoadResult) -> Result<()> {
    let telemetry = TelemetryRecorder::new(&dag.repo_root, session_id);
    let mut app = App::from_dag(session_id, dag, telemetry);
    let _raw = RawMode::new().context("enable raw terminal mode for DAG inspector")?;
    let mut stdout = io::stdout();
    app.render(&mut stdout)?;
    let mut stdin = io::stdin();
    let mut buffer = [0u8; 8];
    loop {
        let read = stdin.read(&mut buffer)?;
        if read == 0 {
            continue;
        }
        match parse_key(&buffer[..read]) {
            Key::Quit => break,
            Key::Next => app.next(),
            Key::Prev => app.prev(),
            Key::TogglePrompt => app.toggle_prompt(),
            Key::Retry => app.retry(),
            Key::None => {}
        }
        app.render(&mut stdout)?;
    }
    app.finish(&mut stdout)?;
    Ok(())
}

enum Key {
    Next,
    Prev,
    TogglePrompt,
    Retry,
    Quit,
    None,
}

fn parse_key(bytes: &[u8]) -> Key {
    match bytes {
        [b'q', ..] | [3] | [27, .., b'q'] => Key::Quit,
        [9, ..] => Key::Next,
        [13, ..] | [10, ..] => Key::TogglePrompt,
        [b'r', ..] | [b'R', ..] => Key::Retry,
        [27, 91, 65, ..] | [27, 79, 65, ..] | [b'k', ..] => Key::Prev,
        [27, 91, 66, ..] | [27, 79, 66, ..] | [b'j', ..] => Key::Next,
        [27, 91, 67, ..] | [27, 79, 67, ..] | [b'l', ..] => Key::Next,
        [27, 91, 68, ..] | [27, 79, 68, ..] | [b'h', ..] => Key::Prev,
        _ => Key::None,
    }
}

struct App {
    session_id: String,
    nodes: Vec<DagNode>,
    selected: usize,
    prompt_open: Vec<bool>,
    status_line: Option<String>,
    dag_status: DagStatus,
    source: Option<String>,
    message: Option<String>,
    warnings: Vec<String>,
    telemetry: TelemetryRecorder,
}

impl App {
    fn from_dag(session_id: &str, dag: DagLoadResult, telemetry: TelemetryRecorder) -> Self {
        let count = dag.nodes.len();
        let source = dag.source.as_ref().map(source_label);
        let message = dag.message.clone().or_else(|| match dag.status {
            DagStatus::Missing => Some(NO_TRACE_MESSAGE.to_string()),
            DagStatus::Error => Some("Failed to load reasoning trace".to_string()),
            DagStatus::Found => None,
        });
        let status_line = dag.warnings.first().cloned().or_else(|| message.clone());
        let mut app = Self {
            session_id: session_id.to_string(),
            nodes: dag.nodes,
            selected: 0,
            prompt_open: vec![false; count],
            status_line,
            dag_status: dag.status,
            source,
            message,
            warnings: dag.warnings,
            telemetry,
        };
        app.telemetry.record_node_view(app.current_node());
        app
    }

    fn current_node(&self) -> Option<&DagNode> {
        self.nodes.get(self.selected)
    }

    fn next(&mut self) {
        if self.nodes.is_empty() {
            return;
        }
        self.selected = (self.selected + 1) % self.nodes.len();
        self.status_line = None;
        self.telemetry.record_node_view(self.current_node());
    }

    fn prev(&mut self) {
        if self.nodes.is_empty() {
            return;
        }
        if self.selected == 0 {
            self.selected = self.nodes.len() - 1;
        } else {
            self.selected -= 1;
        }
        self.status_line = None;
        self.telemetry.record_node_view(self.current_node());
    }

    fn toggle_prompt(&mut self) {
        let expanded = if let Some(flag) = self.prompt_open.get_mut(self.selected) {
            *flag = !*flag;
            self.status_line = Some(
                if *flag {
                    "Full prompt expanded"
                } else {
                    "Prompt collapsed"
                }
                .to_string(),
            );
            Some(*flag)
        } else {
            None
        };
        if let Some(expanded) = expanded {
            self.telemetry
                .record_prompt_toggle(self.current_node(), expanded);
        }
    }

    fn retry(&mut self) {
        if let Some(node) = self.current_node() {
            if retry_available(&node.payload) {
                self.status_line = Some("Retry requested (disabled in viewer)".to_string());
            } else {
                self.status_line = Some("Retry disabled for this node".to_string());
            }
        }
    }

    fn render(&self, out: &mut impl Write) -> io::Result<()> {
        write!(out, "\x1b[2J\x1b[H")?;
        writeln!(out, "DAG inspector — session {}", self.session_id)?;
        let status_label = match self.dag_status {
            DagStatus::Found => "found",
            DagStatus::Missing => "missing",
            DagStatus::Error => "error",
        };
        let source_label = self.source.as_deref().unwrap_or("none");
        writeln!(out, "Status: {status_label} | Source: {source_label}")?;
        if let Some(msg) = self.message.as_ref() {
            if !msg.is_empty() {
                writeln!(out, "Message: {}", truncate(msg, DETAIL_WIDTH))?;
            }
        }
        for warning in &self.warnings {
            if !warning.is_empty() {
                writeln!(out, "Warning: {}", truncate(warning, DETAIL_WIDTH))?;
            }
        }
        writeln!(
            out,
            "Keys: ↑/↓/←/→ or Tab to move • Enter toggles prompt • r retry • q quit"
        )?;
        writeln!(out, "\nNodes:")?;
        if self.nodes.is_empty() {
            let reason = self.message.as_deref().unwrap_or(NO_TRACE_MESSAGE);
            if let Some(warning) = self.warnings.first() {
                writeln!(
                    out,
                    "  (no nodes to display — {}; {})",
                    truncate(reason, DETAIL_WIDTH),
                    truncate(warning, DETAIL_WIDTH)
                )?;
            } else {
                writeln!(
                    out,
                    "  (no nodes to display — {})",
                    truncate(reason, DETAIL_WIDTH)
                )?;
            }
        } else {
            for (idx, node) in self.nodes.iter().enumerate() {
                let marker = if idx == self.selected { '>' } else { ' ' };
                let summary = truncate(&summarize_payload(&node.payload), LIST_SUMMARY_WIDTH);
                writeln!(out, "{marker} [{}] {}", node.node_type, summary)?;
            }
        }
        writeln!(out, "\nDetails:")?;
        if let Some(node) = self.current_node() {
            self.render_details(out, node)?;
        } else {
            writeln!(out, "  Select a node to see request/response details.")?;
        }
        if let Some(status) = self.status_line.as_ref() {
            writeln!(out, "\nStatus: {}", truncate(status, DETAIL_WIDTH))?;
        }
        out.flush()
    }

    fn render_details(&self, out: &mut impl Write, node: &DagNode) -> io::Result<()> {
        writeln!(out, "  Node {} [{}]", node.id, node.node_type)?;
        let summary = summarize_payload(&node.payload);
        writeln!(out, "  Summary: {}", truncate(&summary, DETAIL_WIDTH))?;

        let request = request_summary(&node.payload);
        writeln!(out, "  Request: {}", truncate(&request, DETAIL_WIDTH))?;

        let response = response_summary(&node.payload);
        writeln!(out, "  Response: {}", truncate(&response, DETAIL_WIDTH))?;

        if let Some(err) = failure_message(&node.payload) {
            writeln!(out, "  Failure: {}", truncate(&err, DETAIL_WIDTH))?;
        }
        if let Some(code) = exit_code(&node.payload) {
            writeln!(out, "  Exit code: {}", code)?;
        }

        let prompt_open = self
            .prompt_open
            .get(self.selected)
            .copied()
            .unwrap_or(false);
        match prompt_text(&node.payload) {
            Some(full) if prompt_open => {
                writeln!(out, "  Prompt (expanded):")?;
                for line in wrap_text(&full, DETAIL_WIDTH).lines() {
                    writeln!(out, "    {}", line)?;
                }
            }
            Some(full) => {
                writeln!(out, "  Prompt: hidden (press Enter to expand)")?;
                writeln!(
                    out,
                    "  Prompt preview: {}",
                    truncate(&clean_text(&full), DETAIL_WIDTH)
                )?;
            }
            None => writeln!(out, "  Prompt: (not captured)")?,
        }

        let retry_state = if retry_available(&node.payload) {
            "enabled"
        } else {
            "disabled"
        };
        writeln!(out, "  Retry: {}", retry_state)?;
        Ok(())
    }

    fn finish(&self, out: &mut impl Write) -> io::Result<()> {
        write!(out, "\x1b[2J\x1b[H")?;
        writeln!(out, "Exited DAG inspector.")?;
        out.flush()
    }
}

#[cfg(unix)]
struct RawMode {
    fd: i32,
    original: termios::Termios,
}

#[cfg(unix)]
impl RawMode {
    fn new() -> Result<Self> {
        let fd = io::stdin().as_raw_fd();
        let original = termios::tcgetattr(fd).context("read terminal attributes")?;
        let mut raw = original.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(fd, termios::SetArg::TCSANOW, &raw)
            .context("enable raw mode for stdin")?;
        Ok(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = termios::tcsetattr(self.fd, termios::SetArg::TCSANOW, &self.original);
    }
}

#[cfg(not(unix))]
struct RawMode;

#[cfg(not(unix))]
impl RawMode {
    fn new() -> Result<Self> {
        Ok(Self)
    }
}

fn source_label(source: &DagDataSource) -> String {
    match source {
        DagDataSource::Sqlite => "sqlite",
        DagDataSource::JsonFile => "json",
    }
    .to_string()
}

fn summarize_payload(payload: &Value) -> String {
    let paths = [
        &["summary"][..],
        &["title"][..],
        &["message"][..],
        &["request", "summary"],
        &["response", "summary"],
    ];
    if let Some(text) = pick_string(payload, &paths) {
        return clean_text(&text);
    }
    truncate(&short_json(Some(payload)), LIST_SUMMARY_WIDTH)
}

fn request_summary(payload: &Value) -> String {
    let paths = [
        &["request", "summary"][..],
        &["request", "text"],
        &["request", "body", "summary"],
        &["request", "input"],
    ];
    pick_string(payload, &paths)
        .map(|s| clean_text(&s))
        .unwrap_or_else(|| short_json(payload.get("request")))
}

fn response_summary(payload: &Value) -> String {
    let paths = [
        &["response", "summary"][..],
        &["response", "text"],
        &["response", "body", "summary"],
        &["response", "output"],
    ];
    pick_string(payload, &paths)
        .map(|s| clean_text(&s))
        .unwrap_or_else(|| short_json(payload.get("response")))
}

fn failure_message(payload: &Value) -> Option<String> {
    let paths = [
        &["error", "message"][..],
        &["error"][..],
        &["failure"][..],
        &["stderr"][..],
        &["status", "message"],
    ];
    pick_string(payload, &paths).map(|s| clean_text(&s))
}

fn exit_code(payload: &Value) -> Option<String> {
    let paths = [
        &["exit_code"][..],
        &["status", "exit_code"],
        &["status_code"],
        &["response", "exit_code"],
    ];
    for path in paths {
        if let Some(val) = nested_value(payload, path) {
            if let Some(num) = val.as_i64() {
                return Some(num.to_string());
            }
            if let Some(text) = value_as_string(val) {
                return Some(clean_text(&text));
            }
        }
    }
    None
}

fn prompt_text(payload: &Value) -> Option<String> {
    let paths = [
        &["prompt"][..],
        &["request", "prompt"],
        &["input", "prompt"],
        &["message", "prompt"],
        &["request", "body", "prompt"],
    ];
    pick_string(payload, &paths).map(|s| s.trim().to_string())
}

fn retry_available(payload: &Value) -> bool {
    let bool_paths = [
        &["retryable"][..],
        &["can_retry"][..],
        &["retry", "available"],
        &["actions", "retry", "enabled"],
    ];
    for path in bool_paths {
        if let Some(val) = nested_value(payload, path) {
            if let Some(flag) = val.as_bool() {
                if flag {
                    return true;
                }
            } else if let Some(text) = value_as_string(val) {
                let lowered = text.to_lowercase();
                if lowered == "true" || lowered == "available" || lowered == "enabled" {
                    return true;
                }
            }
        }
    }
    false
}

fn pick_string(payload: &Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        if let Some(val) = nested_value(payload, path) {
            if let Some(text) = value_as_string(val) {
                if !text.trim().is_empty() {
                    return Some(text);
                }
            }
        }
    }
    None
}

fn nested_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Array(arr) if !arr.is_empty() => Some(format!("{} items", arr.len())),
        Value::Object(obj) if !obj.is_empty() => serde_json::to_string(value).ok(),
        _ => None,
    }
}

fn short_json(value: Option<&Value>) -> String {
    if let Some(v) = value {
        if let Some(text) = value_as_string(v) {
            return clean_text(&text);
        }
        if let Ok(raw) = serde_json::to_string(v) {
            return clean_text(&raw);
        }
    }
    String::new()
}

fn clean_text(text: &str) -> String {
    text.replace('\n', " ")
        .replace('\r', " ")
        .trim()
        .to_string()
}

fn truncate(text: &str, max: usize) -> String {
    let cleaned = clean_text(text);
    let mut result = String::new();
    for (idx, ch) in cleaned.chars().enumerate() {
        if idx >= max {
            result.push('…');
            break;
        }
        result.push(ch);
    }
    result
}

fn wrap_text(text: &str, width: usize) -> String {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in clean_text(text).split_whitespace() {
        if !line.is_empty() && line.len() + word.len() + 1 > width {
            lines.push(line);
            line = String::new();
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines.join("\n")
}

#[derive(Clone, Debug)]
struct TelemetryPhase {
    label: String,
    enabled: bool,
}

impl TelemetryPhase {
    fn detect() -> Self {
        let label = std::env::var("DOCDEX_PHASE").unwrap_or_else(|_| "ga".to_string());
        let disabled_env = std::env::var("DOCDEX_TUI_TELEMETRY_DISABLE")
            .map(|value| {
                let normalized = value.to_lowercase();
                !normalized.is_empty() && normalized != "0" && normalized != "false"
            })
            .unwrap_or(false);
        let normalized = label.to_lowercase();
        let phase_allows = !matches!(normalized.as_str(), "alpha" | "dev" | "disabled" | "off");
        Self {
            label,
            enabled: !disabled_env && phase_allows,
        }
    }
}

#[derive(Debug)]
struct TelemetryRecorder {
    writer: Option<BufWriter<File>>,
    session_id: String,
    repo_root: String,
    phase: TelemetryPhase,
}

#[derive(Serialize)]
struct TelemetryEvent {
    ts: String,
    action: String,
    session_id: String,
    repo_root: String,
    phase: String,
    node_id: Option<i64>,
    node_type: Option<String>,
    state: Option<String>,
}

impl TelemetryRecorder {
    fn new(repo_root: &str, session_id: &str) -> Self {
        let phase = TelemetryPhase::detect();
        if !phase.enabled {
            return Self {
                writer: None,
                session_id: session_id.to_string(),
                repo_root: repo_root.to_string(),
                phase,
            };
        }
        let path = telemetry_path(repo_root);
        let writer = open_telemetry_writer(&path).ok();
        if writer.is_none() {
            warn!(
                path = %path.display(),
                "failed to open DAG telemetry log; continuing without telemetry"
            );
        }
        Self {
            writer,
            session_id: session_id.to_string(),
            repo_root: repo_root.to_string(),
            phase,
        }
    }

    fn record_node_view(&mut self, node: Option<&DagNode>) {
        if !self.phase.enabled {
            return;
        }
        if let Some(node) = node {
            let event = TelemetryEvent {
                ts: Utc::now().to_rfc3339(),
                action: "node_expand".to_string(),
                session_id: self.session_id.clone(),
                repo_root: self.repo_root.clone(),
                phase: self.phase.label.clone(),
                node_id: Some(node.id),
                node_type: Some(node.node_type.clone()),
                state: Some("selected".to_string()),
            };
            self.write_event(event);
        }
    }

    fn record_prompt_toggle(&mut self, node: Option<&DagNode>, expanded: bool) {
        if !self.phase.enabled {
            return;
        }
        let event = TelemetryEvent {
            ts: Utc::now().to_rfc3339(),
            action: "prompt_toggle".to_string(),
            session_id: self.session_id.clone(),
            repo_root: self.repo_root.clone(),
            phase: self.phase.label.clone(),
            node_id: node.map(|n| n.id),
            node_type: node.map(|n| n.node_type.clone()),
            state: Some(if expanded { "expanded" } else { "collapsed" }.to_string()),
        };
        self.write_event(event);
    }

    fn write_event(&mut self, event: TelemetryEvent) {
        if let Some(writer) = self.writer.as_mut() {
            if let Ok(line) = serde_json::to_string(&event) {
                let _ = writer.write_all(line.as_bytes());
                let _ = writer.write_all(b"\n");
                let _ = writer.flush();
            }
        }
    }

    #[cfg(test)]
    fn for_tests(repo_root: &str, session_id: &str) -> Self {
        let path = telemetry_path(repo_root);
        let writer = open_telemetry_writer(&path).ok();
        Self {
            writer,
            session_id: session_id.to_string(),
            repo_root: repo_root.to_string(),
            phase: TelemetryPhase {
                label: "test".to_string(),
                enabled: true,
            },
        }
    }
}

fn telemetry_path(repo_root: &str) -> PathBuf {
    Path::new(repo_root)
        .join(".docdex")
        .join("logs")
        .join("dag_telemetry.log")
}

fn open_telemetry_writer(path: &Path) -> io::Result<BufWriter<File>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(BufWriter::new(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    fn dag_result(root: &TempDir, nodes: Vec<DagNode>, status: DagStatus) -> DagLoadResult {
        DagLoadResult {
            repo_root: root.path().display().to_string(),
            repo_fingerprint: "fp".to_string(),
            session_id: "session-1".to_string(),
            status,
            nodes,
            source: Some(DagDataSource::JsonFile),
            message: None,
            warnings: vec![],
        }
    }

    #[test]
    fn render_shows_nodes_and_prompt_preview() {
        let temp = TempDir::new().unwrap();
        let nodes = vec![DagNode {
            id: 1,
            node_type: "tool".to_string(),
            payload: json!({
                "summary": "call tool",
                "prompt": "show full content",
                "response": { "summary": "ok" }
            }),
            created_at: None,
        }];
        let dag = dag_result(&temp, nodes, DagStatus::Found);
        let telemetry = TelemetryRecorder::for_tests(&dag.repo_root, "session-1");
        let mut app = App::from_dag("session-1", dag, telemetry);

        let mut out = Vec::new();
        app.render(&mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(rendered.contains("DAG inspector"));
        assert!(rendered.contains("Prompt: hidden"));
        assert!(rendered.contains("Keys:"));
    }

    #[test]
    fn navigation_wraps_and_clears_status_line() {
        let temp = TempDir::new().unwrap();
        let nodes = vec![
            DagNode {
                id: 1,
                node_type: "tool".to_string(),
                payload: json!({ "summary": "step a" }),
                created_at: None,
            },
            DagNode {
                id: 2,
                node_type: "tool".to_string(),
                payload: json!({ "summary": "step b" }),
                created_at: None,
            },
        ];
        let dag = dag_result(&temp, nodes, DagStatus::Found);
        let telemetry = TelemetryRecorder::for_tests(&dag.repo_root, "session-nav");
        let mut app = App::from_dag("session-nav", dag, telemetry);

        app.status_line = Some("set".to_string());
        app.next();
        assert_eq!(app.selected, 1);
        assert!(app.status_line.is_none());
        app.next();
        assert_eq!(app.selected, 0);
        app.prev();
        assert_eq!(app.selected, 1);
    }

    #[test]
    fn render_handles_empty_state() {
        let temp = TempDir::new().unwrap();
        let dag = DagLoadResult {
            repo_root: temp.path().display().to_string(),
            repo_fingerprint: "fp".to_string(),
            session_id: "session-empty".to_string(),
            status: DagStatus::Missing,
            nodes: vec![],
            source: None,
            message: Some(NO_TRACE_MESSAGE.to_string()),
            warnings: vec!["Offline cache directory not found".to_string()],
        };
        let telemetry = TelemetryRecorder::for_tests(&dag.repo_root, "session-empty");
        let mut app = App::from_dag("session-empty", dag, telemetry);

        let mut out = Vec::new();
        app.render(&mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(rendered.contains("no nodes to display"));
        assert!(rendered.contains(NO_TRACE_MESSAGE));
    }

    #[test]
    fn telemetry_logs_without_prompt_content() {
        let temp = TempDir::new().unwrap();
        let nodes = vec![DagNode {
            id: 7,
            node_type: "tool".to_string(),
            payload: json!({
                "prompt": "secret prompt text",
                "response": { "summary": "ok" }
            }),
            created_at: None,
        }];
        let dag = dag_result(&temp, nodes, DagStatus::Found);
        let telemetry = TelemetryRecorder::for_tests(&dag.repo_root, "session-telemetry");
        let mut app = App::from_dag("session-telemetry", dag, telemetry);

        app.toggle_prompt();

        let log_path = temp
            .path()
            .join(".docdex")
            .join("logs")
            .join("dag_telemetry.log");
        let contents = fs::read_to_string(log_path).unwrap();
        assert!(contents.contains("\"action\":\"prompt_toggle\""));
        assert!(contents.contains("\"state\":\"expanded\""));
        assert!(!contents.contains("secret prompt text"));
    }
}
