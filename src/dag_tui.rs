use crate::dag::{DagDataSource, DagLoadResult, DagNode, DagStatus, NO_TRACE_MESSAGE};
use anyhow::{Context, Result};
use serde_json::Value;
use std::io::{self, Read, Write};

#[cfg(unix)]
use nix::sys::termios;
#[cfg(unix)]
use std::os::fd::AsRawFd;

const LIST_SUMMARY_WIDTH: usize = 72;
const DETAIL_WIDTH: usize = 96;

pub fn run_dag_tui(session_id: &str, dag: DagLoadResult) -> Result<()> {
    let mut app = App::from_dag(session_id, dag);
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
}

impl App {
    fn from_dag(session_id: &str, dag: DagLoadResult) -> Self {
        let count = dag.nodes.len();
        let source = dag.source.as_ref().map(source_label);
        let message = dag.message.clone().or_else(|| match dag.status {
            DagStatus::Missing => Some(NO_TRACE_MESSAGE.to_string()),
            DagStatus::Error => Some("Failed to load reasoning trace".to_string()),
            DagStatus::Found => None,
        });
        let status_line = dag
            .warnings
            .first()
            .cloned()
            .or_else(|| message.clone());
        Self {
            session_id: session_id.to_string(),
            nodes: dag.nodes,
            selected: 0,
            prompt_open: vec![false; count],
            status_line,
            dag_status: dag.status,
            source,
            message,
            warnings: dag.warnings,
        }
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
    }

    fn toggle_prompt(&mut self) {
        if let Some(flag) = self.prompt_open.get_mut(self.selected) {
            *flag = !*flag;
            self.status_line = Some(
                if *flag {
                    "Full prompt expanded"
                } else {
                    "Prompt collapsed"
                }
                .to_string(),
            );
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
