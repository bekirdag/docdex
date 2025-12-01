use crate::dag::{self, DagDataSource, DagLoadResult, DagNode, DagStatus, NO_TRACE_MESSAGE};
use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tracing::warn;

#[cfg(unix)]
use nix::sys::termios;
#[cfg(unix)]
use std::os::fd::AsRawFd;

const LIST_SUMMARY_WIDTH: usize = 72;
const DETAIL_WIDTH: usize = 96;
const DEFAULT_DAEMON_HOST: &str = "127.0.0.1";
const DEFAULT_DAEMON_PORT: u16 = 46137;
const DAEMON_PROBE_TIMEOUT_MS: u64 = 200;

#[derive(Clone)]
struct ReloadConfig {
    repo_root: PathBuf,
    session_id: String,
    global_state_dir: Option<PathBuf>,
}

#[derive(Clone, Debug)]
struct DaemonStatus {
    host: String,
    port: u16,
    unreachable: bool,
    last_error: Option<String>,
}

#[derive(Clone, Debug)]
struct RepoChoice {
    fingerprint: String,
    path: PathBuf,
}

impl RepoChoice {
    fn label(&self) -> String {
        format!("{} ({})", self.fingerprint, self.path.display())
    }
}

#[derive(Clone, Debug)]
struct RepoInventory {
    missing_repo: bool,
    state_root: Option<PathBuf>,
    available: Vec<RepoChoice>,
    reason: Option<String>,
    selection: Option<usize>,
    last_warning: Option<String>,
}

impl RepoInventory {
    fn new() -> Self {
        Self {
            missing_repo: false,
            state_root: None,
            available: Vec::new(),
            reason: None,
            selection: None,
            last_warning: None,
        }
    }

    fn refresh(&mut self, status: &DagStatus, repo_fingerprint: &str, state_root: Option<PathBuf>) {
        self.state_root = state_root.clone();
        self.available = state_root.as_ref().map(discover_repos).unwrap_or_default();
        self.missing_repo = false;
        self.reason = None;
        self.selection = None;
        if !matches!(status, DagStatus::Missing) {
            return;
        }
        match state_root {
            None => {
                self.missing_repo = true;
                self.reason = Some(
                    "Repo manager directory not found; index or attach a repo before retrying."
                        .to_string(),
                );
            }
            Some(root) => {
                let repos_dir = root.join("repos");
                if !repos_dir.exists() {
                    self.missing_repo = true;
                    self.reason = Some(format!(
                        "Repo manager path not found at {}.",
                        repos_dir.display()
                    ));
                    return;
                }
                let repo_dir = repos_dir.join(repo_fingerprint);
                if !repo_dir.exists() {
                    self.missing_repo = true;
                    let detail = if self.available.is_empty() {
                        format!(
                            "Fingerprint {} not found; no repos registered under {}.",
                            repo_fingerprint,
                            repos_dir.display()
                        )
                    } else {
                        format!(
                            "Fingerprint {} not found under {}.",
                            repo_fingerprint,
                            repos_dir.display()
                        )
                    };
                    self.reason = Some(detail);
                }
            }
        }
    }

    fn banner_lines(&self) -> Option<Vec<String>> {
        if !self.missing_repo {
            return None;
        }
        let mut lines = Vec::new();
        lines.push(
            "Repo is not attached. Index or pick a known repo before continuing.".to_string(),
        );
        if let Some(reason) = self.reason.as_ref() {
            lines.push(format!("Reason: {}", truncate(reason, DETAIL_WIDTH)));
        }
        if let Some(root) = self.state_root.as_ref() {
            lines.push(format!(
                "Repo manager: {}",
                truncate(&root.display().to_string(), DETAIL_WIDTH.saturating_sub(15))
            ));
        }
        if self.available.is_empty() {
            lines.push("Available repos: (none registered yet)".to_string());
        } else {
            lines.push(format!("Available repos ({}):", self.available.len()));
            for (idx, repo) in self.available.iter().enumerate() {
                if idx >= 5 {
                    lines.push(format!("  ... {} more", self.available.len() - idx));
                    break;
                }
                lines.push(format!(
                    "  [{}] {}",
                    idx + 1,
                    truncate(&repo.label(), DETAIL_WIDTH.saturating_sub(6))
                ));
            }
        }
        lines.push(
            "Actions: [s] Select repo • [r] Retry • [q] Quit (session preserved)".to_string(),
        );
        Some(lines)
    }

    fn select_next(&mut self) -> Option<&RepoChoice> {
        if self.available.is_empty() {
            self.selection = None;
            return None;
        }
        let next = match self.selection {
            Some(idx) if idx + 1 < self.available.len() => idx + 1,
            _ => 0,
        };
        self.selection = Some(next);
        self.available.get(next)
    }
}

pub fn run_dag_tui(
    session_id: &str,
    dag: DagLoadResult,
    global_state_dir: Option<PathBuf>,
) -> Result<()> {
    let telemetry = TelemetryRecorder::new(&dag.repo_root, session_id);
    let mut app = App::from_dag(session_id, dag, telemetry, global_state_dir);
    if app.daemon.unreachable {
        let reason = app
            .daemon
            .last_error
            .as_deref()
            .unwrap_or("daemon unreachable");
        eprintln!(
            "tui_daemon_unreachable repo={} session={} target={}:{} error={}",
            app.repo_root, app.session_id, app.daemon.host, app.daemon.port, reason
        );
    }
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
            Key::SelectRepo => app.select_repo(),
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
    SelectRepo,
    Quit,
    None,
}

fn parse_key(bytes: &[u8]) -> Key {
    match bytes {
        [b'q', ..] | [3] | [27, .., b'q'] => Key::Quit,
        [9, ..] => Key::Next,
        [13, ..] | [10, ..] => Key::TogglePrompt,
        [b'r', ..] | [b'R', ..] => Key::Retry,
        [b's', ..] | [b'S', ..] => Key::SelectRepo,
        [27, 91, 65, ..] | [27, 79, 65, ..] | [b'k', ..] => Key::Prev,
        [27, 91, 66, ..] | [27, 79, 66, ..] | [b'j', ..] => Key::Next,
        [27, 91, 67, ..] | [27, 79, 67, ..] | [b'l', ..] => Key::Next,
        [27, 91, 68, ..] | [27, 79, 68, ..] | [b'h', ..] => Key::Prev,
        _ => Key::None,
    }
}

struct App {
    session_id: String,
    repo_root: String,
    repo_fingerprint: String,
    nodes: Vec<DagNode>,
    selected: usize,
    prompt_open: Vec<bool>,
    status_line: Option<String>,
    dag_status: DagStatus,
    source: Option<String>,
    message: Option<String>,
    warnings: Vec<String>,
    telemetry: TelemetryRecorder,
    daemon: DaemonStatus,
    reload_config: Option<ReloadConfig>,
    repo_inventory: RepoInventory,
    repo_warning_logged: bool,
}

impl App {
    fn from_dag(
        session_id: &str,
        dag: DagLoadResult,
        telemetry: TelemetryRecorder,
        global_state_dir: Option<PathBuf>,
    ) -> Self {
        let daemon = DaemonStatus::from_status(&dag);
        let DagLoadResult {
            repo_root,
            repo_fingerprint,
            session_id: _,
            status,
            nodes,
            source,
            message,
            warnings,
        } = dag;
        let count = nodes.len();
        let message = message.clone().or_else(|| match status {
            DagStatus::Missing => Some(NO_TRACE_MESSAGE.to_string()),
            DagStatus::Error => Some("Failed to load reasoning trace".to_string()),
            DagStatus::Found => None,
        });
        let status_line = warnings.first().cloned().or_else(|| message.clone());
        let mut app = Self {
            session_id: session_id.to_string(),
            repo_root,
            nodes,
            selected: 0,
            prompt_open: vec![false; count],
            status_line,
            dag_status: status,
            source: source.map(source_label),
            message,
            warnings,
            telemetry,
            daemon,
            reload_config: Some(ReloadConfig::new(
                &repo_root,
                session_id,
                global_state_dir.clone(),
            )),
            repo_inventory: RepoInventory::new(),
            repo_warning_logged: false,
            repo_fingerprint,
        };
        app.refresh_repo_inventory();
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
        match self.daemon.check() {
            Ok(_) => {}
            Err(err) => {
                let guidance = format!(
                    "Docdex daemon is not reachable on {}:{}; start it and press r to retry.",
                    self.daemon.host, self.daemon.port
                );
                self.status_line = Some(truncate(&guidance, DETAIL_WIDTH));
                eprintln!(
                    "tui_daemon_unreachable repo={} session={} target={}:{} error={}",
                    self.repo_root, self.session_id, self.daemon.host, self.daemon.port, err
                );
                return;
            }
        }

        if let Some(config) = self.reload_config.clone() {
            match dag::load_session_dag(
                &config.repo_root,
                &config.session_id,
                config.global_state_dir.clone(),
            ) {
                Ok(new_dag) => {
                    let previous = self.selected;
                    self.apply_dag(new_dag);
                    if !self.nodes.is_empty() {
                        self.selected = previous.min(self.nodes.len().saturating_sub(1));
                    } else {
                        self.selected = 0;
                    }
                    self.status_line = Some(
                        "Retry succeeded; state preserved. Press r to refresh again or q to exit."
                            .to_string(),
                    );
                }
                Err(err) => {
                    let message = format!("Retry failed: {err}");
                    self.status_line = Some(truncate(&message, DETAIL_WIDTH));
                    eprintln!(
                        "tui_retry_failed repo={} session={} error={}",
                        self.repo_root, self.session_id, err
                    );
                }
            }
            return;
        }

        if let Some(node) = self.current_node() {
            if retry_available(&node.payload) {
                self.status_line = Some("Retry requested (no reload source available)".to_string());
            } else {
                self.status_line = Some("Retry disabled for this node".to_string());
            }
        } else {
            self.status_line = Some("Retry requested (no trace available)".to_string());
        }
    }

    fn select_repo(&mut self) {
        if !self.repo_inventory.missing_repo {
            self.status_line = Some("Repo already attached; no selection needed.".to_string());
            return;
        }
        if let Some(choice) = self.repo_inventory.select_next() {
            let idx = self.repo_inventory.selection.map(|i| i + 1).unwrap_or(1);
            let message = format!(
                "Selected repo [{}]: {} (attach or retry when ready)",
                idx,
                truncate(&choice.label(), DETAIL_WIDTH.saturating_sub(32))
            );
            self.status_line = Some(message);
            return;
        }
        self.status_line = Some(
            "No repos available; index or attach a repo, then retry (state preserved).".to_string(),
        );
    }

    fn refresh_repo_inventory(&mut self) {
        let override_root = self
            .reload_config
            .as_ref()
            .and_then(|cfg| cfg.global_state_dir.clone());
        let state_root = dag::resolve_state_root(override_root).ok();
        self.repo_inventory
            .refresh(&self.dag_status, &self.repo_fingerprint, state_root);
        if self.repo_inventory.missing_repo {
            self.log_repo_warning();
        } else {
            self.repo_warning_logged = false;
            self.repo_inventory.last_warning = None;
        }
    }

    fn log_repo_warning(&mut self) {
        if self.repo_warning_logged || !self.repo_inventory.missing_repo {
            return;
        }
        let state_root = self
            .repo_inventory
            .state_root
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unavailable".to_string());
        let available = if self.repo_inventory.available.is_empty() {
            "-".to_string()
        } else {
            self.repo_inventory
                .available
                .iter()
                .map(|r| r.fingerprint.as_str())
                .take(6)
                .collect::<Vec<_>>()
                .join(",")
        };
        let reason = self
            .repo_inventory
            .reason
            .as_deref()
            .unwrap_or_default()
            .replace('\n', " ");
        let warning = format!(
            "tui_repo_not_attached repo={} session={} state_root={} available_count={} available_repos={} reason={}",
            self.repo_root,
            self.session_id,
            state_root,
            self.repo_inventory.available.len(),
            available,
            reason
        );
        self.repo_inventory.last_warning = Some(warning.clone());
        eprintln!("{}", warning);
        self.repo_warning_logged = true;
    }

    fn render(&self, out: &mut impl Write) -> io::Result<()> {
        write!(out, "\x1b[2J\x1b[H")?;
        if let Some(lines) = self.repo_inventory.banner_lines() {
            for line in lines {
                writeln!(out, "{}", truncate(&line, DETAIL_WIDTH))?;
            }
            writeln!(out)?;
        }
        if let Some(lines) = self.daemon.banner_lines(&self.repo_root) {
            for line in lines {
                writeln!(out, "{}", truncate(&line, DETAIL_WIDTH))?;
            }
            writeln!(out)?;
        }
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
            "Keys: ↑/↓/←/→ or Tab to move • Enter toggles prompt • r retry • s select repo • q quit"
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

    fn apply_dag(&mut self, dag: DagLoadResult) {
        self.repo_root = dag.repo_root.clone();
        self.repo_fingerprint = dag.repo_fingerprint.clone();
        self.dag_status = dag.status;
        self.source = dag.source.as_ref().map(source_label);
        self.message = dag.message.clone().or_else(|| match dag.status {
            DagStatus::Missing => Some(NO_TRACE_MESSAGE.to_string()),
            DagStatus::Error => Some("Failed to load reasoning trace".to_string()),
            DagStatus::Found => None,
        });
        self.warnings = dag.warnings;
        self.nodes = dag.nodes;
        self.prompt_open = vec![false; self.nodes.len()];
        self.status_line = self
            .warnings
            .first()
            .cloned()
            .or_else(|| self.message.clone());
        self.daemon.refresh_from_status(&self.dag_status);
        if let Some(config) = self.reload_config.as_mut() {
            config.repo_root = PathBuf::from(&self.repo_root);
        }
        self.refresh_repo_inventory();
        self.telemetry.record_node_view(self.current_node());
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

impl ReloadConfig {
    fn new(repo_root: &str, session_id: &str, global_state_dir: Option<PathBuf>) -> Self {
        Self {
            repo_root: PathBuf::from(repo_root),
            session_id: session_id.to_string(),
            global_state_dir,
        }
    }
}

impl DaemonStatus {
    fn from_status(dag: &DagLoadResult) -> Self {
        let host =
            std::env::var("DOCDEX_TUI_HOST").unwrap_or_else(|_| DEFAULT_DAEMON_HOST.to_string());
        let port = std::env::var("DOCDEX_TUI_PORT")
            .ok()
            .and_then(|raw| raw.parse::<u16>().ok())
            .unwrap_or(DEFAULT_DAEMON_PORT);
        let mut status = Self {
            host,
            port,
            unreachable: matches!(dag.status, DagStatus::Missing | DagStatus::Error),
            last_error: None,
        };
        if status.unreachable && daemon_probe_enabled() {
            if let Err(err) = status.check() {
                status.last_error.get_or_insert(err);
            }
        }
        if status.unreachable && status.last_error.is_none() {
            status.last_error =
                Some("trace unavailable; start the docdex daemon and retry".to_string());
        }
        status
    }

    fn check(&mut self) -> Result<(), String> {
        if !daemon_probe_enabled() {
            return if self.unreachable {
                Err(self
                    .last_error
                    .clone()
                    .unwrap_or_else(|| "daemon probe disabled; last state unreachable".into()))
            } else {
                Ok(())
            };
        }
        match probe_daemon(&self.host, self.port) {
            Ok(_) => {
                self.unreachable = false;
                self.last_error = None;
                Ok(())
            }
            Err(err) => {
                self.unreachable = true;
                self.last_error = Some(err.clone());
                Err(err)
            }
        }
    }

    fn refresh_from_status(&mut self, status: &DagStatus) {
        if matches!(status, DagStatus::Found) {
            self.unreachable = false;
            self.last_error = None;
        }
    }

    fn banner_lines(&self, repo_root: &str) -> Option<Vec<String>> {
        if !self.unreachable {
            return None;
        }
        let target = format!("{}:{}", self.host, self.port);
        let mut lines = Vec::new();
        lines.push(format!(
            "Docdex daemon is not reachable on {target}. Start it locally and retry."
        ));
        if let Some(err) = self.last_error.as_ref() {
            lines.push(format!("Reason: {}", truncate(err, DETAIL_WIDTH)));
        }
        let repo_hint = truncate(repo_root, DETAIL_WIDTH.saturating_sub(12));
        lines.push(format!(
            "Start hint: docdexd serve --repo {} --host {} --port {} --log warn",
            repo_hint, self.host, self.port
        ));
        lines.push(format!("Health: docdexd check --repo {}", repo_hint));
        lines.push(
            "Actions: [r] Retry • [q] Quit (loopback expected; add --auth-token when exposed)"
                .to_string(),
        );
        Some(lines)
    }
}

fn daemon_probe_enabled() -> bool {
    std::env::var("DOCDEX_TUI_DISABLE_PROBE")
        .map(|value| {
            let normalized = value.to_lowercase();
            !(normalized == "1" || normalized == "true" || normalized == "yes")
        })
        .unwrap_or(true)
}

fn probe_daemon(host: &str, port: u16) -> Result<(), String> {
    let target = format!("{host}:{port}");
    let addr = target
        .to_socket_addrs()
        .map_err(|err| format!("resolve {target}: {err}"))?
        .next()
        .ok_or_else(|| format!("resolve {target}: no addresses"))?;
    TcpStream::connect_timeout(&addr, Duration::from_millis(DAEMON_PROBE_TIMEOUT_MS))
        .map_err(|err| format!("connect {target}: {err}"))?;
    Ok(())
}

fn discover_repos(state_root: &Path) -> Vec<RepoChoice> {
    let repos_dir = state_root.join("repos");
    let Ok(entries) = fs::read_dir(&repos_dir) else {
        return Vec::new();
    };
    let mut repos = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        if let Some(name) = path.file_name().and_then(|v| v.to_str()) {
            repos.push(RepoChoice {
                fingerprint: name.to_string(),
                path: path.clone(),
            });
        }
    }
    repos.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    repos
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
    use std::env;
    use std::fs;
    use std::net::TcpListener;
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
        let mut app = App::from_dag("session-1", dag, telemetry, None);

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
        let mut app = App::from_dag("session-nav", dag, telemetry, None);

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
        let mut app = App::from_dag("session-empty", dag, telemetry, None);

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
        let mut app = App::from_dag("session-telemetry", dag, telemetry, None);

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

    #[test]
    fn daemon_unreachable_banner_shows_with_instructions() {
        env::set_var("DOCDEX_TUI_DISABLE_PROBE", "1");
        let temp = TempDir::new().unwrap();
        let dag = DagLoadResult {
            repo_root: temp.path().display().to_string(),
            repo_fingerprint: "fp".to_string(),
            session_id: "session-banner".to_string(),
            status: DagStatus::Missing,
            nodes: vec![],
            source: None,
            message: Some(NO_TRACE_MESSAGE.to_string()),
            warnings: vec![],
        };
        let telemetry = TelemetryRecorder::for_tests(&dag.repo_root, "session-banner");
        let mut app = App::from_dag("session-banner", dag, telemetry, None);

        let mut out = Vec::new();
        app.render(&mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(rendered.contains("Docdex daemon is not reachable"));
        assert!(rendered.contains("docdexd serve"));
        assert!(rendered.contains("[r] Retry"));
        env::remove_var("DOCDEX_TUI_DISABLE_PROBE");
    }

    #[test]
    fn missing_repo_banner_lists_available_repos() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo_missing");
        fs::create_dir_all(&repo_root).unwrap();
        let state_root = temp.path().join("state");
        let repos_dir = state_root.join("repos");
        fs::create_dir_all(repos_dir.join("fp-known")).unwrap();

        let dag = DagLoadResult {
            repo_root: repo_root.display().to_string(),
            repo_fingerprint: "fp-missing".to_string(),
            session_id: "session-missing".to_string(),
            status: DagStatus::Missing,
            nodes: vec![],
            source: None,
            message: Some(NO_TRACE_MESSAGE.to_string()),
            warnings: vec![],
        };
        let telemetry = TelemetryRecorder::for_tests(&dag.repo_root, "session-missing");
        let mut app = App::from_dag("session-missing", dag, telemetry, Some(state_root.clone()));

        let mut out = Vec::new();
        app.render(&mut out).unwrap();
        let rendered = String::from_utf8(out).unwrap();

        assert!(app.repo_inventory.missing_repo);
        assert!(rendered.contains("Repo is not attached"));
        assert!(rendered.contains("fp-known"));
        assert!(rendered.contains("Available repos"));
        let warning = app.repo_inventory.last_warning.clone().unwrap_or_default();
        assert!(warning.contains("tui_repo_not_attached"));
        assert!(warning.contains("available_count=1"));
    }

    #[test]
    fn select_repo_cycles_without_dropping_state() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo_missing");
        fs::create_dir_all(&repo_root).unwrap();
        let state_root = temp.path().join("state");
        let repos_dir = state_root.join("repos");
        fs::create_dir_all(repos_dir.join("fp-one")).unwrap();
        fs::create_dir_all(repos_dir.join("fp-two")).unwrap();

        let dag = DagLoadResult {
            repo_root: repo_root.display().to_string(),
            repo_fingerprint: "fp-missing".to_string(),
            session_id: "session-select".to_string(),
            status: DagStatus::Missing,
            nodes: vec![],
            source: None,
            message: Some(NO_TRACE_MESSAGE.to_string()),
            warnings: vec![],
        };
        let telemetry = TelemetryRecorder::for_tests(&dag.repo_root, "session-select");
        let mut app = App::from_dag("session-select", dag, telemetry, Some(state_root.clone()));

        let initial_selected = app.selected;
        app.select_repo();
        let first = app.status_line.clone().unwrap_or_default();
        assert!(first.contains("fp-one"));

        app.select_repo();
        let second = app.status_line.clone().unwrap_or_default();
        assert!(second.contains("fp-two"));
        assert_eq!(app.selected, initial_selected);
    }

    #[test]
    fn retry_reloads_trace_without_dropping_selection() {
        let temp = TempDir::new().unwrap();
        let repo_root = temp.path().join("repo");
        fs::create_dir_all(&repo_root).unwrap();
        let state_root = temp.path().join("state");
        let session = "session-retry";
        let initial = dag::load_session_dag(&repo_root, session, Some(state_root.clone())).unwrap();
        let fingerprint = initial.repo_fingerprint.clone();
        let repo_root_str = initial.repo_root.clone();
        let dag_dir = state_root.join("repos").join(fingerprint).join("dag");
        fs::create_dir_all(&dag_dir).unwrap();
        fs::write(
            dag_dir.join(format!("{session}.json")),
            r#"[ { "id": 1, "type": "tool", "payload": { "summary": "loaded" } }, { "id": 2, "type": "decision", "payload": { "summary": "more", "retryable": true } } ]"#,
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        env::set_var("DOCDEX_TUI_HOST", "127.0.0.1");
        env::set_var("DOCDEX_TUI_PORT", port.to_string());

        let telemetry = TelemetryRecorder::for_tests(&repo_root_str, session);
        let mut app = App::from_dag(session, initial, telemetry, Some(state_root.clone()));

        app.retry();

        assert_eq!(app.nodes.len(), 2);
        assert!(app
            .status_line
            .as_deref()
            .unwrap_or_default()
            .to_lowercase()
            .contains("retry"));
        assert!(app.selected < 2);
        assert!(app.daemon.banner_lines(&app.repo_root).is_none());

        env::remove_var("DOCDEX_TUI_HOST");
        env::remove_var("DOCDEX_TUI_PORT");
        drop(listener);
    }
}
