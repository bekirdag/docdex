use anyhow::Result;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::{fmt, EnvFilter};
use which::which;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserKind {
    Chrome,
    Chromium,
    Firefox,
    Webkit,
    Edge,
    Brave,
    Vivaldi,
    Custom,
}

impl BrowserKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            BrowserKind::Chrome => "chrome",
            BrowserKind::Chromium => "chromium",
            BrowserKind::Firefox => "firefox",
            BrowserKind::Webkit => "webkit",
            BrowserKind::Edge => "edge",
            BrowserKind::Brave => "brave",
            BrowserKind::Vivaldi => "vivaldi",
            BrowserKind::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserSource {
    Env,
    Config,
    Playwright,
    Which,
    KnownPath,
    AutoInstall,
}

impl BrowserSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            BrowserSource::Env => "env",
            BrowserSource::Config => "config",
            BrowserSource::Playwright => "playwright",
            BrowserSource::Which => "which",
            BrowserSource::KnownPath => "known_path",
            BrowserSource::AutoInstall => "auto_install",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BrowserCandidate {
    pub kind: BrowserKind,
    pub name: String,
    pub path: PathBuf,
    pub source: BrowserSource,
    pub priority: u32,
}

impl BrowserCandidate {
    fn new(
        kind: BrowserKind,
        name: impl Into<String>,
        path: PathBuf,
        source: BrowserSource,
        priority: u32,
    ) -> Self {
        Self {
            kind,
            name: name.into(),
            path,
            source,
            priority,
        }
    }
}

pub fn init_logging(level: &str) -> Result<()> {
    let level = if env_boolish("DOCDEX_WEB_DEBUG").unwrap_or(false)
        || env_boolish("DOCDEX_LLM_DEBUG").unwrap_or(false)
    {
        "debug"
    } else {
        level
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("{level},html5ever=error")));
    // Write logs to stderr to avoid interfering with stdout protocols (e.g., MCP stdio).
    if let Some(path) = resolve_state_log_path() {
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                let file = Arc::new(Mutex::new(file));
                let make_writer = move || StateLogWriter {
                    file: Arc::clone(&file),
                    stderr: io::stderr(),
                };
                let _ = fmt()
                    .with_env_filter(filter)
                    .with_writer(make_writer)
                    .try_init();
                return Ok(());
            }
            Err(err) => {
                eprintln!("docdexd: failed to open log file {}: {err}", path.display());
            }
        }
    }
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init();
    Ok(())
}

pub fn detect_browser_binary(config_path: Option<&Path>) -> Option<BrowserCandidate> {
    let mut candidates = detect_browser_candidates(config_path);
    candidates.sort_by_key(|candidate| candidate.priority);
    candidates.into_iter().next()
}

pub fn detect_browser_candidates(config_path: Option<&Path>) -> Vec<BrowserCandidate> {
    fn push_candidate(
        candidates: &mut Vec<BrowserCandidate>,
        priority: &mut u32,
        kind: BrowserKind,
        name: &str,
        path: PathBuf,
        source: BrowserSource,
    ) -> bool {
        if path.is_file() {
            candidates.push(BrowserCandidate::new(kind, name, path, source, *priority));
            *priority = priority.saturating_add(1);
            return true;
        }
        false
    }

    fn push_resolved(
        candidates: &mut Vec<BrowserCandidate>,
        priority: &mut u32,
        kind: BrowserKind,
        name: &str,
        raw: &Path,
        source: BrowserSource,
    ) {
        if push_candidate(candidates, priority, kind, name, raw.to_path_buf(), source) {
            return;
        }
        if let Ok(resolved) = which(raw) {
            let _ = push_candidate(candidates, priority, kind, name, resolved, source);
        }
    }

    let mut candidates: Vec<BrowserCandidate> = Vec::new();
    let mut priority = 0u32;

    if let Some(path) = env_path("DOCDEX_WEB_BROWSER") {
        push_resolved(
            &mut candidates,
            &mut priority,
            BrowserKind::Custom,
            "DOCDEX_WEB_BROWSER",
            &path,
            BrowserSource::Env,
        );
    }

    if let Some(path) = env_path("DOCDEX_CHROME_PATH").or_else(|| env_path("CHROME_PATH")) {
        push_resolved(
            &mut candidates,
            &mut priority,
            BrowserKind::Chrome,
            "CHROME_PATH",
            &path,
            BrowserSource::Env,
        );
    }

    if let Some(path) = config_path {
        let _ = push_candidate(
            &mut candidates,
            &mut priority,
            BrowserKind::Custom,
            "config",
            path.to_path_buf(),
            BrowserSource::Config,
        );
    }

    if let Some(path) = resolve_playwright_chromium_path() {
        let _ = push_candidate(
            &mut candidates,
            &mut priority,
            BrowserKind::Chromium,
            "Playwright Chromium",
            path,
            BrowserSource::Playwright,
        );
    }

    let commands = [
        (BrowserKind::Chrome, "google-chrome"),
        (BrowserKind::Chrome, "google-chrome-stable"),
        (BrowserKind::Chromium, "chromium"),
        (BrowserKind::Chromium, "chromium-browser"),
        (BrowserKind::Chrome, "chrome"),
        (BrowserKind::Edge, "msedge"),
        (BrowserKind::Brave, "brave-browser"),
        (BrowserKind::Vivaldi, "vivaldi"),
    ];
    for (kind, cmd) in commands {
        if let Ok(path) = which(cmd) {
            let _ = push_candidate(
                &mut candidates,
                &mut priority,
                kind,
                cmd,
                path,
                BrowserSource::Which,
            );
        }
    }

    if cfg!(target_os = "macos") {
        let candidates_os = [
            (
                BrowserKind::Chrome,
                "Google Chrome",
                "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ),
            (
                BrowserKind::Chrome,
                "Google Chrome Beta",
                "/Applications/Google Chrome Beta.app/Contents/MacOS/Google Chrome Beta",
            ),
            (
                BrowserKind::Chrome,
                "Google Chrome Canary",
                "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
            ),
            (
                BrowserKind::Chromium,
                "Chromium",
                "/Applications/Chromium.app/Contents/MacOS/Chromium",
            ),
            (
                BrowserKind::Edge,
                "Microsoft Edge",
                "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            ),
            (
                BrowserKind::Edge,
                "Microsoft Edge Beta",
                "/Applications/Microsoft Edge Beta.app/Contents/MacOS/Microsoft Edge Beta",
            ),
            (
                BrowserKind::Edge,
                "Microsoft Edge Dev",
                "/Applications/Microsoft Edge Dev.app/Contents/MacOS/Microsoft Edge Dev",
            ),
            (
                BrowserKind::Edge,
                "Microsoft Edge Canary",
                "/Applications/Microsoft Edge Canary.app/Contents/MacOS/Microsoft Edge Canary",
            ),
            (
                BrowserKind::Brave,
                "Brave Browser",
                "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
            ),
            (
                BrowserKind::Brave,
                "Brave Browser Beta",
                "/Applications/Brave Browser Beta.app/Contents/MacOS/Brave Browser Beta",
            ),
            (
                BrowserKind::Brave,
                "Brave Browser Nightly",
                "/Applications/Brave Browser Nightly.app/Contents/MacOS/Brave Browser Nightly",
            ),
            (
                BrowserKind::Vivaldi,
                "Vivaldi",
                "/Applications/Vivaldi.app/Contents/MacOS/Vivaldi",
            ),
        ];
        for (kind, name, candidate) in candidates_os {
            let path = Path::new(candidate);
            let _ = push_candidate(
                &mut candidates,
                &mut priority,
                kind,
                name,
                path.to_path_buf(),
                BrowserSource::KnownPath,
            );
        }
        return candidates;
    }

    if cfg!(target_os = "windows") {
        let suffixes = [
            (
                BrowserKind::Chrome,
                "Chrome",
                "Google\\Chrome\\Application\\chrome.exe",
            ),
            (
                BrowserKind::Chrome,
                "Chrome Beta",
                "Google\\Chrome Beta\\Application\\chrome.exe",
            ),
            (
                BrowserKind::Chrome,
                "Chrome Canary",
                "Google\\Chrome Canary\\Application\\chrome.exe",
            ),
            (
                BrowserKind::Chromium,
                "Chromium",
                "Chromium\\Application\\chrome.exe",
            ),
            (
                BrowserKind::Edge,
                "Edge",
                "Microsoft\\Edge\\Application\\msedge.exe",
            ),
            (
                BrowserKind::Edge,
                "Edge Beta",
                "Microsoft\\Edge Beta\\Application\\msedge.exe",
            ),
            (
                BrowserKind::Edge,
                "Edge Dev",
                "Microsoft\\Edge Dev\\Application\\msedge.exe",
            ),
            (
                BrowserKind::Edge,
                "Edge Canary",
                "Microsoft\\Edge SxS\\Application\\msedge.exe",
            ),
            (
                BrowserKind::Brave,
                "Brave",
                "BraveSoftware\\Brave-Browser\\Application\\brave.exe",
            ),
            (
                BrowserKind::Brave,
                "Brave Beta",
                "BraveSoftware\\Brave-Browser-Beta\\Application\\brave.exe",
            ),
            (
                BrowserKind::Brave,
                "Brave Nightly",
                "BraveSoftware\\Brave-Browser-Nightly\\Application\\brave.exe",
            ),
            (
                BrowserKind::Vivaldi,
                "Vivaldi",
                "Vivaldi\\Application\\vivaldi.exe",
            ),
        ];
        let mut bases = Vec::new();
        for key in ["PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"] {
            if let Some(base) = std::env::var_os(key) {
                bases.push(PathBuf::from(base));
            }
        }
        for base in bases {
            for (kind, name, suffix) in suffixes {
                let candidate = base.join(suffix);
                let _ = push_candidate(
                    &mut candidates,
                    &mut priority,
                    kind,
                    name,
                    candidate,
                    BrowserSource::KnownPath,
                );
            }
        }
        return candidates;
    }

    let candidates_linux = [
        (
            BrowserKind::Chrome,
            "Google Chrome",
            "/usr/bin/google-chrome",
        ),
        (
            BrowserKind::Chrome,
            "Google Chrome Stable",
            "/usr/bin/google-chrome-stable",
        ),
        (BrowserKind::Chromium, "Chromium", "/usr/bin/chromium"),
        (
            BrowserKind::Chromium,
            "Chromium Browser",
            "/usr/bin/chromium-browser",
        ),
        (
            BrowserKind::Chrome,
            "Google Chrome",
            "/opt/google/chrome/chrome",
        ),
        (BrowserKind::Chromium, "Chromium Snap", "/snap/bin/chromium"),
    ];
    for (kind, name, candidate) in candidates_linux {
        let path = Path::new(candidate);
        let _ = push_candidate(
            &mut candidates,
            &mut priority,
            kind,
            name,
            path.to_path_buf(),
            BrowserSource::KnownPath,
        );
    }
    candidates
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PlaywrightManifest {
    #[serde(default)]
    pub installed_at: Option<String>,
    #[serde(default)]
    pub browsers_path: Option<PathBuf>,
    #[serde(default)]
    pub playwright_version: Option<String>,
    pub browsers: Vec<PlaywrightBrowser>,
}

#[derive(Debug, Deserialize, Clone)]
pub(crate) struct PlaywrightBrowser {
    pub name: String,
    pub path: PathBuf,
    #[serde(default)]
    pub version: Option<String>,
}

pub(crate) fn resolve_playwright_chromium() -> Option<PlaywrightBrowser> {
    let manifest = read_playwright_manifest()?;
    for browser in manifest.browsers {
        if browser.name.eq_ignore_ascii_case("chromium") && browser.path.is_file() {
            return Some(browser);
        }
    }
    None
}

fn resolve_playwright_chromium_path() -> Option<PathBuf> {
    resolve_playwright_chromium().map(|browser| browser.path)
}

pub(crate) fn read_playwright_manifest() -> Option<PlaywrightManifest> {
    let manifest_path = resolve_playwright_manifest_path()?;
    let raw = std::fs::read_to_string(&manifest_path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub(crate) fn resolve_playwright_manifest_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PLAYWRIGHT_BROWSERS_PATH") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Some(PathBuf::from(trimmed).join("manifest.json"));
        }
    }
    let base_dir = crate::state_paths::default_state_base_dir().ok()?;
    Some(base_dir.join("bin").join("playwright").join("manifest.json"))
}

fn resolve_state_log_path() -> Option<PathBuf> {
    if !env_boolish("DOCDEX_LOG_TO_STATE").unwrap_or(false) {
        return None;
    }
    let base_dir = crate::state_paths::default_state_base_dir().ok()?;
    let logs_dir = base_dir.join("logs");
    if let Err(err) = crate::state_layout::ensure_state_dir_secure(&logs_dir) {
        eprintln!(
            "docdexd: failed to create logs dir {}: {err}",
            logs_dir.display()
        );
        return None;
    }
    Some(logs_dir.join(format!("docdexd-{}.log", std::process::id())))
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(PathBuf::from(trimmed))
}

struct StateLogWriter {
    file: Arc<Mutex<std::fs::File>>,
    stderr: io::Stderr,
}

impl Write for StateLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "state log file lock poisoned"))?;
        let _ = self.stderr.write_all(buf);
        file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self
            .file
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "state log file lock poisoned"))?;
        let _ = self.stderr.flush();
        file.flush()
    }
}
