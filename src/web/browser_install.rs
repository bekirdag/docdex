use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;

const INSTALL_LOCK_NAME: &str = "browser_install.lock";
const DEFAULT_BROWSERS: &str = "chromium";
const ALLOWED_BROWSERS: [&str; 3] = ["chromium", "firefox", "webkit"];
const INSTALLER_ENV: &str = "DOCDEX_PLAYWRIGHT_INSTALLER";

#[derive(Debug, Clone)]
pub struct BrowserInstallResult {
    pub path: PathBuf,
    pub version: String,
}

pub fn resolve_installed_browser() -> Option<PathBuf> {
    crate::util::resolve_playwright_chromium().map(|browser| browser.path)
}

pub fn install_if_missing(auto_install: bool) -> Result<Option<BrowserInstallResult>> {
    let auto_install = env_boolish("DOCDEX_BROWSER_AUTO_INSTALL").unwrap_or(auto_install);
    if !auto_install {
        return Ok(None);
    }
    if let Some(existing) = crate::util::resolve_playwright_chromium() {
        return Ok(Some(to_install_result(existing)));
    }

    let base_dir =
        crate::state_paths::default_state_base_dir().context("resolve docdex state dir")?;
    let install_dir = resolve_playwright_install_dir(&base_dir)?;
    fs::create_dir_all(&install_dir)
        .with_context(|| format!("create playwright install dir {}", install_dir.display()))?;
    let selected = normalize_browser_list(&[], &[DEFAULT_BROWSERS])?;

    let lock_dir = base_dir.join("locks");
    fs::create_dir_all(&lock_dir)
        .with_context(|| format!("create browser lock dir {}", lock_dir.display()))?;
    let lock_path = lock_dir.join(INSTALL_LOCK_NAME);
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open install lock {}", lock_path.display()))?;
    lock_file
        .lock_exclusive()
        .with_context(|| "browser install lock busy")?;

    if let Some(existing) = crate::util::resolve_playwright_chromium() {
        lock_file.unlock().ok();
        return Ok(Some(to_install_result(existing)));
    }

    let install_result = run_playwright_install(&install_dir, &selected);
    lock_file.unlock().ok();
    install_result?;

    let installed = crate::util::resolve_playwright_chromium().ok_or_else(|| {
        anyhow!("playwright install completed but chromium entry missing from manifest")
    })?;
    Ok(Some(to_install_result(installed)))
}

pub fn install_playwright_browsers(browsers: &[String]) -> Result<Option<BrowserInstallResult>> {
    let selected = normalize_browser_list(browsers, &[])?;
    if selected.is_empty() {
        return Ok(None);
    }

    let base_dir =
        crate::state_paths::default_state_base_dir().context("resolve docdex state dir")?;
    let install_dir = resolve_playwright_install_dir(&base_dir)?;
    fs::create_dir_all(&install_dir)
        .with_context(|| format!("create playwright install dir {}", install_dir.display()))?;

    let lock_dir = base_dir.join("locks");
    fs::create_dir_all(&lock_dir)
        .with_context(|| format!("create browser lock dir {}", lock_dir.display()))?;
    let lock_path = lock_dir.join(INSTALL_LOCK_NAME);
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("open install lock {}", lock_path.display()))?;
    lock_file
        .lock_exclusive()
        .with_context(|| "browser install lock busy")?;

    let install_result = run_playwright_install(&install_dir, &selected);
    lock_file.unlock().ok();
    install_result?;

    if selected.iter().any(|name| name == "chromium") {
        let installed = crate::util::resolve_playwright_chromium().ok_or_else(|| {
            anyhow!("playwright install completed but chromium entry missing from manifest")
        })?;
        return Ok(Some(to_install_result(installed)));
    }
    Ok(None)
}

fn to_install_result(browser: crate::util::PlaywrightBrowser) -> BrowserInstallResult {
    BrowserInstallResult {
        path: browser.path,
        version: browser
            .version
            .unwrap_or_else(|| "installed".to_string()),
    }
}

fn resolve_playwright_install_dir(base_dir: &Path) -> Result<PathBuf> {
    if let Ok(path) = std::env::var("PLAYWRIGHT_BROWSERS_PATH") {
        let trimmed = path.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    Ok(base_dir.join("bin").join("playwright"))
}

fn run_playwright_install(install_dir: &Path, browsers: &[String]) -> Result<()> {
    let browser_list = if browsers.is_empty() {
        DEFAULT_BROWSERS.to_string()
    } else {
        browsers.join(",")
    };
    let installer = resolve_playwright_installer_path()?;
    let status = Command::new("node")
        .arg(installer.as_os_str())
        .arg("--browsers")
        .arg(browser_list)
        .arg("--path")
        .arg(install_dir)
        .env("PLAYWRIGHT_BROWSERS_PATH", install_dir)
        .env("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "0")
        .status()
        .with_context(|| format!("spawn playwright installer {}", installer.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("playwright installer failed with status {status}"))
    }
}

fn normalize_browser_list(browsers: &[String], defaults: &[&str]) -> Result<Vec<String>> {
    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    let mut raw = Vec::new();

    if browsers.is_empty() {
        raw.extend(defaults.iter().map(|value| value.to_string()));
    } else {
        raw.extend(browsers.iter().cloned());
    }

    for value in raw {
        for part in value.split(',') {
            let trimmed = part.trim().to_ascii_lowercase();
            if trimmed.is_empty() {
                continue;
            }
            if !ALLOWED_BROWSERS.contains(&trimmed.as_str()) {
                return Err(anyhow!("unsupported browser: {trimmed}"));
            }
            if seen.insert(trimmed.clone()) {
                selected.push(trimmed);
            }
        }
    }

    Ok(selected)
}

fn resolve_playwright_installer_path() -> Result<PathBuf> {
    if let Ok(value) = std::env::var(INSTALLER_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.is_file() {
                return Ok(path);
            }
            return Err(anyhow!(
                "Playwright installer not found at {}; set DOCDEX_PLAYWRIGHT_INSTALLER to npm/lib/playwright_install.js",
                path.display()
            ));
        }
    }

    let exe = std::env::current_exe().context("resolve current exe")?;
    let mut cursor = exe
        .parent()
        .ok_or_else(|| anyhow!("resolve current exe directory"))?
        .to_path_buf();

    for _ in 0..8 {
        let candidate = cursor.join("lib").join("playwright_install.js");
        if candidate.is_file() {
            return Ok(candidate);
        }
        let candidate = cursor.join("npm").join("lib").join("playwright_install.js");
        if candidate.is_file() {
            return Ok(candidate);
        }
        if !cursor.pop() {
            break;
        }
    }

    Err(anyhow!(
        "Playwright installer script not found; set DOCDEX_PLAYWRIGHT_INSTALLER to npm/lib/playwright_install.js"
    ))
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
