use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use serde::Deserialize;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use which::which;

use crate::web::playwright_scripts;

const INSTALL_LOCK_NAME: &str = "browser_install.lock";
const DEFAULT_BROWSERS: &str = "chromium";
const ALLOWED_BROWSERS: [&str; 3] = ["chromium", "firefox", "webkit"];
const INSTALLER_ENV: &str = "DOCDEX_PLAYWRIGHT_INSTALLER";
const NODE_PATH_ENV: &str = "NODE_PATH";
const PLAYWRIGHT_NODE_PATH_ENV: &str = "DOCDEX_PLAYWRIGHT_NODE_PATH";
const NODE_BIN_ENV: &str = "DOCDEX_NODE_BIN";
const PLAYWRIGHT_NODE_BIN_ENV: &str = "DOCDEX_PLAYWRIGHT_NODE_BIN";
const PLAYWRIGHT_HOST_PLATFORM_OVERRIDE_ENV: &str = "PLAYWRIGHT_HOST_PLATFORM_OVERRIDE";
const NVM_DIR_ENV: &str = "NVM_DIR";
const PLAYWRIGHT_NODE_DIR_NAME: &str = "playwright-node";

#[derive(Debug, Clone)]
pub struct BrowserInstallResult {
    pub path: PathBuf,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct PlaywrightDependencyStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub node_path: Option<PathBuf>,
}

pub fn resolve_installed_browser() -> Option<PathBuf> {
    crate::util::resolve_playwright_chromium().map(|browser| browser.path)
}

pub fn playwright_dependency_status() -> PlaywrightDependencyStatus {
    let node_path = resolve_playwright_node_path();
    let version = node_path
        .as_ref()
        .and_then(|path| read_playwright_version(&path.join("playwright").join("package.json")));
    PlaywrightDependencyStatus {
        installed: node_path.is_some(),
        version,
        node_path,
    }
}

pub fn install_playwright_dependency() -> Result<PlaywrightDependencyStatus> {
    let status = playwright_dependency_status();
    if status.installed {
        return Ok(status);
    }
    let base_dir =
        crate::state_paths::default_state_base_dir().context("resolve docdex state dir")?;
    let install_root = resolve_playwright_dependency_root(&base_dir);
    fs::create_dir_all(&install_root).with_context(|| {
        format!(
            "create playwright dependency dir {}",
            install_root.display()
        )
    })?;

    let (cmd, args) = resolve_npm_command();
    let mut command = Command::new(cmd);
    command
        .args(args)
        .arg("install")
        .arg("--no-save")
        .arg("--ignore-scripts")
        .arg("--no-package-lock")
        .arg("--no-audit")
        .arg("--no-fund")
        .arg("playwright")
        .current_dir(&install_root)
        .env("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "1");
    let status = command.status().with_context(|| {
        format!(
            "spawn playwright dependency install in {}",
            install_root.display()
        )
    })?;
    if !status.success() {
        return Err(anyhow!(
            "playwright dependency install failed with status {status}"
        ));
    }

    let status = playwright_dependency_status();
    if !status.installed {
        return Err(anyhow!(
            "playwright dependency install completed but playwright was not found"
        ));
    }
    Ok(status)
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

    install_playwright_dependency()?;
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
    if !playwright_dependency_status().installed {
        return Err(anyhow!(
            "playwright dependency not installed; run `docdex setup` to install Playwright"
        ));
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
        version: browser.version.unwrap_or_else(|| "installed".to_string()),
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
    let node_path = resolve_playwright_node_path().ok_or_else(|| {
        anyhow!("playwright dependency not installed; run `docdex setup` to install Playwright")
    })?;
    let node_bin = resolve_node_binary()?;
    let installer = resolve_playwright_installer_path()?;
    let merged_node_path = merge_node_path(&node_path);
    let status = Command::new(&node_bin)
        .arg(installer.as_os_str())
        .arg("--browsers")
        .arg(browser_list)
        .arg("--path")
        .arg(install_dir)
        .env("PLAYWRIGHT_BROWSERS_PATH", install_dir)
        .env("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", "0")
        .env(NODE_PATH_ENV, merged_node_path)
        .envs(playwright_host_platform_override_env())
        .status()
        .with_context(|| {
            format!(
                "spawn playwright installer {} via {}",
                installer.display(),
                node_bin.display()
            )
        })?;
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

    playwright_scripts::ensure_playwright_installer_script().context(
        "Playwright installer script not found; set DOCDEX_PLAYWRIGHT_INSTALLER to npm/lib/playwright_install.js",
    )
}

fn resolve_playwright_node_path() -> Option<PathBuf> {
    if let Some(path) = resolve_node_path_env_override() {
        let candidate = if path.ends_with("node_modules") {
            path.clone()
        } else {
            path.join("node_modules")
        };
        if playwright_package_present(&candidate) {
            return Some(candidate);
        }
        if playwright_package_present(&path) {
            return Some(path);
        }
    }

    if let Ok(installer) = resolve_playwright_installer_path() {
        if let Some(parent) = installer.parent() {
            if let Some(node_path) = find_playwright_in_ancestors(parent, 6) {
                return Some(node_path);
            }
        }
    }

    let base_dir = crate::state_paths::default_state_base_dir().ok()?;
    let node_path = resolve_playwright_dependency_node_modules(&base_dir);
    if playwright_package_present(&node_path) {
        return Some(node_path);
    }
    None
}

fn resolve_playwright_dependency_root(base_dir: &Path) -> PathBuf {
    if let Some(path) = resolve_node_path_env_override() {
        if path.ends_with("node_modules") {
            if let Some(parent) = path.parent() {
                return parent.to_path_buf();
            }
        }
        return path;
    }
    base_dir.join("bin").join(PLAYWRIGHT_NODE_DIR_NAME)
}

fn resolve_playwright_dependency_node_modules(base_dir: &Path) -> PathBuf {
    if let Some(path) = resolve_node_path_env_override() {
        if path.ends_with("node_modules") {
            return path;
        }
        return path.join("node_modules");
    }
    resolve_playwright_dependency_root(base_dir).join("node_modules")
}

fn resolve_node_path_env_override() -> Option<PathBuf> {
    let raw = std::env::var(PLAYWRIGHT_NODE_PATH_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn find_playwright_in_ancestors(start: &Path, max_depth: usize) -> Option<PathBuf> {
    let mut cursor = Some(start);
    for _ in 0..=max_depth {
        if let Some(dir) = cursor {
            let candidate = dir.join("node_modules");
            if playwright_package_present(&candidate) {
                return Some(candidate);
            }
            cursor = dir.parent();
        } else {
            break;
        }
    }
    None
}

fn playwright_package_present(node_modules: &Path) -> bool {
    node_modules
        .join("playwright")
        .join("package.json")
        .is_file()
}

#[derive(Deserialize)]
struct PlaywrightPackageMeta {
    version: Option<String>,
}

fn read_playwright_version(path: &Path) -> Option<String> {
    let raw = std::fs::read_to_string(path).ok()?;
    let parsed: PlaywrightPackageMeta = serde_json::from_str(&raw).ok()?;
    parsed.version
}

fn resolve_npm_command() -> (OsString, Vec<OsString>) {
    if let Ok(execpath) = std::env::var("npm_execpath") {
        if !execpath.trim().is_empty() {
            return (OsString::from("node"), vec![OsString::from(execpath)]);
        }
    }
    let cmd = if cfg!(windows) { "npm.cmd" } else { "npm" };
    (OsString::from(cmd), Vec::new())
}

pub(crate) fn merge_node_path(node_path: &Path) -> OsString {
    let extra = node_path.to_string_lossy();
    match std::env::var_os(NODE_PATH_ENV) {
        Some(existing) if !existing.is_empty() => {
            let sep = if cfg!(windows) { ";" } else { ":" };
            let merged = format!("{extra}{sep}{}", existing.to_string_lossy());
            OsString::from(merged)
        }
        _ => OsString::from(extra.as_ref()),
    }
}

pub(crate) fn resolve_node_binary() -> Result<PathBuf> {
    if let Some(path) = node_bin_from_env(NODE_BIN_ENV)? {
        let _ = crate::util::update_playwright_manifest_node_bin(&path);
        return Ok(path);
    }
    if let Some(path) = node_bin_from_env(PLAYWRIGHT_NODE_BIN_ENV)? {
        let _ = crate::util::update_playwright_manifest_node_bin(&path);
        return Ok(path);
    }
    if let Some(path) = node_bin_from_manifest() {
        return Ok(path);
    }
    if let Ok(path) = which("node") {
        let _ = crate::util::update_playwright_manifest_node_bin(&path);
        return Ok(path);
    }
    if let Some(path) = resolve_node_from_nvm() {
        let _ = crate::util::update_playwright_manifest_node_bin(&path);
        return Ok(path);
    }
    if let Some(path) = resolve_node_from_common_paths() {
        let _ = crate::util::update_playwright_manifest_node_bin(&path);
        return Ok(path);
    }
    Err(anyhow!(
        "node binary not found; set DOCDEX_NODE_BIN or DOCDEX_PLAYWRIGHT_NODE_BIN, or add node to PATH"
    ))
}

pub(crate) fn backfill_playwright_node_bin_from_env() {
    if let Ok(Some(path)) = node_bin_from_env(PLAYWRIGHT_NODE_BIN_ENV) {
        let _ = crate::util::update_playwright_manifest_node_bin(&path);
        return;
    }
    if let Ok(Some(path)) = node_bin_from_env(NODE_BIN_ENV) {
        let _ = crate::util::update_playwright_manifest_node_bin(&path);
    }
}

fn node_bin_from_env(key: &str) -> Result<Option<PathBuf>> {
    if let Ok(value) = std::env::var(key) {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let path = PathBuf::from(trimmed);
        if path.is_file() {
            return Ok(Some(path));
        }
        return Err(anyhow!(
            "node binary not found at {}; set {} to a valid node path",
            path.display(),
            key
        ));
    }
    Ok(None)
}

fn node_bin_from_manifest() -> Option<PathBuf> {
    let manifest = crate::util::read_playwright_manifest()?;
    let node_bin = manifest.node_bin?;
    if node_bin.is_file() {
        Some(node_bin)
    } else {
        None
    }
}

pub(crate) fn playwright_host_platform_override_env() -> Option<(&'static str, String)> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    if std::env::var_os(PLAYWRIGHT_HOST_PLATFORM_OVERRIDE_ENV).is_some() {
        return None;
    }
    if std::env::consts::ARCH != "aarch64" {
        return None;
    }
    let darwin_major = resolve_darwin_major_version()?;
    let mac_version = if darwin_major < 18 {
        "mac10.13".to_string()
    } else if darwin_major == 18 {
        "mac10.14".to_string()
    } else if darwin_major == 19 {
        "mac10.15".to_string()
    } else {
        let computed = (darwin_major as i32) - 9;
        let capped = computed.min(15).max(10);
        format!("mac{capped}")
    };
    Some((
        PLAYWRIGHT_HOST_PLATFORM_OVERRIDE_ENV,
        format!("{mac_version}-arm64"),
    ))
}

fn resolve_darwin_major_version() -> Option<u64> {
    static CACHED: OnceLock<Option<u64>> = OnceLock::new();
    *CACHED.get_or_init(|| {
        let output = Command::new("uname").arg("-r").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let raw = String::from_utf8_lossy(&output.stdout);
        let major = raw
            .trim()
            .split('.')
            .next()?
            .trim()
            .parse::<u64>()
            .ok()?;
        Some(major)
    })
}

fn resolve_node_from_nvm() -> Option<PathBuf> {
    if cfg!(windows) {
        return None;
    }
    let base_dir = std::env::var_os(NVM_DIR_ENV)
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".nvm")))?;
    let versions_dir = base_dir.join("versions").join("node");
    if !versions_dir.is_dir() {
        return None;
    }
    if let Some(path) = resolve_node_from_nvm_default(&base_dir, &versions_dir) {
        return Some(path);
    }
    resolve_node_from_nvm_versions(&versions_dir)
}

fn resolve_node_from_nvm_default(base_dir: &Path, versions_dir: &Path) -> Option<PathBuf> {
    let default_alias_path = base_dir.join("alias").join("default");
    let default_alias = std::fs::read_to_string(default_alias_path).ok()?;
    let target = default_alias.trim();
    if target.is_empty() {
        return None;
    }
    if let Some(version) = normalize_nvm_version(target) {
        return node_path_for_version(versions_dir, &version);
    }
    if let Some(version) = resolve_nvm_alias(base_dir, target) {
        return node_path_for_version(versions_dir, &version);
    }
    None
}

fn resolve_nvm_alias(base_dir: &Path, alias: &str) -> Option<String> {
    let alias_path = base_dir.join("alias").join(alias);
    let alias_target = std::fs::read_to_string(alias_path).ok()?;
    normalize_nvm_version(alias_target.trim())
}

fn normalize_nvm_version(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.trim_start_matches('v');
    let mut chars = normalized.chars();
    if !chars.next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return None;
    }
    Some(format!("v{}", normalized))
}

fn resolve_node_from_nvm_versions(versions_dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(PathBuf, (u32, u32, u32))> = None;
    let entries = std::fs::read_dir(versions_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let version = parse_node_version(&name)?;
        let candidate = entry.path().join("bin").join(node_filename());
        if candidate.is_file() {
            let replace = match best {
                None => true,
                Some((_, best_version)) => version > best_version,
            };
            if replace {
                best = Some((candidate, version));
            }
        }
    }
    best.map(|(path, _)| path)
}

fn parse_node_version(name: &str) -> Option<(u32, u32, u32)> {
    let trimmed = name.trim().trim_start_matches('v');
    let mut parts = trimmed.split('.');
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    let patch = parts
        .next()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0);
    Some((major, minor, patch))
}

fn node_path_for_version(versions_dir: &Path, version: &str) -> Option<PathBuf> {
    let candidate = versions_dir.join(version).join("bin").join(node_filename());
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

fn resolve_node_from_common_paths() -> Option<PathBuf> {
    if cfg!(windows) {
        let mut candidates = Vec::new();
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            candidates.push(PathBuf::from(program_files).join("nodejs").join("node.exe"));
        }
        if let Some(program_files) = std::env::var_os("ProgramFiles(x86)") {
            candidates.push(PathBuf::from(program_files).join("nodejs").join("node.exe"));
        }
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            candidates.push(
                PathBuf::from(local_app_data)
                    .join("Programs")
                    .join("nodejs")
                    .join("node.exe"),
            );
        }
        for candidate in candidates {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        return None;
    }

    let candidates = [
        "/usr/bin/node",
        "/usr/local/bin/node",
        "/opt/homebrew/bin/node",
        "/opt/homebrew/opt/node/bin/node",
        "/snap/bin/node",
    ];
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn node_filename() -> &'static str {
    if cfg!(windows) {
        "node.exe"
    } else {
        "node"
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use std::ffi::OsString;
    use tempfile::TempDir;

    struct EnvGuard {
        saved: Vec<(&'static str, Option<OsString>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            Self { saved: Vec::new() }
        }

        fn set_var(&mut self, key: &'static str, value: Option<OsString>) {
            let existing = std::env::var_os(key);
            self.saved.push((key, existing));
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in self.saved.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn resolve_node_binary_prefers_env_override() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = TempDir::new()?;
        let node_path = temp.path().join("node");
        std::fs::write(&node_path, "node")?;
        let mut env = EnvGuard::new();
        env.set_var(NODE_BIN_ENV, Some(node_path.as_os_str().to_os_string()));
        env.set_var(PLAYWRIGHT_NODE_BIN_ENV, Option::<OsString>::None);
        env.set_var(NVM_DIR_ENV, Option::<OsString>::None);
        let resolved = resolve_node_binary()?;
        assert_eq!(resolved, node_path);
        Ok(())
    }

    #[test]
    fn resolve_node_binary_uses_nvm_default_when_missing_on_path() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = TempDir::new()?;
        let nvm_dir = temp.path().join(".nvm");
        let versions_dir = nvm_dir.join("versions").join("node");
        let v18 = versions_dir.join("v18.19.0").join("bin");
        let v20 = versions_dir.join("v20.10.0").join("bin");
        std::fs::create_dir_all(&v18)?;
        std::fs::create_dir_all(&v20)?;
        std::fs::write(v18.join("node"), "node")?;
        std::fs::write(v20.join("node"), "node")?;
        std::fs::create_dir_all(nvm_dir.join("alias"))?;
        std::fs::write(nvm_dir.join("alias").join("default"), "v20.10.0\n")?;
        let empty_path = temp.path().join("empty-path");
        std::fs::create_dir_all(&empty_path)?;

        let mut env = EnvGuard::new();
        env.set_var(NODE_BIN_ENV, Option::<OsString>::None);
        env.set_var(PLAYWRIGHT_NODE_BIN_ENV, Option::<OsString>::None);
        env.set_var(NVM_DIR_ENV, Some(nvm_dir.as_os_str().to_os_string()));
        env.set_var("HOME", Some(temp.path().as_os_str().to_os_string()));
        env.set_var("USERPROFILE", Some(temp.path().as_os_str().to_os_string()));
        env.set_var("PATH", Some(empty_path.as_os_str().to_os_string()));

        let resolved = resolve_node_binary()?;
        assert_eq!(resolved, v20.join("node"));
        Ok(())
    }
}
