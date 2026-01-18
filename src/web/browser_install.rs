use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use fs4::FileExt;
use serde::Deserialize;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;
use zip::ZipArchive;

use crate::state_layout::ensure_state_dir_secure;
use crate::util;

const INSTALL_LOCK_NAME: &str = "browser_install.lock";
const CHROMIUM_DIR_NAME: &str = "chromium";
const MANIFEST_FILE: &str = "manifest.json";
const CFT_LKG_URL: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;

#[derive(Debug, Clone)]
pub struct BrowserInstallResult {
    pub path: PathBuf,
    pub version: String,
}

#[derive(Debug, Clone)]
pub struct ChromiumInstallStatus {
    pub installed: bool,
    pub version: Option<String>,
    pub path: Option<PathBuf>,
}

pub fn resolve_installed_browser() -> Option<PathBuf> {
    util::resolve_chromium_binary_path()
}

pub fn chromium_install_status() -> ChromiumInstallStatus {
    if let Some(manifest) = util::read_chromium_manifest() {
        let path = manifest.path.clone();
        let installed = path.is_file();
        ChromiumInstallStatus {
            installed,
            version: manifest.version,
            path: if installed { Some(path) } else { None },
        }
    } else {
        ChromiumInstallStatus {
            installed: false,
            version: None,
            path: None,
        }
    }
}

pub fn install_if_missing(auto_install: bool) -> Result<Option<BrowserInstallResult>> {
    let auto_install = env_boolish("DOCDEX_BROWSER_AUTO_INSTALL").unwrap_or(auto_install);
    if !auto_install {
        return Ok(None);
    }
    if let Some(existing) = existing_install_result() {
        return Ok(Some(existing));
    }
    Ok(Some(install_chromium()?))
}

pub fn install_chromium() -> Result<BrowserInstallResult> {
    if let Some(existing) = existing_install_result() {
        return Ok(existing);
    }
    install_chromium_inner()
}

fn existing_install_result() -> Option<BrowserInstallResult> {
    let manifest = util::read_chromium_manifest()?;
    if !manifest.path.is_file() {
        return None;
    }
    Some(BrowserInstallResult {
        path: manifest.path,
        version: manifest.version.unwrap_or_else(|| "installed".to_string()),
    })
}

fn install_chromium_inner() -> Result<BrowserInstallResult> {
    let base_dir =
        crate::state_paths::default_state_base_dir().context("resolve docdex state dir")?;
    let install_dir = resolve_chromium_install_dir(&base_dir);
    ensure_state_dir_secure(&install_dir)
        .with_context(|| format!("create chromium install dir {}", install_dir.display()))?;

    let lock_dir = base_dir.join("locks");
    ensure_state_dir_secure(&lock_dir)
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

    if let Some(existing) = existing_install_result() {
        lock_file.unlock().ok();
        return Ok(existing);
    }

    let download = resolve_chromium_download()?;
    let staging_dir = install_dir
        .parent()
        .ok_or_else(|| anyhow!("chromium install dir has no parent"))?
        .join(format!("{CHROMIUM_DIR_NAME}.incoming"));
    if staging_dir.exists() {
        fs::remove_dir_all(&staging_dir)
            .with_context(|| format!("clear staging dir {}", staging_dir.display()))?;
    }
    fs::create_dir_all(&staging_dir)
        .with_context(|| format!("create staging dir {}", staging_dir.display()))?;

    download_and_extract(&download, &staging_dir)?;
    let binary_rel = chromium_binary_rel_path(&download.platform)?;
    let staged_binary = staging_dir.join(binary_rel);
    if !staged_binary.is_file() {
        return Err(anyhow!(
            "chromium binary missing after install at {}",
            staged_binary.display()
        ));
    }

    if install_dir.exists() {
        fs::remove_dir_all(&install_dir)
            .with_context(|| format!("remove old chromium dir {}", install_dir.display()))?;
    }
    fs::rename(&staging_dir, &install_dir)
        .with_context(|| format!("promote chromium dir {}", install_dir.display()))?;

    let final_binary = install_dir.join(binary_rel);
    ensure_binary_permissions(&final_binary)?;
    ensure_chromium_helper_permissions(&install_dir, &download.platform, &download.version)?;

    let manifest = util::ChromiumManifest {
        installed_at: Some(Utc::now().to_rfc3339()),
        version: Some(download.version.clone()),
        platform: Some(download.platform.clone()),
        download_url: Some(download.url.clone()),
        path: final_binary.clone(),
    };
    let manifest_path =
        util::resolve_chromium_manifest_path().unwrap_or_else(|| install_dir.join(MANIFEST_FILE));
    let payload = serde_json::to_string_pretty(&manifest).context("serialize chromium manifest")?;
    fs::write(&manifest_path, format!("{payload}\n"))
        .with_context(|| format!("write chromium manifest {}", manifest_path.display()))?;

    lock_file.unlock().ok();
    Ok(BrowserInstallResult {
        path: final_binary,
        version: download.version,
    })
}

fn resolve_chromium_install_dir(base_dir: &Path) -> PathBuf {
    base_dir.join("bin").join(CHROMIUM_DIR_NAME)
}

#[derive(Debug, Clone)]
struct ChromiumDownload {
    version: String,
    platform: String,
    url: String,
}

#[derive(Debug, Deserialize)]
struct CftManifest {
    channels: CftChannels,
}

#[derive(Debug, Deserialize)]
struct CftChannels {
    #[serde(rename = "Stable")]
    stable: CftChannel,
}

#[derive(Debug, Deserialize)]
struct CftChannel {
    version: String,
    downloads: CftDownloads,
}

#[derive(Debug, Deserialize)]
struct CftDownloads {
    chrome: Vec<CftDownload>,
}

#[derive(Debug, Deserialize)]
struct CftDownload {
    platform: String,
    url: String,
}

fn resolve_chromium_download() -> Result<ChromiumDownload> {
    let platform = chromium_platform()?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .build()
        .context("build chromium download client")?;
    let response = client
        .get(CFT_LKG_URL)
        .send()
        .context("fetch chromium manifest")?
        .error_for_status()
        .context("chromium manifest status")?;
    let manifest: CftManifest = response.json().context("parse chromium manifest")?;
    let channel = manifest.channels.stable;
    let download = channel
        .downloads
        .chrome
        .into_iter()
        .find(|entry| entry.platform == platform)
        .ok_or_else(|| anyhow!("no chromium download available for {platform}"))?;
    Ok(ChromiumDownload {
        version: channel.version,
        platform: platform.to_string(),
        url: download.url,
    })
}

fn download_and_extract(download: &ChromiumDownload, dest_dir: &Path) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .build()
        .context("build chromium downloader")?;
    let mut response = client
        .get(&download.url)
        .send()
        .with_context(|| format!("download chromium {}", download.url))?
        .error_for_status()
        .context("chromium download status")?;
    let mut temp_file = tempfile::NamedTempFile::new().context("create chromium temp file")?;
    io::copy(&mut response, &mut temp_file).context("write chromium archive")?;
    extract_zip(temp_file.path(), dest_dir)
}

fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("open chromium archive {}", archive_path.display()))?;
    let mut archive = ZipArchive::new(file).context("read chromium archive")?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read chromium archive entry")?;
        let Some(rel_path) = entry.enclosed_name() else {
            continue;
        };
        let out_path = dest_dir.join(rel_path);
        if entry.is_dir() {
            fs::create_dir_all(&out_path)
                .with_context(|| format!("create chromium dir {}", out_path.display()))?;
            #[cfg(unix)]
            apply_zip_entry_permissions(&entry, &out_path)?;
            continue;
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create chromium dir {}", parent.display()))?;
        }
        let mut outfile = File::create(&out_path)
            .with_context(|| format!("write chromium file {}", out_path.display()))?;
        io::copy(&mut entry, &mut outfile).context("extract chromium archive")?;
        #[cfg(unix)]
        apply_zip_entry_permissions(&entry, &out_path)?;
    }
    Ok(())
}

#[cfg(unix)]
fn apply_zip_entry_permissions(entry: &zip::read::ZipFile<'_>, out_path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(mode) = entry.unix_mode() else {
        return Ok(());
    };
    let mode = mode & 0o777;
    if mode == 0 {
        return Ok(());
    }
    let mut perms = fs::metadata(out_path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(out_path, perms)?;
    Ok(())
}

fn chromium_platform() -> Result<&'static str> {
    if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            return Ok("mac-arm64");
        }
        return Ok("mac-x64");
    }
    if cfg!(target_os = "linux") {
        return Ok("linux64");
    }
    if cfg!(target_os = "windows") {
        return Ok("win64");
    }
    Err(anyhow!("unsupported platform for chromium install"))
}

fn chromium_binary_rel_path(platform: &str) -> Result<&'static str> {
    match platform {
        "mac-arm64" => Ok(
            "chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        ),
        "mac-x64" => Ok(
            "chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
        ),
        "linux64" => Ok("chrome-linux64/chrome"),
        "win64" => Ok("chrome-win64/chrome.exe"),
        _ => Err(anyhow!("unsupported chromium platform: {platform}")),
    }
}

#[cfg(unix)]
fn ensure_chromium_helper_permissions(
    _install_dir: &Path,
    _platform: &str,
    _version: &str,
) -> Result<()> {
    let Some(helpers_dir) = resolve_chromium_helpers_dir(_install_dir, _platform, _version) else {
        return Ok(());
    };
    let helper_bins = [
        "app_mode_loader",
        "chrome_crashpad_handler",
        "web_app_shortcut_copier",
        "Google Chrome for Testing Helper.app/Contents/MacOS/Google Chrome for Testing Helper",
        "Google Chrome for Testing Helper (Alerts).app/Contents/MacOS/Google Chrome for Testing Helper (Alerts)",
        "Google Chrome for Testing Helper (GPU).app/Contents/MacOS/Google Chrome for Testing Helper (GPU)",
        "Google Chrome for Testing Helper (Plugin).app/Contents/MacOS/Google Chrome for Testing Helper (Plugin)",
        "Google Chrome for Testing Helper (Renderer).app/Contents/MacOS/Google Chrome for Testing Helper (Renderer)",
    ];
    for rel_path in helper_bins {
        let path = helpers_dir.join(rel_path);
        if path.is_file() {
            ensure_binary_permissions(&path)?;
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_chromium_helper_permissions(
    _install_dir: &Path,
    _platform: &str,
    _version: &str,
) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn resolve_chromium_helpers_dir(
    install_dir: &Path,
    platform: &str,
    version: &str,
) -> Option<PathBuf> {
    let base = match platform {
        "mac-arm64" => "chrome-mac-arm64/Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Versions",
        "mac-x64" => "chrome-mac-x64/Google Chrome for Testing.app/Contents/Frameworks/Google Chrome for Testing Framework.framework/Versions",
        _ => return None,
    };
    let versions_dir = install_dir.join(base);
    let by_version = versions_dir.join(version).join("Helpers");
    if by_version.is_dir() {
        return Some(by_version);
    }
    let entries = fs::read_dir(&versions_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let helpers_dir = path.join("Helpers");
            if helpers_dir.is_dir() {
                return Some(helpers_dir);
            }
        }
    }
    None
}

#[cfg(unix)]
fn ensure_binary_permissions(_path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::metadata(_path)?;
    let mut perms = metadata.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(_path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn ensure_binary_permissions(_path: &Path) -> Result<()> {
    Ok(())
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

    #[test]
    fn chromium_binary_rel_path_known_platforms() {
        assert!(chromium_binary_rel_path("linux64")
            .unwrap()
            .ends_with("/chrome"));
        assert!(chromium_binary_rel_path("mac-arm64")
            .unwrap()
            .contains("Google Chrome for Testing.app"));
        assert!(chromium_binary_rel_path("win64").unwrap().ends_with(".exe"));
    }
}
