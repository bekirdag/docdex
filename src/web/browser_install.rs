use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

const INSTALL_DIR_NAME: &str = "chromium";
const INSTALL_LOCK_NAME: &str = "browser_install.lock";
const MANIFEST_FILE: &str = "manifest.json";
const DEFAULT_MANIFEST_URL: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";
const DEFAULT_PLATFORM: &str = "linux64";

#[derive(Debug, Clone)]
pub struct BrowserInstallResult {
    pub path: PathBuf,
    pub version: String,
}

pub fn resolve_installed_browser() -> Option<PathBuf> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let base_dir = crate::state_paths::default_state_base_dir().ok()?;
    let install_dir = base_dir.join("bin").join(INSTALL_DIR_NAME);
    let manifest_path = install_dir.join(MANIFEST_FILE);
    let raw = fs::read_to_string(manifest_path).ok()?;
    let parsed: Value = serde_json::from_str(&raw).ok()?;
    let path = parsed
        .get("path")
        .and_then(|value| value.as_str())
        .map(PathBuf::from)?;
    if path.is_file() {
        Some(path)
    } else {
        None
    }
}

pub fn install_if_missing(auto_install: bool) -> Result<Option<BrowserInstallResult>> {
    if !cfg!(target_os = "linux") {
        return Ok(None);
    }
    let auto_install = env_boolish("DOCDEX_BROWSER_AUTO_INSTALL").unwrap_or(auto_install);
    if !auto_install {
        return Ok(None);
    }
    if let Some(existing) = resolve_installed_browser() {
        return Ok(Some(BrowserInstallResult {
            path: existing,
            version: "installed".to_string(),
        }));
    }

    let base_dir =
        crate::state_paths::default_state_base_dir().context("resolve docdex state dir")?;
    let install_dir = base_dir.join("bin").join(INSTALL_DIR_NAME);
    fs::create_dir_all(&install_dir)
        .with_context(|| format!("create browser install dir {}", install_dir.display()))?;

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

    let result = install_chromium(&install_dir)?;
    lock_file.unlock().ok();
    Ok(Some(result))
}

fn install_chromium(install_dir: &Path) -> Result<BrowserInstallResult> {
    let download = resolve_download_spec()?;
    let version_dir = install_dir.join(&download.version);
    let manifest_path = install_dir.join(MANIFEST_FILE);
    let archive_path = install_dir.join(format!("chrome-{}.zip", download.version));

    if !version_dir.exists() {
        download_archive(&download.url, &archive_path)?;
        verify_sha256(&archive_path, &download.sha256)?;
        extract_zip(&archive_path, &version_dir)?;
    }

    let chrome_path = version_dir.join("chrome-linux64").join("chrome");
    if !chrome_path.is_file() {
        return Err(anyhow!(
            "installed browser binary not found at {}",
            chrome_path.display()
        ));
    }
    ensure_executable(&chrome_path)?;

    write_manifest(
        &manifest_path,
        &download.version,
        &download.url,
        &download.sha256,
        &chrome_path,
    )?;

    Ok(BrowserInstallResult {
        path: chrome_path,
        version: download.version,
    })
}

struct DownloadSpec {
    version: String,
    url: String,
    sha256: String,
}

fn resolve_download_spec() -> Result<DownloadSpec> {
    let override_base = env_string("DOCDEX_BROWSER_DOWNLOAD_BASE");
    let override_version = env_string("DOCDEX_BROWSER_VERSION");
    let override_sha = env_string("DOCDEX_BROWSER_SHA256");

    if let (Some(base), Some(version), Some(sha256)) = (
        override_base.as_ref(),
        override_version.as_ref(),
        override_sha.as_ref(),
    ) {
        let url = format!("{base}/{version}/linux64/chrome-linux64.zip");
        return Ok(DownloadSpec {
            version: version.clone(),
            url,
            sha256: sha256.clone(),
        });
    }

    let manifest_url = override_base.unwrap_or_else(|| DEFAULT_MANIFEST_URL.to_string());
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build browser manifest client")?;
    let manifest: Value = client
        .get(&manifest_url)
        .send()
        .context("download browser manifest")?
        .error_for_status()
        .context("browser manifest http error")?
        .json()
        .context("parse browser manifest JSON")?;

    let channels = manifest
        .get("channels")
        .and_then(|value| value.as_object())
        .ok_or_else(|| anyhow!("browser manifest missing channels"))?;
    let stable = channels
        .get("Stable")
        .ok_or_else(|| anyhow!("browser manifest missing Stable channel"))?;
    let version = stable
        .get("version")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow!("browser manifest missing version"))?;
    let downloads = stable
        .get("downloads")
        .and_then(|value| value.get("chrome"))
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow!("browser manifest missing downloads"))?;

    for entry in downloads {
        let platform = entry
            .get("platform")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if platform != DEFAULT_PLATFORM {
            continue;
        }
        let url = entry
            .get("url")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow!("browser manifest missing download url"))?;
        let sha256 = entry
            .get("sha256")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow!("browser manifest missing download checksum"))?;
        return Ok(DownloadSpec {
            version: version.to_string(),
            url: url.to_string(),
            sha256: sha256.to_string(),
        });
    }

    Err(anyhow!(
        "browser manifest missing linux64 download (platform {})",
        DEFAULT_PLATFORM
    ))
}

fn download_archive(url: &str, dest: &Path) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()
        .context("build browser download client")?;
    let partial_path = dest.with_extension("partial");
    let mut start = 0u64;
    if let Ok(metadata) = fs::metadata(&partial_path) {
        if metadata.is_file() {
            start = metadata.len();
        }
    }

    let mut request = client.get(url);
    if start > 0 {
        request = request.header(reqwest::header::RANGE, format!("bytes={start}-"));
    }

    let mut response = request.send().context("download browser archive")?;
    let status = response.status();
    if start > 0 && status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE && partial_path.is_file() {
        fs::rename(&partial_path, dest)
            .with_context(|| format!("finalize browser archive {}", dest.display()))?;
        return Ok(());
    }
    if start > 0 && status != reqwest::StatusCode::PARTIAL_CONTENT {
        let _ = fs::remove_file(&partial_path);
        start = 0;
        response = client.get(url).send().context("download browser archive")?;
    }

    let mut response = response
        .error_for_status()
        .context("browser archive http error")?;
    let mut file = if start > 0 {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(&partial_path)
            .with_context(|| format!("open browser archive {}", partial_path.display()))?
    } else {
        File::create(&partial_path)
            .with_context(|| format!("create browser archive {}", partial_path.display()))?
    };

    let copy_result = std::io::copy(&mut response, &mut file)
        .with_context(|| format!("write browser archive {}", partial_path.display()));
    if let Err(err) = copy_result {
        let _ = fs::remove_file(&partial_path);
        return Err(err);
    }

    fs::rename(&partial_path, dest)
        .with_context(|| format!("finalize browser archive {}", dest.display()))?;
    Ok(())
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(anyhow!(
            "browser archive checksum mismatch: expected {expected}, got {actual}"
        ))
    }
}

fn extract_zip(archive: &Path, dest: &Path) -> Result<()> {
    let file = File::open(archive)
        .with_context(|| format!("open browser archive {}", archive.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("open browser zip")?;
    if dest.exists() {
        fs::remove_dir_all(dest)
            .with_context(|| format!("remove existing browser dir {}", dest.display()))?;
    }
    fs::create_dir_all(dest).with_context(|| format!("create browser dir {}", dest.display()))?;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read browser zip entry")?;
        let outpath = dest.join(entry.name());
        if entry.name().ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(parent) = outpath.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut outfile = File::create(&outpath)?;
            std::io::copy(&mut entry, &mut outfile)?;
        }
    }
    Ok(())
}

fn ensure_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(perms.mode() | 0o111);
        fs::set_permissions(path, perms)?;
    }
    Ok(())
}

fn write_manifest(
    path: &Path,
    version: &str,
    url: &str,
    sha256: &str,
    chrome_path: &Path,
) -> Result<()> {
    let payload = serde_json::json!({
        "version": version,
        "url": url,
        "sha256": sha256,
        "path": chrome_path.to_string_lossy(),
    });
    fs::write(path, serde_json::to_string_pretty(&payload)?)
        .with_context(|| format!("write browser manifest {}", path.display()))?;
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

fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}
