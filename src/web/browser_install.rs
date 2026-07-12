use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use fs4::FileExt;
use serde::Deserialize;
use std::cmp::Ordering as CmpOrdering;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use zip::ZipArchive;

use crate::state_layout::ensure_state_dir_secure;
use crate::util;
use crate::web::policy::public_dns_resolver;

const INSTALL_LOCK_NAME: &str = "browser_install.lock";
const CHROMIUM_DIR_NAME: &str = "chromium";
const CHROMIUM_ARTIFACT: &str = util::MANAGED_CHROMIUM_ARTIFACT;
const CFT_LKG_URL: &str =
    "https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions-with-downloads.json";
const DOWNLOAD_TIMEOUT_SECS: u64 = 300;
const DEFAULT_UPDATE_CHECK_INTERVAL_SECS: u64 = 24 * 60 * 60;
const MAX_UPDATE_CHECK_INTERVAL_SECS: u64 = 30 * 24 * 60 * 60;
const DEFAULT_INSTALL_LOCK_TIMEOUT_MS: u64 = 30_000;
const MAX_INSTALL_LOCK_TIMEOUT_MS: u64 = 5 * 60 * 1_000;
const INSTALL_LOCK_POLL_MS: u64 = 50;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 100_000;
const MAX_SYMLINK_TARGET_BYTES: u64 = 4_096;
static INSTALL_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

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

#[derive(Debug, Clone)]
struct ExistingInstall {
    result: BrowserInstallResult,
    manifest: util::ChromiumManifest,
}

struct InstallSingleflightGuard;

impl Drop for InstallSingleflightGuard {
    fn drop(&mut self) {
        INSTALL_IN_PROGRESS.store(false, Ordering::Release);
    }
}

struct InstallFileLock {
    file: File,
}

struct StagingDirGuard {
    path: PathBuf,
}

impl Drop for StagingDirGuard {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.path) {
            if error.kind() != io::ErrorKind::NotFound {
                tracing::warn!(
                    target: "docdexd",
                    path = %self.path.display(),
                    error = %error,
                    "failed to clean managed browser staging directory"
                );
            }
        }
    }
}

impl Drop for InstallFileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub fn resolve_installed_browser() -> Option<PathBuf> {
    util::resolve_chromium_binary_path()
}

pub fn chromium_install_status() -> ChromiumInstallStatus {
    if let Some(manifest) = util::read_chromium_manifest() {
        let path = manifest.path.clone();
        let installed = util::chromium_manifest_is_usable(&manifest);
        ChromiumInstallStatus {
            installed,
            version: if installed { manifest.version } else { None },
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
    install_or_refresh_managed(auto_install)
}

pub fn install_or_refresh_managed(auto_install: bool) -> Result<Option<BrowserInstallResult>> {
    let auto_install = env_boolish("DOCDEX_BROWSER_AUTO_INSTALL").unwrap_or(auto_install);
    if !auto_install {
        return Ok(None);
    }
    Ok(Some(install_chromium_with_policy(false)?))
}

pub fn install_chromium() -> Result<BrowserInstallResult> {
    install_chromium_with_policy(true)
}

fn install_chromium_with_policy(force_update_check: bool) -> Result<BrowserInstallResult> {
    let existing = existing_install();
    if existing
        .as_ref()
        .is_some_and(|entry| !update_check_required(&entry.manifest, force_update_check))
    {
        return Ok(existing.expect("existing install checked above").result);
    }

    let Some(_singleflight) = try_acquire_install_singleflight() else {
        if !force_update_check {
            if let Some(existing) = existing {
                return Ok(existing.result);
            }
        }
        return Err(anyhow!(
            "managed browser installation is already running in this process; retry shortly"
        ));
    };

    let existing = existing_install();
    if existing
        .as_ref()
        .is_some_and(|entry| !update_check_required(&entry.manifest, force_update_check))
    {
        return Ok(existing.expect("existing install checked above").result);
    }
    install_chromium_inner(force_update_check)
}

fn existing_install() -> Option<ExistingInstall> {
    let manifest = util::read_chromium_manifest()?;
    if !util::chromium_manifest_is_usable(&manifest) {
        return None;
    }
    let result = BrowserInstallResult {
        path: manifest.path.clone(),
        version: manifest.version.clone()?,
    };
    Some(ExistingInstall { result, manifest })
}

fn install_chromium_inner(force_update_check: bool) -> Result<BrowserInstallResult> {
    let base_dir =
        crate::state_paths::default_state_base_dir().context("resolve docdex state dir")?;
    let install_dir = resolve_chromium_install_dir(&base_dir);
    ensure_state_dir_secure(&install_dir)
        .with_context(|| format!("create chromium install dir {}", install_dir.display()))?;

    let lock_dir = base_dir.join("locks");
    ensure_state_dir_secure(&lock_dir)
        .with_context(|| format!("create browser lock dir {}", lock_dir.display()))?;
    let lock_path = lock_dir.join(INSTALL_LOCK_NAME);
    let _install_lock = match acquire_install_lock(&lock_path, install_lock_timeout()) {
        Ok(lock) => lock,
        Err(error) => {
            return existing_or_error(
                existing_install(),
                error,
                "lock acquisition",
                !force_update_check,
            )
        }
    };

    recover_interrupted_install(&install_dir)?;

    let existing = existing_install();
    if existing
        .as_ref()
        .is_some_and(|entry| !update_check_required(&entry.manifest, force_update_check))
    {
        return Ok(existing.expect("existing install checked above").result);
    }

    let download = match resolve_chromium_download() {
        Ok(download) => download,
        Err(error) => {
            return existing_or_error(existing, error, "stable-version check", !force_update_check)
        }
    };
    if let Some(mut existing) = existing {
        match compare_chromium_versions(&existing.result.version, &download.version) {
            Some(CmpOrdering::Greater) => {
                existing.manifest.last_checked_at = Some(Utc::now().to_rfc3339());
                if let Err(error) = write_chromium_manifest(&existing.manifest) {
                    tracing::warn!(
                        target: "docdexd",
                        error = %error,
                        "managed browser downgrade was rejected but its refresh timestamp could not be persisted"
                    );
                }
                tracing::warn!(
                    target: "docdexd",
                    installed_version = %existing.result.version,
                    offered_version = %download.version,
                    "refusing to downgrade the managed browser"
                );
                return Ok(existing.result);
            }
            None => {
                return Err(anyhow!(
                    "managed browser version comparison failed for installed={} offered={}",
                    existing.result.version,
                    download.version
                ));
            }
            _ => {}
        }
        if existing.result.version == download.version {
            existing.manifest.last_checked_at = Some(Utc::now().to_rfc3339());
            if let Err(error) = write_chromium_manifest(&existing.manifest) {
                tracing::warn!(
                    target: "docdexd",
                    error = %error,
                    "managed browser version is current but its refresh timestamp could not be persisted"
                );
            }
            return Ok(existing.result);
        }
    }

    match install_chromium_download(&base_dir, &install_dir, &download) {
        Ok(result) => Ok(result),
        Err(error) => existing_or_error(
            existing_install(),
            error,
            "browser update",
            !force_update_check,
        ),
    }
}

fn install_chromium_download(
    base_dir: &Path,
    install_dir: &Path,
    download: &ChromiumDownload,
) -> Result<BrowserInstallResult> {
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
    let _staging_guard = StagingDirGuard {
        path: staging_dir.clone(),
    };

    download_and_extract(&download, &staging_dir)?;
    let binary_rel = chromium_binary_rel_path(&download.platform)?;
    let staged_binary = staging_dir.join(binary_rel);
    if !staged_binary.is_file() {
        return Err(anyhow!(
            "chromium binary missing after install at {}",
            staged_binary.display()
        ));
    }

    let backup_dir = chromium_backup_dir(install_dir)?;
    if backup_dir.exists() {
        fs::remove_dir_all(&backup_dir)
            .with_context(|| format!("clear chromium backup dir {}", backup_dir.display()))?;
    }
    let had_existing = install_dir.exists();
    if had_existing {
        fs::rename(install_dir, &backup_dir).with_context(|| {
            format!(
                "move existing chromium install {} to rollback backup {}",
                install_dir.display(),
                backup_dir.display()
            )
        })?;
    }
    if let Err(error) = fs::rename(&staging_dir, install_dir) {
        if had_existing {
            let _ = fs::rename(&backup_dir, install_dir);
        }
        return Err(error)
            .with_context(|| format!("promote chromium dir {}", install_dir.display()));
    }

    let promoted_result = (|| -> Result<BrowserInstallResult> {
        let final_binary = install_dir.join(binary_rel);
        let expected_binary = util::managed_chromium_binary_path(base_dir, &download.platform)
            .ok_or_else(|| anyhow!("unsupported chromium platform: {}", download.platform))?;
        if final_binary != expected_binary {
            return Err(anyhow!(
                "managed chromium path mismatch: expected {}, got {}",
                expected_binary.display(),
                final_binary.display()
            ));
        }
        ensure_binary_permissions(&final_binary)?;

        let manifest = util::ChromiumManifest {
            installed_at: Some(Utc::now().to_rfc3339()),
            last_checked_at: Some(Utc::now().to_rfc3339()),
            version: Some(download.version.clone()),
            platform: Some(download.platform.clone()),
            artifact: Some(CHROMIUM_ARTIFACT.to_string()),
            download_url: Some(download.url.clone()),
            path: final_binary.clone(),
        };
        write_chromium_manifest(&manifest)?;
        Ok(BrowserInstallResult {
            path: final_binary,
            version: download.version.clone(),
        })
    })();
    let result = match promoted_result {
        Ok(result) => result,
        Err(error) => {
            rollback_promoted_install(install_dir, &backup_dir, had_existing).with_context(
                || format!("restore previous managed browser after update failure: {error}"),
            )?;
            return Err(error).context("managed browser update rolled back");
        }
    };
    if had_existing {
        if let Err(error) = fs::remove_dir_all(&backup_dir) {
            tracing::warn!(
                target: "docdexd",
                path = %backup_dir.display(),
                error = %error,
                "managed browser update succeeded but rollback cleanup was deferred"
            );
        }
    }
    Ok(result)
}

fn rollback_promoted_install(
    install_dir: &Path,
    backup_dir: &Path,
    had_existing: bool,
) -> Result<()> {
    let failed_dir = chromium_failed_dir(install_dir)?;
    if failed_dir.exists() {
        fs::remove_dir_all(&failed_dir)
            .with_context(|| format!("clear failed browser dir {}", failed_dir.display()))?;
    }
    if install_dir.exists() {
        if fs::rename(install_dir, &failed_dir).is_err() {
            fs::remove_dir_all(install_dir).with_context(|| {
                format!("remove failed promoted browser {}", install_dir.display())
            })?;
        }
    }
    if had_existing {
        fs::rename(backup_dir, install_dir).with_context(|| {
            format!(
                "restore browser rollback {} to {}",
                backup_dir.display(),
                install_dir.display()
            )
        })?;
    }
    if failed_dir.exists() {
        fs::remove_dir_all(&failed_dir)
            .with_context(|| format!("remove failed browser dir {}", failed_dir.display()))?;
    }
    Ok(())
}

fn compare_chromium_versions(left: &str, right: &str) -> Option<CmpOrdering> {
    fn parse(value: &str) -> Option<Vec<u64>> {
        let parts = value
            .split('.')
            .map(|part| {
                if part.is_empty() {
                    None
                } else {
                    part.parse::<u64>().ok()
                }
            })
            .collect::<Option<Vec<_>>>()?;
        (!parts.is_empty()).then_some(parts)
    }

    let mut left = parse(left)?;
    let mut right = parse(right)?;
    let width = left.len().max(right.len());
    left.resize(width, 0);
    right.resize(width, 0);
    Some(left.cmp(&right))
}

fn chromium_backup_dir(install_dir: &Path) -> Result<PathBuf> {
    let parent = install_dir
        .parent()
        .ok_or_else(|| anyhow!("chromium install dir has no parent"))?;
    Ok(parent.join(format!("{CHROMIUM_DIR_NAME}.rollback")))
}

fn chromium_failed_dir(install_dir: &Path) -> Result<PathBuf> {
    let parent = install_dir
        .parent()
        .ok_or_else(|| anyhow!("chromium install dir has no parent"))?;
    Ok(parent.join(format!("{CHROMIUM_DIR_NAME}.failed")))
}

fn recover_interrupted_install(install_dir: &Path) -> Result<()> {
    let backup_dir = chromium_backup_dir(install_dir)?;
    if !backup_dir.exists() {
        return Ok(());
    }
    if install_dir.exists() && existing_install().is_some() {
        fs::remove_dir_all(&backup_dir).with_context(|| {
            format!(
                "remove obsolete chromium rollback backup {}",
                backup_dir.display()
            )
        })?;
        return Ok(());
    }
    if install_dir.exists() {
        fs::remove_dir_all(install_dir).with_context(|| {
            format!(
                "remove interrupted chromium install {}",
                install_dir.display()
            )
        })?;
    }
    fs::rename(&backup_dir, install_dir).with_context(|| {
        format!(
            "restore interrupted chromium install from {} to {}",
            backup_dir.display(),
            install_dir.display()
        )
    })?;
    Ok(())
}

fn try_acquire_install_singleflight() -> Option<InstallSingleflightGuard> {
    INSTALL_IN_PROGRESS
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| InstallSingleflightGuard)
}

fn acquire_install_lock(lock_path: &Path, timeout: Duration) -> Result<InstallFileLock> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(lock_path)
        .with_context(|| format!("open install lock {}", lock_path.display()))?;
    let started = Instant::now();
    loop {
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(InstallFileLock { file }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let elapsed = started.elapsed();
                if elapsed >= timeout {
                    return Err(anyhow!(
                        "timed out after {}ms waiting for browser install lock {}",
                        timeout.as_millis(),
                        lock_path.display()
                    ));
                }
                let remaining = timeout.saturating_sub(elapsed);
                std::thread::sleep(remaining.min(Duration::from_millis(INSTALL_LOCK_POLL_MS)));
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("lock browser install file {}", lock_path.display()));
            }
        }
    }
}

fn update_check_required(manifest: &util::ChromiumManifest, force: bool) -> bool {
    if force {
        return true;
    }
    if !env_boolish("DOCDEX_BROWSER_AUTO_UPDATE").unwrap_or(true) {
        return false;
    }
    manifest_refresh_due_at(manifest, Utc::now(), update_check_interval())
}

fn manifest_refresh_due_at(
    manifest: &util::ChromiumManifest,
    now: DateTime<Utc>,
    interval: Duration,
) -> bool {
    if interval.is_zero() {
        return true;
    }
    let Some(raw_timestamp) = manifest
        .last_checked_at
        .as_deref()
        .or(manifest.installed_at.as_deref())
    else {
        return true;
    };
    let Ok(timestamp) = DateTime::parse_from_rfc3339(raw_timestamp) else {
        return true;
    };
    let timestamp = timestamp.with_timezone(&Utc);
    if timestamp > now + chrono::Duration::minutes(5) {
        return true;
    }
    if timestamp > now {
        return false;
    }
    now.signed_duration_since(timestamp)
        .to_std()
        .map(|elapsed| elapsed >= interval)
        .unwrap_or(true)
}

fn update_check_interval() -> Duration {
    let seconds = env_u64("DOCDEX_BROWSER_UPDATE_CHECK_INTERVAL_SECS")
        .unwrap_or(DEFAULT_UPDATE_CHECK_INTERVAL_SECS)
        .min(MAX_UPDATE_CHECK_INTERVAL_SECS);
    Duration::from_secs(seconds)
}

fn install_lock_timeout() -> Duration {
    let millis = env_u64("DOCDEX_BROWSER_INSTALL_LOCK_TIMEOUT_MS")
        .unwrap_or(DEFAULT_INSTALL_LOCK_TIMEOUT_MS)
        .clamp(1, MAX_INSTALL_LOCK_TIMEOUT_MS);
    Duration::from_millis(millis)
}

fn existing_or_error(
    existing: Option<ExistingInstall>,
    error: anyhow::Error,
    action: &str,
    allow_existing: bool,
) -> Result<BrowserInstallResult> {
    if allow_existing {
        if let Some(existing) = existing.as_ref() {
            tracing::warn!(
                target: "docdexd",
                error = %error,
                action,
                version = %existing.result.version,
                "managed browser refresh failed; continuing with the validated installed browser"
            );
            return Ok(existing.result.clone());
        }
    }
    if existing.is_some() {
        tracing::warn!(
            target: "docdexd",
            error = %error,
            action,
            "managed browser refresh failed; the existing validated browser remains available"
        );
    }
    Err(error).with_context(|| format!("managed browser {action} failed"))
}

fn write_chromium_manifest(manifest: &util::ChromiumManifest) -> Result<()> {
    let manifest_path =
        util::resolve_chromium_manifest_path().context("resolve managed chromium manifest path")?;
    let parent = manifest_path
        .parent()
        .ok_or_else(|| anyhow!("managed chromium manifest has no parent"))?;
    ensure_state_dir_secure(parent)
        .with_context(|| format!("create chromium manifest dir {}", parent.display()))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("create chromium manifest temp file in {}", parent.display()))?;
    serde_json::to_writer_pretty(temp.as_file_mut(), manifest)
        .context("serialize chromium manifest")?;
    temp.as_file_mut()
        .write_all(b"\n")
        .context("finish chromium manifest")?;
    temp.as_file_mut()
        .flush()
        .context("flush chromium manifest")?;
    temp.as_file()
        .sync_all()
        .context("sync chromium manifest")?;
    temp.persist(&manifest_path)
        .map_err(|error| error.error)
        .with_context(|| format!("write chromium manifest {}", manifest_path.display()))?;
    Ok(())
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
    #[serde(rename = "chrome-headless-shell")]
    chrome_headless_shell: Vec<CftDownload>,
}

#[derive(Debug, Deserialize)]
struct CftDownload {
    platform: String,
    url: String,
}

fn resolve_chromium_download() -> Result<ChromiumDownload> {
    let platform = chromium_platform()?;
    let client = build_download_client()?;
    let response = client
        .get(CFT_LKG_URL)
        .send()
        .context("fetch chromium manifest")?
        .error_for_status()
        .context("chromium manifest status")?;
    let manifest_body = read_response_limited(response, MAX_MANIFEST_BYTES, "chromium manifest")?;
    let manifest: CftManifest =
        serde_json::from_slice(&manifest_body).context("parse chromium manifest")?;
    let channel = manifest.channels.stable;
    let download = channel
        .downloads
        .chrome_headless_shell
        .into_iter()
        .find(|entry| entry.platform == platform)
        .ok_or_else(|| anyhow!("no chromium download available for {platform}"))?;
    validate_chromium_download_url(&channel.version, platform, &download.url)?;
    Ok(ChromiumDownload {
        version: channel.version,
        platform: platform.to_string(),
        url: download.url,
    })
}

fn download_and_extract(download: &ChromiumDownload, dest_dir: &Path) -> Result<()> {
    let client = build_download_client()?;
    let mut response = client
        .get(&download.url)
        .send()
        .with_context(|| format!("download chromium {}", download.url))?
        .error_for_status()
        .context("chromium download status")?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ARCHIVE_BYTES)
    {
        return Err(anyhow!(
            "chromium archive exceeds the {} byte download limit",
            MAX_ARCHIVE_BYTES
        ));
    }
    let mut temp_file = tempfile::NamedTempFile::new().context("create chromium temp file")?;
    copy_limited(
        &mut response,
        &mut temp_file,
        MAX_ARCHIVE_BYTES,
        "chromium archive",
    )?;
    extract_zip(temp_file.path(), dest_dir)
}

fn build_download_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .dns_resolver(public_dns_resolver())
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(DOWNLOAD_TIMEOUT_SECS))
        .build()
        .context("build chromium download client")
}

fn validate_chromium_download_url(version: &str, platform: &str, raw_url: &str) -> Result<()> {
    let _url = url::Url::parse(raw_url).context("parse chromium download URL")?;
    let expected = util::managed_chromium_download_url(version, platform)
        .ok_or_else(|| anyhow!("chromium manifest returned an invalid version or platform"))?;
    if raw_url != expected {
        return Err(anyhow!(
            "chromium manifest returned an unexpected artifact URL"
        ));
    }
    Ok(())
}

fn read_response_limited(
    mut response: reqwest::blocking::Response,
    limit: u64,
    label: &str,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        return Err(anyhow!("{label} exceeds the {limit} byte response limit"));
    }
    let mut body = Vec::new();
    copy_limited(&mut response, &mut body, limit, label)?;
    Ok(body)
}

fn copy_limited(
    reader: &mut impl Read,
    writer: &mut impl io::Write,
    limit: u64,
    label: &str,
) -> Result<u64> {
    let copied = io::copy(&mut reader.take(limit.saturating_add(1)), writer)
        .with_context(|| format!("read {label}"))?;
    if copied > limit {
        return Err(anyhow!("{label} exceeds the {limit} byte limit"));
    }
    Ok(copied)
}

fn extract_zip(archive_path: &Path, dest_dir: &Path) -> Result<()> {
    let file = File::open(archive_path)
        .with_context(|| format!("open chromium archive {}", archive_path.display()))?;
    let mut archive = ZipArchive::new(file).context("read chromium archive")?;
    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(anyhow!(
            "chromium archive contains more than {MAX_ARCHIVE_ENTRIES} entries"
        ));
    }
    let mut extracted_bytes = 0u64;
    #[cfg(unix)]
    let mut symlinks = Vec::new();
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).context("read chromium archive entry")?;
        let Some(rel_path) = entry.enclosed_name().map(Path::to_path_buf) else {
            continue;
        };
        let out_path = dest_dir.join(rel_path);
        if zip_entry_is_symlink(&entry) {
            let mut target = Vec::new();
            entry
                .by_ref()
                .take(MAX_SYMLINK_TARGET_BYTES + 1)
                .read_to_end(&mut target)
                .context("read chromium archive symlink target")?;
            if target.len() as u64 > MAX_SYMLINK_TARGET_BYTES {
                return Err(anyhow!("chromium archive symlink target is too long"));
            }
            extracted_bytes = reserve_extracted_bytes(extracted_bytes, target.len() as u64)?;
            let target = String::from_utf8(target)
                .context("chromium archive symlink target is not UTF-8")?;
            #[cfg(unix)]
            symlinks.push((out_path, PathBuf::from(target)));
            #[cfg(not(unix))]
            return Err(anyhow!(
                "chromium archive contains a symlink unsupported on this platform"
            ));
            continue;
        }
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
        let before_entry = extracted_bytes;
        reserve_extracted_bytes(before_entry, entry.size())?;
        let copied = copy_limited(
            &mut entry,
            &mut outfile,
            MAX_EXTRACTED_BYTES.saturating_sub(before_entry),
            "chromium archive entry",
        )?;
        extracted_bytes = reserve_extracted_bytes(before_entry, copied)?;
        #[cfg(unix)]
        apply_zip_entry_permissions(&entry, &out_path)?;
    }
    #[cfg(unix)]
    for (link_path, target) in symlinks {
        create_safe_archive_symlink(dest_dir, &link_path, &target)?;
    }
    Ok(())
}

fn reserve_extracted_bytes(current: u64, additional: u64) -> Result<u64> {
    let total = current
        .checked_add(additional)
        .ok_or_else(|| anyhow!("chromium archive expanded size overflow"))?;
    if total > MAX_EXTRACTED_BYTES {
        return Err(anyhow!(
            "chromium archive exceeds the {MAX_EXTRACTED_BYTES} byte expanded size limit"
        ));
    }
    Ok(total)
}

fn zip_entry_is_symlink(entry: &zip::read::ZipFile<'_>) -> bool {
    entry
        .unix_mode()
        .is_some_and(|mode| mode & 0o170000 == 0o120000)
}

#[cfg(unix)]
fn create_safe_archive_symlink(dest_dir: &Path, link_path: &Path, target: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    if target.as_os_str().is_empty() || target.is_absolute() {
        return Err(anyhow!(
            "chromium archive contains an unsafe symlink target"
        ));
    }
    let parent = link_path
        .parent()
        .ok_or_else(|| anyhow!("chromium archive symlink has no parent"))?;
    let parent_rel = parent
        .strip_prefix(dest_dir)
        .context("chromium archive symlink escapes destination")?;
    let mut depth = parent_rel
        .components()
        .filter(|component| matches!(component, std::path::Component::Normal(_)))
        .count();
    for component in target.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::ParentDir if depth > 0 => depth -= 1,
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err(anyhow!(
                    "chromium archive symlink target escapes destination"
                ));
            }
        }
    }
    if fs::symlink_metadata(link_path).is_ok() {
        return Err(anyhow!(
            "chromium archive contains duplicate path {}",
            link_path.display()
        ));
    }
    fs::create_dir_all(parent)
        .with_context(|| format!("create chromium dir {}", parent.display()))?;
    symlink(target, link_path)
        .with_context(|| format!("create chromium symlink {}", link_path.display()))?;
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
    util::managed_chromium_platform()
        .ok_or_else(|| anyhow!("unsupported platform for chromium install"))
}

fn chromium_binary_rel_path(platform: &str) -> Result<&'static str> {
    util::managed_chromium_binary_rel_path(platform)
        .ok_or_else(|| anyhow!("unsupported chromium platform: {platform}"))
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

fn env_u64(key: &str) -> Option<u64> {
    let raw = std::env::var(key).ok()?;
    raw.trim().parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use once_cell::sync::Lazy;
    use std::io::Write;
    use std::sync::Mutex;

    static INSTALL_TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    #[test]
    fn chromium_binary_rel_path_known_platforms() {
        assert!(chromium_binary_rel_path("linux64")
            .unwrap()
            .ends_with("/chrome-headless-shell"));
        assert!(chromium_binary_rel_path("mac-arm64")
            .unwrap()
            .contains("chrome-headless-shell"));
        assert!(chromium_binary_rel_path("win64").unwrap().ends_with(".exe"));
    }

    #[test]
    fn chromium_download_url_is_restricted_to_official_storage() {
        let version = "123.0.4567.8";
        let platform = "mac-arm64";
        validate_chromium_download_url(
            version,
            platform,
            "https://storage.googleapis.com/chrome-for-testing-public/123.0.4567.8/mac-arm64/chrome-headless-shell-mac-arm64.zip",
        )
        .expect("official URL");
        for untrusted in [
            "http://storage.googleapis.com/chrome-for-testing-public/123.0.4567.8/mac-arm64/chrome-headless-shell-mac-arm64.zip",
            "https://storage.googleapis.com/chrome-for-testing-public/999/mac-arm64/chrome-headless-shell-mac-arm64.zip",
            "https://storage.googleapis.com/chrome-for-testing-public/123.0.4567.8/mac-arm64/chrome-mac-arm64.zip",
            "https://storage.googleapis.com/chrome-for-testing-public/123.0.4567.8/mac-arm64/chrome-headless-shell-mac-arm64.zip?mirror=1",
            "https://127.0.0.1/chrome-for-testing-public/123.0.4567.8/mac-arm64/chrome-headless-shell-mac-arm64.zip",
        ] {
            assert!(validate_chromium_download_url(version, platform, untrusted).is_err());
        }
    }

    #[test]
    fn bounded_copy_rejects_streams_larger_than_the_limit() {
        let mut input = std::io::Cursor::new(b"12345".to_vec());
        let mut output = Vec::new();
        let error = copy_limited(&mut input, &mut output, 4, "test stream")
            .expect_err("oversized stream must fail");
        assert!(error.to_string().contains("exceeds the 4 byte limit"));
        assert_eq!(output, b"12345");
    }

    #[test]
    fn expanded_archive_budget_rejects_overflow_and_oversize() {
        assert_eq!(reserve_extracted_bytes(10, 20).expect("within limit"), 30);
        assert!(reserve_extracted_bytes(MAX_EXTRACTED_BYTES, 1).is_err());
        assert!(reserve_extracted_bytes(u64::MAX, 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn extract_zip_preserves_safe_symlinks() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let archive_path = temp.path().join("browser.zip");
        {
            let file = File::create(&archive_path).expect("archive file");
            let mut archive = zip::ZipWriter::new(file);
            let options = zip::write::FileOptions::default();
            archive
                .start_file("bundle/Versions/1/resource.txt", options)
                .expect("start resource");
            archive.write_all(b"ok").expect("write resource");
            archive
                .add_symlink("bundle/Versions/Current", "1", options)
                .expect("add version symlink");
            archive
                .add_symlink("bundle/Resources", "Versions/Current", options)
                .expect("add resources symlink");
            archive.finish().expect("finish archive");
        }

        let destination = temp.path().join("out");
        fs::create_dir(&destination).expect("destination");
        extract_zip(&archive_path, &destination).expect("extract archive");

        let current = destination.join("bundle/Versions/Current");
        assert!(fs::symlink_metadata(&current)
            .expect("current metadata")
            .file_type()
            .is_symlink());
        assert_eq!(
            fs::read_link(&current).expect("current target"),
            Path::new("1")
        );
        assert_eq!(
            fs::read(destination.join("bundle/Resources/resource.txt")).expect("linked resource"),
            b"ok"
        );
    }

    #[cfg(unix)]
    #[test]
    fn extract_zip_rejects_escaping_symlinks() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let archive_path = temp.path().join("browser.zip");
        {
            let file = File::create(&archive_path).expect("archive file");
            let mut archive = zip::ZipWriter::new(file);
            archive
                .add_symlink(
                    "bundle/escape",
                    "../../outside",
                    zip::write::FileOptions::default(),
                )
                .expect("add unsafe symlink");
            archive.finish().expect("finish archive");
        }

        let destination = temp.path().join("out");
        fs::create_dir(&destination).expect("destination");
        let error = extract_zip(&archive_path, &destination)
            .expect_err("escaping symlink must be rejected");
        assert!(error.to_string().contains("escapes destination"));
        assert!(!destination.join("bundle/escape").exists());
    }

    #[test]
    fn managed_install_validation_requires_canonical_current_artifact() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let platform = "mac-arm64";
        let version = "123.0.4567.8";
        let binary =
            util::managed_chromium_binary_path(temp.path(), platform).expect("managed binary path");
        fs::create_dir_all(binary.parent().expect("binary parent")).expect("binary directory");
        fs::write(&binary, b"binary").expect("binary");
        ensure_binary_permissions(&binary).expect("executable permissions");
        let mut manifest = util::ChromiumManifest {
            installed_at: None,
            last_checked_at: None,
            version: Some(version.to_string()),
            platform: Some(platform.to_string()),
            artifact: None,
            download_url: util::managed_chromium_download_url(version, platform),
            path: binary.clone(),
        };
        assert!(!util::chromium_manifest_is_usable_at(
            &manifest,
            temp.path(),
            platform
        ));
        manifest.artifact = Some(CHROMIUM_ARTIFACT.to_string());
        assert!(util::chromium_manifest_is_usable_at(
            &manifest,
            temp.path(),
            platform
        ));

        let valid = manifest.clone();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&binary)
                .expect("binary metadata")
                .permissions();
            permissions.set_mode(0o644);
            fs::set_permissions(&binary, permissions).expect("remove executable bit");
            assert!(!util::chromium_manifest_is_usable_at(
                &valid,
                temp.path(),
                platform
            ));
            ensure_binary_permissions(&binary).expect("restore executable permissions");
        }
        manifest.version = Some(String::new());
        assert!(!util::chromium_manifest_is_usable_at(
            &manifest,
            temp.path(),
            platform
        ));
        manifest = valid.clone();
        manifest.platform = Some("linux64".to_string());
        assert!(!util::chromium_manifest_is_usable_at(
            &manifest,
            temp.path(),
            platform
        ));
        manifest = valid.clone();
        manifest.download_url = Some("https://example.com/browser.zip".to_string());
        assert!(!util::chromium_manifest_is_usable_at(
            &manifest,
            temp.path(),
            platform
        ));
        manifest = valid;
        manifest.path = temp.path().join("outside-browser");
        fs::write(&manifest.path, b"binary").expect("outside binary");
        ensure_binary_permissions(&manifest.path).expect("outside permissions");
        assert!(!util::chromium_manifest_is_usable_at(
            &manifest,
            temp.path(),
            platform
        ));
    }

    #[test]
    fn refresh_policy_uses_last_successful_check_and_rejects_future_timestamps() {
        let now = Utc::now();
        let mut manifest = util::ChromiumManifest {
            installed_at: Some((now - chrono::Duration::days(10)).to_rfc3339()),
            last_checked_at: Some((now - chrono::Duration::hours(1)).to_rfc3339()),
            version: None,
            platform: None,
            artifact: None,
            download_url: None,
            path: PathBuf::new(),
        };
        let interval = Duration::from_secs(DEFAULT_UPDATE_CHECK_INTERVAL_SECS);
        assert!(!manifest_refresh_due_at(&manifest, now, interval));
        manifest.last_checked_at = Some((now - chrono::Duration::hours(25)).to_rfc3339());
        assert!(manifest_refresh_due_at(&manifest, now, interval));
        manifest.last_checked_at = Some((now + chrono::Duration::hours(1)).to_rfc3339());
        assert!(manifest_refresh_due_at(&manifest, now, interval));
        manifest.last_checked_at = None;
        manifest.installed_at = None;
        assert!(manifest_refresh_due_at(&manifest, now, interval));
    }

    #[test]
    fn process_singleflight_is_nonblocking_and_releases_on_drop() {
        let _test_lock = INSTALL_TEST_LOCK.lock().expect("test lock");
        INSTALL_IN_PROGRESS.store(false, Ordering::Release);
        let first = try_acquire_install_singleflight().expect("first installer");
        assert!(try_acquire_install_singleflight().is_none());
        drop(first);
        assert!(try_acquire_install_singleflight().is_some());
        INSTALL_IN_PROGRESS.store(false, Ordering::Release);
    }

    #[test]
    fn interprocess_install_lock_wait_is_bounded() {
        let _test_lock = INSTALL_TEST_LOCK.lock().expect("test lock");
        let temp = tempfile::TempDir::new().expect("tempdir");
        let lock_path = temp.path().join("install.lock");
        let holder = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .expect("lock file");
        FileExt::lock_exclusive(&holder).expect("hold lock");
        let started = Instant::now();
        let error = acquire_install_lock(&lock_path, Duration::from_millis(25))
            .err()
            .expect("contended lock must time out");
        assert!(error.to_string().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        FileExt::unlock(&holder).expect("unlock holder");
    }

    #[test]
    fn interrupted_install_restores_rollback_directory() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let install_dir = temp.path().join("bin/chromium");
        let backup_dir = temp.path().join("bin/chromium.rollback");
        fs::create_dir_all(&backup_dir).expect("backup directory");
        fs::write(backup_dir.join("sentinel"), b"previous").expect("backup sentinel");

        recover_interrupted_install(&install_dir).expect("recover interrupted install");

        assert_eq!(
            fs::read(install_dir.join("sentinel")).expect("restored sentinel"),
            b"previous"
        );
        assert!(!backup_dir.exists());
    }

    #[test]
    fn chromium_version_comparison_is_numeric_and_rejects_malformed_values() {
        assert_eq!(
            compare_chromium_versions("124.0.1", "123.999.999"),
            Some(CmpOrdering::Greater)
        );
        assert_eq!(
            compare_chromium_versions("123.0", "123"),
            Some(CmpOrdering::Equal)
        );
        assert_eq!(
            compare_chromium_versions("122.9", "123.0"),
            Some(CmpOrdering::Less)
        );
        assert_eq!(compare_chromium_versions("123.beta", "123.0"), None);
        assert_eq!(compare_chromium_versions("", "123.0"), None);
    }

    #[test]
    fn staging_guard_removes_abandoned_install_tree() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let staging = temp.path().join("chromium.incoming");
        fs::create_dir_all(&staging).expect("staging directory");
        fs::write(staging.join("partial"), b"partial").expect("partial artifact");

        drop(StagingDirGuard {
            path: staging.clone(),
        });

        assert!(!staging.exists());
    }

    #[test]
    fn rollback_restores_previous_tree_and_removes_failed_promotion() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let install_dir = temp.path().join("chromium");
        let backup_dir = temp.path().join("chromium.rollback");
        fs::create_dir_all(&install_dir).expect("promoted install");
        fs::write(install_dir.join("sentinel"), b"failed").expect("failed sentinel");
        fs::create_dir_all(&backup_dir).expect("rollback install");
        fs::write(backup_dir.join("sentinel"), b"previous").expect("previous sentinel");

        rollback_promoted_install(&install_dir, &backup_dir, true).expect("rollback");

        assert_eq!(
            fs::read(install_dir.join("sentinel")).expect("restored sentinel"),
            b"previous"
        );
        assert!(!backup_dir.exists());
        assert!(!temp.path().join("chromium.failed").exists());
    }

    #[test]
    fn rollback_without_previous_tree_removes_failed_promotion() {
        let temp = tempfile::TempDir::new().expect("tempdir");
        let install_dir = temp.path().join("chromium");
        let backup_dir = temp.path().join("chromium.rollback");
        fs::create_dir_all(&install_dir).expect("promoted install");
        fs::write(install_dir.join("sentinel"), b"failed").expect("failed sentinel");

        rollback_promoted_install(&install_dir, &backup_dir, false).expect("rollback");

        assert!(!install_dir.exists());
        assert!(!backup_dir.exists());
        assert!(!temp.path().join("chromium.failed").exists());
    }
}
