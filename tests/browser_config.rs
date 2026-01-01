use docdexd::config;
use once_cell::sync::Lazy;
use std::ffi::OsString;
use std::path::Path;
use std::sync::Mutex;
use tempfile::TempDir;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }

    fn unset(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = self.prev.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn touch_file(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).expect("create parent dir");
    std::fs::write(path, b"#!/bin/sh\necho test\n").expect("write file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(perms.mode() | 0o111);
        std::fs::set_permissions(path, perms).expect("chmod");
    }
}

#[test]
#[cfg(not(target_os = "windows"))]
fn config_persists_detected_browser_path() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let bin_dir = temp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    let chrome_path = bin_dir.join("google-chrome");
    touch_file(&chrome_path);

    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _path_guard = EnvGuard::set("PATH", bin_dir.to_string_lossy().as_ref());
    let _auto_install = EnvGuard::set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let _env_browser = EnvGuard::unset("DOCDEX_WEB_BROWSER");
    let _chrome_path_env = EnvGuard::unset("DOCDEX_CHROME_PATH");
    let _chrome_path_env_alias = EnvGuard::unset("CHROME_PATH");

    let config_path = temp.path().join("docdex.toml");
    let config = config::load_config_from_path(&config_path).expect("load config");
    assert_eq!(
        config.web.scraper.chrome_binary_path.as_ref(),
        Some(&chrome_path)
    );
    assert_eq!(config.web.scraper.browser_kind.as_deref(), Some("chrome"));

    let reload = config::load_config_from_path(&config_path).expect("reload config");
    assert_eq!(
        reload.web.scraper.chrome_binary_path.as_ref(),
        Some(&chrome_path)
    );
}
