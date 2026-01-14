use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const FETCHER_NAME: &str = "playwright_fetch.js";
const INSTALLER_NAME: &str = "playwright_install.js";
const FETCHER_SCRIPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/npm/lib/playwright_fetch.js"
));
const INSTALLER_SCRIPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/npm/lib/playwright_install.js"
));

pub fn ensure_playwright_fetcher_script() -> Result<PathBuf> {
    ensure_script(FETCHER_NAME, FETCHER_SCRIPT)
}

pub fn ensure_playwright_installer_script() -> Result<PathBuf> {
    ensure_script(INSTALLER_NAME, INSTALLER_SCRIPT)
}

fn ensure_script(name: &str, contents: &str) -> Result<PathBuf> {
    let base_dir =
        crate::state_paths::default_state_base_dir().context("resolve docdex state dir")?;
    let scripts_dir = base_dir.join("bin").join("playwright-scripts");
    fs::create_dir_all(&scripts_dir)
        .with_context(|| format!("create playwright scripts dir {}", scripts_dir.display()))?;
    let path = scripts_dir.join(name);
    if needs_write(&path, contents) {
        fs::write(&path, contents)
            .with_context(|| format!("write playwright script {}", path.display()))?;
    }
    Ok(path)
}

fn needs_write(path: &Path, contents: &str) -> bool {
    match fs::read_to_string(path) {
        Ok(existing) => existing != contents,
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use tempfile::TempDir;

    struct EnvGuard {
        home: Option<std::ffi::OsString>,
        userprofile: Option<std::ffi::OsString>,
    }

    impl EnvGuard {
        fn new(temp: &Path) -> Self {
            let home = std::env::var_os("HOME");
            let userprofile = std::env::var_os("USERPROFILE");
            std::env::set_var("HOME", temp);
            std::env::set_var("USERPROFILE", temp);
            Self { home, userprofile }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            restore_env("HOME", self.home.take());
            restore_env("USERPROFILE", self.userprofile.take());
        }
    }

    fn restore_env(key: &str, value: Option<std::ffi::OsString>) {
        if let Some(value) = value {
            std::env::set_var(key, value);
        } else {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn ensure_playwright_fetcher_script_writes_bundle() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = TempDir::new()?;
        let _env = EnvGuard::new(temp.path());
        let path = ensure_playwright_fetcher_script()?;
        assert!(path.ends_with("playwright_fetch.js"));
        let contents = fs::read_to_string(&path)?;
        assert!(contents.contains("playwright fetch failed"));
        Ok(())
    }

    #[test]
    fn ensure_playwright_installer_script_writes_bundle() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        let temp = TempDir::new()?;
        let _env = EnvGuard::new(temp.path());
        let path = ensure_playwright_installer_script()?;
        assert!(path.ends_with("playwright_install.js"));
        let contents = fs::read_to_string(&path)?;
        assert!(contents.contains("playwright CLI not found"));
        Ok(())
    }
}
