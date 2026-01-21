use ignore::gitignore::Gitignore;
use std::path::{Path, PathBuf};
use tracing::warn;
use walkdir::WalkDir;

#[derive(Clone)]
pub struct IgnoreMatcher {
    matchers: Vec<ScopedIgnore>,
}

#[derive(Clone)]
struct ScopedIgnore {
    root: PathBuf,
    matcher: Gitignore,
    depth: usize,
    priority: u8,
}

impl IgnoreMatcher {
    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        let mut ignored: Option<bool> = None;
        for scoped in &self.matchers {
            if !path.starts_with(&scoped.root) {
                continue;
            }
            let matched = scoped.matcher.matched_path_or_any_parents(path, is_dir);
            if matched.is_none() {
                continue;
            }
            if matched.is_whitelist() {
                ignored = Some(false);
            } else if matched.is_ignore() {
                ignored = Some(true);
            }
        }
        ignored.unwrap_or(false)
    }
}

pub fn build_ignore_matcher(root: &Path, excluded_dirs: &[String]) -> Option<IgnoreMatcher> {
    let mut matchers = Vec::new();
    let mut added = false;
    let walker = WalkDir::new(root).into_iter().filter_entry(|entry| {
        if entry.depth() == 0 {
            return true;
        }
        if !entry.file_type().is_dir() {
            return true;
        }
        let name = entry.file_name().to_string_lossy().to_lowercase();
        !excluded_dirs.iter().any(|excluded| excluded == &name)
    });

    for entry in walker.filter_map(|entry| entry.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let file_name = entry.file_name().to_string_lossy();
        let is_docdexignore = file_name == ".docdexignore";
        if !is_docdexignore && file_name != ".gitignore" {
            continue;
        }
        let (matcher, err) = Gitignore::new(entry.path());
        if let Some(err) = err {
            warn!(
                target: "docdexd",
                error = ?err,
                file = %entry.path().display(),
                "failed to load ignore file"
            );
        }
        let scope_root = entry
            .path()
            .parent()
            .unwrap_or(root)
            .to_path_buf();
        let depth = scope_root
            .strip_prefix(root)
            .map(|path| path.components().count())
            .unwrap_or(0);
        let priority = if is_docdexignore { 1 } else { 0 };
        matchers.push(ScopedIgnore {
            root: scope_root,
            matcher,
            depth,
            priority,
        });
        added = true;
    }

    if !added {
        return None;
    }

    matchers.sort_by(|a, b| {
        a.depth
            .cmp(&b.depth)
            .then(a.priority.cmp(&b.priority))
            .then_with(|| a.root.cmp(&b.root))
    });
    Some(IgnoreMatcher {
        matchers,
    })
}
