use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};
use tracing::warn;
use walkdir::WalkDir;

#[derive(Clone)]
pub struct IgnoreMatcher {
    root: PathBuf,
    matcher: Gitignore,
}

impl IgnoreMatcher {
    pub fn is_ignored(&self, path: &Path, is_dir: bool) -> bool {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        self.matcher
            .matched_path_or_any_parents(rel, is_dir)
            .is_ignore()
    }
}

pub fn build_ignore_matcher(root: &Path, excluded_dirs: &[String]) -> Option<IgnoreMatcher> {
    let mut builder = GitignoreBuilder::new(root);
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
        if file_name != ".gitignore" && file_name != ".docdexignore" {
            continue;
        }
        if let Some(err) = builder.add(entry.path()) {
            warn!(
                target: "docdexd",
                error = ?err,
                file = %entry.path().display(),
                "failed to load ignore file"
            );
        } else {
            added = true;
        }
    }

    if !added {
        return None;
    }

    let matcher = match builder.build() {
        Ok(matcher) => matcher,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "failed to build ignore matcher"
            );
            return None;
        }
    };
    Some(IgnoreMatcher {
        root: root.to_path_buf(),
        matcher,
    })
}
