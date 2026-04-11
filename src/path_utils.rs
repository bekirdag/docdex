use std::path::{Component, Path, PathBuf};

pub fn path_to_forward_slash_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn normalize_repo_relative_path(path: &Path) -> Option<PathBuf> {
    if path.is_absolute() {
        return None;
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => clean.push(part),
            _ => return None,
        }
    }
    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

pub fn normalize_repo_relative_path_from_str(input: &str) -> Option<PathBuf> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    normalize_repo_relative_path(Path::new(trimmed))
}

pub fn normalize_repo_relative_string(input: &str) -> Option<String> {
    normalize_repo_relative_path_from_str(input).map(|path| path_to_forward_slash_string(&path))
}

pub fn normalize_repo_relative_string_from_path(path: &Path) -> Option<String> {
    normalize_repo_relative_path(path).map(|clean| path_to_forward_slash_string(&clean))
}

#[cfg(test)]
mod tests {
    use super::{
        normalize_repo_relative_path_from_str, normalize_repo_relative_string,
        normalize_repo_relative_string_from_path,
    };
    use std::path::{Path, PathBuf};

    #[test]
    fn normalize_repo_relative_path_rejects_empty() {
        assert_eq!(normalize_repo_relative_path_from_str(""), None);
        assert_eq!(normalize_repo_relative_path_from_str("   "), None);
    }

    #[test]
    fn normalize_repo_relative_path_rejects_absolute_and_parent_segments() {
        assert_eq!(normalize_repo_relative_path_from_str("/abs/path"), None);
        assert_eq!(normalize_repo_relative_path_from_str("../escape.txt"), None);
        assert_eq!(
            normalize_repo_relative_path_from_str("foo/../bar.txt"),
            None
        );
    }

    #[test]
    fn normalize_repo_relative_path_cleans_current_dir() {
        assert_eq!(
            normalize_repo_relative_path_from_str("foo/./bar.txt"),
            Some(PathBuf::from("foo/bar.txt"))
        );
    }

    #[test]
    fn normalize_repo_relative_string_uses_forward_slashes() {
        assert_eq!(
            normalize_repo_relative_string("foo\\bar.txt"),
            Some("foo/bar.txt".to_string())
        );
    }

    #[test]
    fn normalize_repo_relative_string_from_path_uses_forward_slashes() {
        assert_eq!(
            normalize_repo_relative_string_from_path(Path::new("foo/bar.txt")),
            Some("foo/bar.txt".to_string())
        );
    }
}
