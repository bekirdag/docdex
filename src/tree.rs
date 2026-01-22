use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const UNLIMITED_DEPTH: usize = usize::MAX;

const DEFAULT_EXCLUDES: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".bun",
    ".yarn",
    ".pnpm-store",
    "dist",
    "build",
    "out",
    "lib-cov",
    "coverage",
    ".nyc_output",
    "logs",
    "target",
    "bin",
    "obj",
    "vendor",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    ".idea",
    ".vscode",
    ".cache",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".vercel",
    ".serverless",
    ".terraform",
    ".gradle",
    ".m2",
    ".cargo",
    "Pods",
    "DerivedData",
    ".parcel-cache",
    ".tmp",
    ".temp",
    "tmp",
];

#[derive(Clone, Debug)]
pub struct TreeOptions {
    pub max_depth: Option<usize>,
    pub dirs_only: bool,
    pub include_hidden: bool,
    pub extra_excludes: Vec<String>,
}

impl Default for TreeOptions {
    fn default() -> Self {
        Self {
            max_depth: None,
            dirs_only: false,
            include_hidden: false,
            extra_excludes: Vec::new(),
        }
    }
}

pub struct TreeOutput {
    pub root: PathBuf,
    pub tree: String,
    pub excludes: Vec<String>,
}

pub fn render_tree(root: &Path, options: &TreeOptions) -> Result<TreeOutput> {
    let root = root
        .canonicalize()
        .map_err(|err| anyhow!("resolve tree root {}: {err}", root.display()))?;
    if !root.is_dir() {
        return Err(anyhow!("tree root is not a directory"));
    }
    let max_depth = options.max_depth.unwrap_or(UNLIMITED_DEPTH);
    let excludes = build_excludes(options);
    let root_label = root
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| root.display().to_string());
    let mut out = String::new();
    out.push_str(&root_label);
    out.push('\n');
    render_children(&root, "", 0, max_depth, options, &excludes, &mut out)?;
    let mut exclude_list: Vec<String> = excludes.into_iter().collect();
    exclude_list.sort();
    Ok(TreeOutput {
        root,
        tree: out,
        excludes: exclude_list,
    })
}

fn build_excludes(options: &TreeOptions) -> HashSet<String> {
    let mut excludes = HashSet::new();
    for name in DEFAULT_EXCLUDES {
        excludes.insert((*name).to_string());
    }
    for extra in options.extra_excludes.iter() {
        let trimmed = extra.trim();
        if !trimmed.is_empty() {
            excludes.insert(trimmed.to_string());
        }
    }
    excludes
}

fn render_children(
    dir: &Path,
    prefix: &str,
    depth: usize,
    max_depth: usize,
    options: &TreeOptions,
    excludes: &HashSet<String>,
    out: &mut String,
) -> Result<()> {
    if depth >= max_depth {
        return Ok(());
    }
    let mut entries = collect_children(dir, options, excludes)?;
    if entries.is_empty() {
        return Ok(());
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    let last_index = entries.len().saturating_sub(1);
    for (idx, entry) in entries.into_iter().enumerate() {
        let is_last = idx == last_index;
        let connector = if is_last { "└──" } else { "├──" };
        let next_prefix = if is_last {
            format!("{prefix}    ")
        } else {
            format!("{prefix}│   ")
        };
        if let Some(target) = entry.symlink_target.as_ref() {
            out.push_str(&format!(
                "{prefix}{connector} {} -> {}\n",
                entry.name,
                target.display()
            ));
        } else {
            out.push_str(&format!("{prefix}{connector} {}\n", entry.name));
        }
        if entry.is_dir {
            render_children(
                &entry.path,
                &next_prefix,
                depth + 1,
                max_depth,
                options,
                excludes,
                out,
            )?;
        }
    }
    Ok(())
}

struct ChildEntry {
    path: PathBuf,
    name: String,
    is_dir: bool,
    symlink_target: Option<PathBuf>,
}

fn collect_children(
    dir: &Path,
    options: &TreeOptions,
    excludes: &HashSet<String>,
) -> Result<Vec<ChildEntry>> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let name = file_name.to_string_lossy().to_string();
        if !options.include_hidden && name.starts_with('.') {
            continue;
        }
        if excludes.contains(&name) {
            continue;
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        let file_type = metadata.file_type();
        let is_dir = path.is_dir();
        let is_file = path.is_file();
        let is_symlink = file_type.is_symlink();
        if is_dir || (!options.dirs_only && is_file) {
            let symlink_target = if is_symlink {
                fs::read_link(&path).ok()
            } else {
                None
            };
            entries.push(ChildEntry {
                path,
                name,
                is_dir,
                symlink_target,
            });
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use tempfile::TempDir;

    fn write_file(path: &Path) {
        let _ = File::create(path).unwrap();
    }

    #[test]
    fn render_tree_excludes_defaults() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("src")).unwrap();
        write_file(&root.join("src").join("lib.rs"));
        write_file(&root.join("README.md"));
        fs::create_dir(root.join(".git")).unwrap();
        fs::create_dir(root.join("target")).unwrap();

        let output = render_tree(root, &TreeOptions::default()).unwrap();
        let root_label = root
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| root.display().to_string());
        let expected = format!("{root_label}\n├── README.md\n└── src\n    └── lib.rs\n");
        assert_eq!(output.tree, expected);
    }

    #[test]
    fn render_tree_dirs_only() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("src")).unwrap();
        write_file(&root.join("README.md"));

        let options = TreeOptions {
            dirs_only: true,
            ..TreeOptions::default()
        };
        let output = render_tree(root, &options).unwrap();
        let root_label = root
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| root.display().to_string());
        let expected = format!("{root_label}\n└── src\n");
        assert_eq!(output.tree, expected);
    }

    #[test]
    fn render_tree_max_depth_zero() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join("src")).unwrap();
        let options = TreeOptions {
            max_depth: Some(0),
            ..TreeOptions::default()
        };
        let output = render_tree(root, &options).unwrap();
        let root_label = root
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| root.display().to_string());
        assert_eq!(output.tree, format!("{root_label}\n"));
    }

    #[test]
    fn render_tree_include_hidden() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        fs::create_dir(root.join(".hidden")).unwrap();
        let options = TreeOptions {
            include_hidden: true,
            ..TreeOptions::default()
        };
        let output = render_tree(root, &options).unwrap();
        let root_label = root
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| root.display().to_string());
        let expected = format!("{root_label}\n└── .hidden\n");
        assert_eq!(output.tree, expected);
    }
}
