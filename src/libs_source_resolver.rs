use crate::libs::{LibSource, LibSourcesFile};
use anyhow::Result;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LibDocSourceType {
    NodePackageJson,
    PythonRequirementsTxt,
    PythonPyprojectToml,
    RustCargoToml,
    GoMod,
    ConfiguredLocalFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LibDocSourceEligibility {
    Eligible,
    Missing,
    Unsupported,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedLibDocSource {
    #[serde(rename = "type")]
    pub source_type: LibDocSourceType,
    pub library: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub paths: Vec<String>,
    pub eligibility: LibDocSourceEligibility,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LibDocSourceDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LibsSourceResolution {
    pub sources: Vec<ResolvedLibDocSource>,
    pub diagnostics: Vec<LibDocSourceDiagnostic>,
}

#[derive(Debug, Clone)]
pub struct LibsSourceResolver {
    repo_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SourceKey {
    source_type: LibDocSourceType,
    library: String,
    version: Option<String>,
    eligibility: LibDocSourceEligibility,
    reason: Option<String>,
}

impl LibsSourceResolver {
    pub fn new(repo_root: PathBuf) -> Self {
        Self { repo_root }
    }

    pub fn resolve(
        &self,
        explicit_sources: Option<&LibSourcesFile>,
    ) -> Result<LibsSourceResolution> {
        if !self.repo_root.is_dir() {
            anyhow::bail!("repo root is not a directory: {}", self.repo_root.display());
        }

        let mut sources: BTreeMap<SourceKey, BTreeSet<String>> = BTreeMap::new();
        let mut diagnostics: Vec<LibDocSourceDiagnostic> = Vec::new();

        if let Some(file) = explicit_sources {
            for src in file.sources.iter() {
                let library = src.library.trim().to_string();
                let version = src
                    .version
                    .as_ref()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());
                let resolved = resolve_repo_relative(&self.repo_root, &src.path);
                let path_str = display_path(&self.repo_root, &resolved);

                if library.is_empty() {
                    diagnostics.push(LibDocSourceDiagnostic {
                        code: "configured_source_invalid".to_string(),
                        message: "configured libs source has empty `library`".to_string(),
                        path: Some(path_str.clone()),
                        library: None,
                    });
                    insert_source(
                        &mut sources,
                        LibDocSourceType::ConfiguredLocalFile,
                        library,
                        version,
                        LibDocSourceEligibility::Invalid,
                        Some("library must not be empty".to_string()),
                        path_str,
                    );
                    continue;
                }

                match fs::metadata(&resolved) {
                    Ok(meta) if meta.is_file() => insert_source(
                        &mut sources,
                        LibDocSourceType::ConfiguredLocalFile,
                        library,
                        version,
                        LibDocSourceEligibility::Eligible,
                        None,
                        path_str,
                    ),
                    Ok(_) => {
                        diagnostics.push(LibDocSourceDiagnostic {
                            code: "configured_source_not_a_file".to_string(),
                            message: "configured libs source path is not a file".to_string(),
                            path: Some(path_str.clone()),
                            library: Some(library.clone()),
                        });
                        insert_source(
                            &mut sources,
                            LibDocSourceType::ConfiguredLocalFile,
                            library,
                            version,
                            LibDocSourceEligibility::Invalid,
                            Some("path is not a file".to_string()),
                            path_str,
                        );
                    }
                    Err(err) => {
                        diagnostics.push(LibDocSourceDiagnostic {
                            code: "configured_source_missing".to_string(),
                            message: format!("configured libs source missing: {err}"),
                            path: Some(path_str.clone()),
                            library: Some(library.clone()),
                        });
                        insert_source(
                            &mut sources,
                            LibDocSourceType::ConfiguredLocalFile,
                            library,
                            version,
                            LibDocSourceEligibility::Missing,
                            Some("configured docs file missing".to_string()),
                            path_str,
                        );
                    }
                }
            }
        }

        // Manifest discovery (best-effort; never fails overall resolution).
        self.discover_package_json(&mut sources, &mut diagnostics);
        self.discover_requirements_txt(&mut sources, &mut diagnostics);
        self.discover_pyproject_toml(&mut sources, &mut diagnostics);
        self.discover_cargo_toml(&mut sources, &mut diagnostics);
        self.discover_go_mod(&mut sources, &mut diagnostics);

        let sources = sources
            .into_iter()
            .map(|(key, paths)| ResolvedLibDocSource {
                source_type: key.source_type,
                library: key.library,
                version: key.version,
                paths: paths.into_iter().collect(),
                eligibility: key.eligibility,
                reason: key.reason,
            })
            .collect();

        Ok(LibsSourceResolution {
            sources,
            diagnostics,
        })
    }

    fn discover_package_json(
        &self,
        sources: &mut BTreeMap<SourceKey, BTreeSet<String>>,
        diagnostics: &mut Vec<LibDocSourceDiagnostic>,
    ) {
        let path = self.repo_root.join("package.json");
        let Some(raw) = read_optional_text(&path, "package.json", &self.repo_root, diagnostics)
        else {
            return;
        };
        let manifest_path = display_path(&self.repo_root, &path);

        let parsed: serde_json::Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(err) => {
                diagnostics.push(LibDocSourceDiagnostic {
                    code: "manifest_parse_error".to_string(),
                    message: format!("failed to parse package.json: {err}"),
                    path: Some(manifest_path),
                    library: None,
                });
                return;
            }
        };

        let mut deps: BTreeMap<String, String> = BTreeMap::new();
        for key in [
            "dependencies",
            "optionalDependencies",
            "peerDependencies",
            "devDependencies",
        ] {
            let Some(obj) = parsed.get(key).and_then(|v| v.as_object()) else {
                continue;
            };
            for (name, version) in obj.iter() {
                if deps.contains_key(name) {
                    continue;
                }
                let Some(version) = version.as_str() else {
                    continue;
                };
                let version = version.trim();
                if version.is_empty() {
                    continue;
                }
                deps.insert(name.to_string(), version.to_string());
            }
        }

        for (name, version) in deps {
            insert_source(
                sources,
                LibDocSourceType::NodePackageJson,
                name,
                Some(version),
                LibDocSourceEligibility::Eligible,
                None,
                manifest_path.clone(),
            );
        }
    }

    fn discover_requirements_txt(
        &self,
        sources: &mut BTreeMap<SourceKey, BTreeSet<String>>,
        diagnostics: &mut Vec<LibDocSourceDiagnostic>,
    ) {
        let path = self.repo_root.join("requirements.txt");
        let Some(raw) = read_optional_text(&path, "requirements.txt", &self.repo_root, diagnostics)
        else {
            return;
        };
        let manifest_path = display_path(&self.repo_root, &path);

        for (idx, line) in raw.lines().enumerate() {
            let trimmed = strip_line_comment(line).trim();
            if trimmed.is_empty() {
                continue;
            }
            let lowered = trimmed.to_ascii_lowercase();
            if lowered.starts_with('-')
                || lowered.starts_with("git+")
                || lowered.contains("://")
                || trimmed.starts_with("./")
                || trimmed.starts_with("../")
            {
                diagnostics.push(LibDocSourceDiagnostic {
                    code: "requirements_unsupported".to_string(),
                    message: format!("unsupported requirements entry at line {}", idx + 1),
                    path: Some(manifest_path.clone()),
                    library: None,
                });
                continue;
            }

            match parse_python_requirement(trimmed) {
                Some((name, version)) => insert_source(
                    sources,
                    LibDocSourceType::PythonRequirementsTxt,
                    name,
                    version,
                    LibDocSourceEligibility::Eligible,
                    None,
                    manifest_path.clone(),
                ),
                None => diagnostics.push(LibDocSourceDiagnostic {
                    code: "requirements_parse_skipped".to_string(),
                    message: format!("could not parse requirement at line {}", idx + 1),
                    path: Some(manifest_path.clone()),
                    library: None,
                }),
            }
        }
    }

    fn discover_pyproject_toml(
        &self,
        sources: &mut BTreeMap<SourceKey, BTreeSet<String>>,
        diagnostics: &mut Vec<LibDocSourceDiagnostic>,
    ) {
        let path = self.repo_root.join("pyproject.toml");
        let Some(raw) = read_optional_text(&path, "pyproject.toml", &self.repo_root, diagnostics)
        else {
            return;
        };
        let manifest_path = display_path(&self.repo_root, &path);

        for dep in parse_pep621_dependencies(&raw) {
            if let Some((name, version)) = parse_python_requirement(dep.as_str()) {
                insert_source(
                    sources,
                    LibDocSourceType::PythonPyprojectToml,
                    name,
                    version,
                    LibDocSourceEligibility::Eligible,
                    None,
                    manifest_path.clone(),
                );
            } else {
                diagnostics.push(LibDocSourceDiagnostic {
                    code: "pyproject_dependency_unsupported".to_string(),
                    message: format!("unsupported dependency entry: {dep}"),
                    path: Some(manifest_path.clone()),
                    library: None,
                });
            }
        }

        // Poetry: keep only simple string values; treat table-style as unsupported.
        for (name, version, unsupported_reason) in parse_poetry_dependencies(&raw) {
            match unsupported_reason {
                None => insert_source(
                    sources,
                    LibDocSourceType::PythonPyprojectToml,
                    name,
                    version,
                    LibDocSourceEligibility::Eligible,
                    None,
                    manifest_path.clone(),
                ),
                Some(reason) => {
                    diagnostics.push(LibDocSourceDiagnostic {
                        code: "poetry_dependency_unsupported".to_string(),
                        message: format!("unsupported poetry dependency: {reason}"),
                        path: Some(manifest_path.clone()),
                        library: Some(name.clone()),
                    });
                    insert_source(
                        sources,
                        LibDocSourceType::PythonPyprojectToml,
                        name,
                        None,
                        LibDocSourceEligibility::Unsupported,
                        Some(reason),
                        manifest_path.clone(),
                    );
                }
            }
        }
    }

    fn discover_cargo_toml(
        &self,
        sources: &mut BTreeMap<SourceKey, BTreeSet<String>>,
        diagnostics: &mut Vec<LibDocSourceDiagnostic>,
    ) {
        let path = self.repo_root.join("Cargo.toml");
        let Some(raw) = read_optional_text(&path, "Cargo.toml", &self.repo_root, diagnostics)
        else {
            return;
        };
        let manifest_path = display_path(&self.repo_root, &path);

        let mut in_deps = false;
        for line in raw.lines() {
            let trimmed = strip_line_comment(line).trim();
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_deps = trimmed == "[dependencies]" || trimmed == "[workspace.dependencies]";
                continue;
            }
            if !in_deps || trimmed.is_empty() {
                continue;
            }
            let Some((name_raw, rhs_raw)) = trimmed.split_once('=') else {
                continue;
            };
            let name = name_raw.trim().to_string();
            let rhs = rhs_raw.trim();
            if name.is_empty() {
                continue;
            }

            if rhs.starts_with('"') || rhs.starts_with('\'') {
                let v = rhs.trim_end_matches(',').trim();
                let version = v.trim_matches('"').trim_matches('\'').trim().to_string();
                insert_source(
                    sources,
                    LibDocSourceType::RustCargoToml,
                    name,
                    Some(version).filter(|s| !s.is_empty()),
                    LibDocSourceEligibility::Eligible,
                    None,
                    manifest_path.clone(),
                );
                continue;
            }

            if rhs.starts_with('{') {
                if rhs.contains("git") || rhs.contains("path") {
                    insert_source(
                        sources,
                        LibDocSourceType::RustCargoToml,
                        name.clone(),
                        None,
                        LibDocSourceEligibility::Unsupported,
                        Some("non-registry dependency (git/path)".to_string()),
                        manifest_path.clone(),
                    );
                    diagnostics.push(LibDocSourceDiagnostic {
                        code: "cargo_dependency_unsupported".to_string(),
                        message: "unsupported Cargo.toml dependency (git/path)".to_string(),
                        path: Some(manifest_path.clone()),
                        library: Some(name),
                    });
                    continue;
                }
                let version_re =
                    Regex::new(r#"version\s*=\s*("([^"]+)"|'([^']+)')"#).expect("regex");
                let version = version_re
                    .captures(rhs)
                    .and_then(|caps| {
                        caps.get(2)
                            .or_else(|| caps.get(3))
                            .map(|m| m.as_str().to_string())
                    })
                    .filter(|s| !s.trim().is_empty());
                insert_source(
                    sources,
                    LibDocSourceType::RustCargoToml,
                    name,
                    version,
                    LibDocSourceEligibility::Eligible,
                    None,
                    manifest_path.clone(),
                );
                continue;
            }
        }
    }

    fn discover_go_mod(
        &self,
        sources: &mut BTreeMap<SourceKey, BTreeSet<String>>,
        diagnostics: &mut Vec<LibDocSourceDiagnostic>,
    ) {
        let path = self.repo_root.join("go.mod");
        let Some(raw) = read_optional_text(&path, "go.mod", &self.repo_root, diagnostics) else {
            return;
        };
        let manifest_path = display_path(&self.repo_root, &path);

        let mut in_block = false;
        for line in raw.lines() {
            let trimmed = strip_line_comment(line).trim();
            if trimmed.is_empty() {
                continue;
            }
            if trimmed == "require (" {
                in_block = true;
                continue;
            }
            if in_block && trimmed == ")" {
                in_block = false;
                continue;
            }

            let item = if in_block {
                trimmed
            } else if trimmed.starts_with("require ") {
                trimmed.trim_start_matches("require ").trim()
            } else {
                continue;
            };

            if let Some((name, version)) = parse_go_mod_req(item) {
                insert_source(
                    sources,
                    LibDocSourceType::GoMod,
                    name,
                    Some(version),
                    LibDocSourceEligibility::Eligible,
                    None,
                    manifest_path.clone(),
                );
            }
        }
    }
}

pub fn resolution_to_sources(
    resolution: &LibsSourceResolution,
    include_configured: bool,
) -> LibSourcesFile {
    let mut sources: Vec<LibSource> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for entry in &resolution.sources {
        if entry.eligibility != LibDocSourceEligibility::Eligible {
            continue;
        }
        if !include_configured && entry.source_type == LibDocSourceType::ConfiguredLocalFile {
            continue;
        }
        let source_label = source_label_for(entry.source_type);
        for path in &entry.paths {
            let path = path.trim();
            if path.is_empty() {
                continue;
            }
            let key = format!(
                "{}|{}|{}|{}",
                entry.library.trim(),
                entry.version.as_deref().unwrap_or(""),
                source_label,
                path
            );
            if !seen.insert(key) {
                continue;
            }
            sources.push(LibSource {
                library: entry.library.clone(),
                version: entry.version.clone(),
                source: source_label.to_string(),
                path: PathBuf::from(path),
                title: None,
            });
        }
    }
    LibSourcesFile { sources }
}

fn source_label_for(source_type: LibDocSourceType) -> &'static str {
    match source_type {
        LibDocSourceType::NodePackageJson => "package.json",
        LibDocSourceType::PythonRequirementsTxt => "requirements.txt",
        LibDocSourceType::PythonPyprojectToml => "pyproject.toml",
        LibDocSourceType::RustCargoToml => "cargo.toml",
        LibDocSourceType::GoMod => "go.mod",
        LibDocSourceType::ConfiguredLocalFile => "configured",
    }
}

fn insert_source(
    sources: &mut BTreeMap<SourceKey, BTreeSet<String>>,
    source_type: LibDocSourceType,
    library: String,
    version: Option<String>,
    eligibility: LibDocSourceEligibility,
    reason: Option<String>,
    path: String,
) {
    let key = SourceKey {
        source_type,
        library,
        version,
        eligibility,
        reason,
    };
    sources.entry(key).or_default().insert(path);
}

fn read_optional_text(
    path: &Path,
    label: &str,
    repo_root: &Path,
    diagnostics: &mut Vec<LibDocSourceDiagnostic>,
) -> Option<String> {
    if !path.exists() {
        return None;
    }
    match fs::read_to_string(path) {
        Ok(raw) => Some(raw),
        Err(err) => {
            diagnostics.push(LibDocSourceDiagnostic {
                code: "manifest_read_error".to_string(),
                message: format!("failed to read {label}: {err}"),
                path: Some(display_path(repo_root, path)),
                library: None,
            });
            None
        }
    }
}

fn resolve_repo_relative(repo_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(path)
    }
}

fn display_path(repo_root: &Path, path: &Path) -> String {
    path.strip_prefix(repo_root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn strip_line_comment(line: &str) -> &str {
    match line.find('#') {
        None => line,
        Some(idx) => &line[..idx],
    }
}

fn parse_python_requirement(value: &str) -> Option<(String, Option<String>)> {
    let before_marker = value.split(';').next().unwrap_or(value).trim();
    if before_marker.is_empty() {
        return None;
    }
    let mut name = String::new();
    for c in before_marker.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            name.push(c);
        } else {
            break;
        }
    }
    let name = name.trim().to_string();
    if name.is_empty() {
        return None;
    }

    let mut remainder = before_marker[name.len()..].trim_start();
    if remainder.starts_with('[') {
        if let Some(end) = remainder.find(']') {
            remainder = remainder[(end + 1)..].trim_start();
        }
    }
    let remainder = remainder.trim();
    let version = if remainder.is_empty() {
        None
    } else {
        Some(remainder.to_string())
    };
    Some((name, version))
}

fn parse_pep621_dependencies(toml_text: &str) -> Vec<String> {
    let mut in_project = false;
    let mut in_deps = false;
    let mut buf = String::new();
    let quoted = Regex::new(r#""([^"]+)"|'([^']+)'"#).expect("regex");
    let mut out = Vec::new();

    for line in toml_text.lines() {
        let trimmed = strip_line_comment(line).trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_project = trimmed == "[project]";
            in_deps = false;
            buf.clear();
            continue;
        }
        if !in_project {
            continue;
        }
        if !in_deps {
            if trimmed.starts_with("dependencies") && trimmed.contains('[') {
                in_deps = true;
                buf.push_str(trimmed);
                buf.push('\n');
                if trimmed.contains(']') {
                    in_deps = false;
                }
            }
        } else {
            buf.push_str(trimmed);
            buf.push('\n');
            if trimmed.contains(']') {
                in_deps = false;
            }
        }
        if !in_deps && !buf.is_empty() {
            out.extend(quoted.captures_iter(&buf).filter_map(|caps| {
                caps.get(1)
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str().to_string())
            }));
            buf.clear();
        }
    }
    out
}

fn parse_poetry_dependencies(toml_text: &str) -> Vec<(String, Option<String>, Option<String>)> {
    let mut out = Vec::new();
    let mut in_deps = false;

    for line in toml_text.lines() {
        let trimmed = strip_line_comment(line).trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_deps = trimmed == "[tool.poetry.dependencies]";
            continue;
        }
        if !in_deps || trimmed.is_empty() {
            continue;
        }
        let Some((name_raw, rhs_raw)) = trimmed.split_once('=') else {
            continue;
        };
        let name = name_raw.trim().to_string();
        let rhs = rhs_raw.trim();
        if name.is_empty() || name == "python" {
            continue;
        }

        if rhs.starts_with('"') || rhs.starts_with('\'') {
            let v = rhs.trim_end_matches(',').trim();
            let version = v.trim_matches('"').trim_matches('\'').trim().to_string();
            out.push((name, Some(version).filter(|s| !s.is_empty()), None));
            continue;
        }

        if rhs.starts_with('{') {
            out.push((
                name,
                None,
                Some("table-style poetry dependency (unsupported)".to_string()),
            ));
            continue;
        }
    }
    out
}

fn parse_go_mod_req(value: &str) -> Option<(String, String)> {
    let mut parts = value.split_whitespace();
    let name = parts.next()?.trim();
    let version = parts.next()?.trim();
    if name.is_empty() || version.is_empty() {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn deterministic_order_is_stable_across_calls() {
        let repo = TempDir::new().expect("tmp repo");
        fs::write(
            repo.path().join("package.json"),
            r#"{ "dependencies": { "zeta": "1.0.0", "alpha": "^2.0.0" } }"#,
        )
        .expect("write package.json");
        fs::write(repo.path().join("requirements.txt"), "requests==2.31.0\n").expect("write");
        fs::write(
            repo.path().join("go.mod"),
            "module x\nrequire github.com/a/b v1.0.0\n",
        )
        .expect("write");

        let resolver = LibsSourceResolver::new(repo.path().to_path_buf());
        let a = resolver.resolve(None).expect("resolve");
        let b = resolver.resolve(None).expect("resolve again");
        assert_eq!(a.sources, b.sources);
        assert_eq!(a.diagnostics, b.diagnostics);
    }

    #[test]
    fn parses_package_json_dependencies() {
        let repo = TempDir::new().expect("tmp repo");
        fs::write(
            repo.path().join("package.json"),
            r#"{ "dependencies": { "react": "^18.0.0" }, "devDependencies": { "vitest": "1.0.0" } }"#,
        )
        .expect("write package.json");
        let resolver = LibsSourceResolver::new(repo.path().to_path_buf());
        let result = resolver.resolve(None).expect("resolve");
        assert!(result.sources.iter().any(|s| {
            s.source_type == LibDocSourceType::NodePackageJson
                && s.library == "react"
                && s.version.as_deref() == Some("^18.0.0")
        }));
    }

    #[test]
    fn marks_cargo_git_deps_as_unsupported() {
        let repo = TempDir::new().expect("tmp repo");
        fs::write(
            repo.path().join("Cargo.toml"),
            r#"
            [package]
            name = "demo"

            [dependencies]
            fancy = { git = "https://example.com/fancy.git" }
            "#,
        )
        .expect("write Cargo.toml");
        let resolver = LibsSourceResolver::new(repo.path().to_path_buf());
        let result = resolver.resolve(None).expect("resolve");
        assert!(result.sources.iter().any(|s| {
            s.source_type == LibDocSourceType::RustCargoToml
                && s.library == "fancy"
                && s.eligibility == LibDocSourceEligibility::Unsupported
        }));
        assert!(result
            .diagnostics
            .iter()
            .any(|d| d.code == "cargo_dependency_unsupported"
                && d.library.as_deref() == Some("fancy")));
    }
}
