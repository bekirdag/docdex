use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("src"))?;
    fs::create_dir_all(repo_root.join("pkg"))?;
    fs::create_dir_all(repo_root.join("web"))?;
    fs::create_dir_all(repo_root.join("web").join("var"))?;
    fs::create_dir_all(repo_root.join("web").join("joined"))?;
    fs::create_dir_all(repo_root.join("web").join("tpl"))?;
    fs::create_dir_all(repo_root.join("web").join("opts"))?;
    fs::create_dir_all(repo_root.join("cmd"))?;
    fs::create_dir_all(repo_root.join("pkggo"))?;

    fs::write(
        repo_root.join("src").join("lib.rs"),
        r#"
mod util;
const DATA: &str = include_str!("data.txt");
pub fn lib() {}
"#,
    )?;
    fs::write(repo_root.join("src").join("data.txt"), "hello")?;
    fs::write(
        repo_root.join("src").join("util.rs"),
        r#"
pub fn util() {}
"#,
    )?;

    fs::write(
        repo_root.join("pkg").join("main.py"),
        r#"
import pkg.util
import importlib
import importlib.util
importlib.import_module("pkg.dynamic")
BASE = "pkg"
importlib.import_module(BASE + ".extra")
importlib.util.spec_from_file_location("pkg.spec", "pkg/spec.py")
"#,
    )?;
    fs::write(
        repo_root.join("pkg").join("util.py"),
        r#"
def helper():
    return 1
"#,
    )?;
    fs::write(
        repo_root.join("pkg").join("dynamic.py"),
        r#"
def dyn():
    return 2
"#,
    )?;
    fs::write(
        repo_root.join("pkg").join("extra.py"),
        r#"
def extra():
    return 3
"#,
    )?;
    fs::write(
        repo_root.join("pkg").join("spec.py"),
        r#"
def spec():
    return 4
"#,
    )?;

    fs::write(
        repo_root.join("web").join("app.js"),
        r#"
import { foo } from "./util";
const req = require("./req");
const concat = require("./concat" + "");
const base = "./var";
const req2 = require(base + "/extra");
const joined = require(path.join("./joined", "file"));
const viaDirname = require(path.join(__dirname, "dirfile.js"));
const templated = require(`./tpl/${name}.js`);
const choice = getChoice();
const opt = require(`./opts/${choice}.js`);
const missing = require(`./missing/${name}.js`);
import("./dyn");
console.log(foo);
"#,
    )?;
    fs::write(
        repo_root.join("web").join("util.js"),
        r#"
export const foo = 1;
"#,
    )?;
    fs::write(
        repo_root.join("web").join("override.js"),
        r#"
export const foo = 2;
"#,
    )?;
    fs::write(
        repo_root.join("web").join("req.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("dirfile.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("concat.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("var").join("extra.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("joined").join("file.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("tpl").join("only.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("opts").join("alpha.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("opts").join("beta.js"),
        r#"
module.exports = {};
"#,
    )?;
    fs::write(
        repo_root.join("web").join("hints.js"),
        r#"
export const hint = 1;
"#,
    )?;
    fs::write(
        repo_root.join("web").join("trace.js"),
        r#"
export const trace = 1;
"#,
    )?;
    fs::write(
        repo_root.join("web").join("dyn.js"),
        r#"
export const dyn = 1;
"#,
    )?;
    fs::write(
        repo_root.join("web").join("use.ts"),
        r#"
import type { Config } from "./types";
"#,
    )?;
    fs::write(
        repo_root.join("web").join("types.ts"),
        r#"
export interface Config { name: string }
"#,
    )?;

    fs::write(
        repo_root.join("go.mod"),
        r#"
module example.com/app
"#,
    )?;
    fs::write(
        repo_root.join("cmd").join("main.go"),
        r#"
package main

import "example.com/app/pkggo"

func main() { _ = pkggo.X }
"#,
    )?;
    fs::write(
        repo_root.join("pkggo").join("pkg.go"),
        r#"
package pkggo

const X = 1
"#,
    )?;

    fs::write(
        repo_root.join("docdex.import_map.json"),
        r#"
{
  "edges": [
    { "source": "web/app.js", "target": "web/hints.js", "kind": "import" }
  ],
  "mappings": [
    { "source": "web/app.js", "spec": "./opts/*.js", "targets": ["./opts/*.js"], "expand": true, "kind": "require" },
    { "source": "web/app.js", "spec": "./util", "target": "./override.js", "kind": "import", "override": true }
  ]
}
"#,
    )?;
    fs::write(
        repo_root.join("docdex.import_traces.jsonl"),
        r#"
{ "source": "web/app.js", "target": "web/trace.js", "kind": "import" }
"#,
    )?;

    Ok(())
}

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .env("DOCDEX_STATE_DIR", state_root)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn inspect_repo_state(state_root: &Path, repo_root: &Path) -> Result<Value, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .args([
            "repo",
            "inspect",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd repo inspect exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn resolve_repo_state_root(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let payload = inspect_repo_state(state_root, repo_root)?;
    let root = payload
        .get("statePaths")
        .and_then(|value| value.get("repoStateRoot"))
        .and_then(|value| value.as_str())
        .ok_or("missing statePaths.repoStateRoot")?;
    Ok(PathBuf::from(root))
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct ImpactEdge {
    source: String,
    target: String,
}

fn load_edges(path: &Path) -> Result<Vec<ImpactEdge>, Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    if value.is_array() {
        if let Ok(edges) = serde_json::from_value(value.clone()) {
            return Ok(edges);
        }
        let mut merged: BTreeSet<ImpactEdge> = BTreeSet::new();
        let entries: Vec<Value> = serde_json::from_value(value)?;
        for entry in entries {
            if let Some(edges_value) = entry.get("edges") {
                let entry_edges: Vec<ImpactEdge> = serde_json::from_value(edges_value.clone())?;
                for edge in entry_edges {
                    merged.insert(edge);
                }
            }
        }
        return Ok(merged.into_iter().collect());
    }
    if let Some(edges_value) = value.get("edges") {
        return Ok(serde_json::from_value(edges_value.clone())?);
    }
    if let Some(graphs_value) = value.get("graphs") {
        let mut merged: BTreeSet<ImpactEdge> = BTreeSet::new();
        let entries: Vec<Value> = serde_json::from_value(graphs_value.clone())?;
        for entry in entries {
            if let Some(edges_value) = entry.get("edges") {
                let entry_edges: Vec<ImpactEdge> = serde_json::from_value(edges_value.clone())?;
                for edge in entry_edges {
                    merged.insert(edge);
                }
            }
        }
        return Ok(merged.into_iter().collect());
    }
    Err("impact_graph.json missing edges".into())
}

struct ImpactDiagnostics {
    unresolved_total: i64,
    unresolved_sample: Vec<String>,
}

fn read_diagnostics(
    path: &Path,
    source: &str,
) -> Result<Option<ImpactDiagnostics>, Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let mut entries: Vec<Value> = Vec::new();
    if value.is_array() {
        if let Some(list) = value.as_array() {
            if list.first().and_then(|item| item.get("source")).is_some() {
                entries.extend(list.iter().cloned());
            } else {
                entries.extend(list.iter().cloned());
            }
        }
    } else if let Some(graphs_value) = value.get("graphs") {
        if let Some(list) = graphs_value.as_array() {
            entries.extend(list.iter().cloned());
        }
    } else {
        return Ok(None);
    }
    for entry in entries {
        if entry.get("edges").is_none() {
            continue;
        }
        let entry_source = entry.get("source").and_then(|v| v.as_str());
        if entry_source != Some(source) {
            continue;
        }
        let diag = entry.get("diagnostics").cloned();
        let Some(diag) = diag else {
            return Ok(None);
        };
        let unresolved_total = diag
            .get("unresolvedImportsTotal")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        let unresolved_sample = diag
            .get("unresolvedImportsSample")
            .and_then(|v| v.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        return Ok(Some(ImpactDiagnostics {
            unresolved_total,
            unresolved_sample,
        }));
    }
    Ok(None)
}

fn assert_normalized_edge_kinds(path: &Path) -> Result<(), Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let mut edge_values: Vec<Value> = Vec::new();
    if value.is_array() {
        if let Some(edges) = value.as_array() {
            if edges.first().and_then(|item| item.get("source")).is_some() {
                edge_values.extend(edges.iter().cloned());
            } else {
                for entry in edges {
                    if let Some(edges_value) = entry.get("edges") {
                        if let Some(list) = edges_value.as_array() {
                            edge_values.extend(list.iter().cloned());
                        }
                    }
                }
            }
        }
    } else if let Some(edges_value) = value.get("edges") {
        if let Some(list) = edges_value.as_array() {
            edge_values.extend(list.iter().cloned());
        }
    } else if let Some(graphs_value) = value.get("graphs") {
        if let Some(list) = graphs_value.as_array() {
            for entry in list {
                if let Some(edges_value) = entry.get("edges") {
                    if let Some(edges) = edges_value.as_array() {
                        edge_values.extend(edges.iter().cloned());
                    }
                }
            }
        }
    }
    for edge in edge_values {
        let kind = edge.get("kind").and_then(|v| v.as_str());
        if let Some(kind) = kind {
            if !matches!(kind, "import" | "include" | "require") {
                return Err(format!("unexpected edge kind {kind}").into());
            }
        }
    }
    Ok(())
}

#[test]
fn impact_graph_from_indexing_contains_import_edges() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_fixture_repo(repo.path())?;

    run_docdex(
        state_root.path(),
        [
            "index",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--enable-symbol-extraction=true",
        ],
    )?;

    let repo_state_root = resolve_repo_state_root(state_root.path(), repo.path())?;
    let edges = load_edges(&repo_state_root.join("impact_graph.json"))?;
    let mut set: BTreeSet<(String, String)> = BTreeSet::new();
    for edge in edges {
        set.insert((edge.source, edge.target));
    }

    let expected = [
        ("src/lib.rs", "src/util.rs"),
        ("src/lib.rs", "src/data.txt"),
        ("pkg/main.py", "pkg/util.py"),
        ("pkg/main.py", "pkg/dynamic.py"),
        ("pkg/main.py", "pkg/extra.py"),
        ("pkg/main.py", "pkg/spec.py"),
        ("web/app.js", "web/override.js"),
        ("web/app.js", "web/req.js"),
        ("web/app.js", "web/concat.js"),
        ("web/app.js", "web/var/extra.js"),
        ("web/app.js", "web/joined/file.js"),
        ("web/app.js", "web/dirfile.js"),
        ("web/app.js", "web/tpl/only.js"),
        ("web/app.js", "web/opts/alpha.js"),
        ("web/app.js", "web/opts/beta.js"),
        ("web/app.js", "web/hints.js"),
        ("web/app.js", "web/trace.js"),
        ("web/app.js", "web/dyn.js"),
        ("web/use.ts", "web/types.ts"),
        ("cmd/main.go", "pkggo/pkg.go"),
    ];
    for (source, target) in expected {
        let key = (source.to_string(), target.to_string());
        if !set.contains(&key) {
            return Err(format!("missing impact edge {source} -> {target}").into());
        }
    }
    if set.contains(&("web/app.js".to_string(), "web/util.js".to_string())) {
        return Err("expected import map override to suppress web/app.js -> web/util.js".into());
    }

    assert_normalized_edge_kinds(&repo_state_root.join("impact_graph.json"))?;

    let diagnostics = read_diagnostics(&repo_state_root.join("impact_graph.json"), "web/app.js")?
        .ok_or("missing diagnostics for web/app.js")?;
    if diagnostics.unresolved_total < 1 {
        return Err("expected unresolved import diagnostics for web/app.js".into());
    }

    Ok(())
}
