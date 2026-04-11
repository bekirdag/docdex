use super::*;

pub(super) fn impact_state_root(state_dir: &Path) -> PathBuf {
    if state_dir.file_name().and_then(|name| name.to_str()) == Some("index") {
        return state_dir.parent().unwrap_or(state_dir).to_path_buf();
    }
    state_dir.to_path_buf()
}

pub(crate) fn impact_graph_path(state_dir: &Path) -> PathBuf {
    impact_state_root(state_dir).join("impact_graph.json")
}

pub(crate) fn import_traces_state_path(state_dir: &Path) -> PathBuf {
    impact_state_root(state_dir).join(IMPORT_TRACES_STATE_FILE)
}

pub(crate) fn extract_import_edges(
    repo_root: &Path,
    state_dir: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(language) = language_for_path(rel_path) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    match language {
        SourceLanguage::Markdown
        | SourceLanguage::Java
        | SourceLanguage::CSharp
        | SourceLanguage::C
        | SourceLanguage::Cpp
        | SourceLanguage::Php
        | SourceLanguage::Kotlin
        | SourceLanguage::Swift
        | SourceLanguage::Ruby
        | SourceLanguage::Lua
        | SourceLanguage::Dart => ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        },
        SourceLanguage::Rust => extract_rust_import_edges(repo_root, rel_path, content),
        SourceLanguage::Python => {
            extract_python_import_edges(repo_root, state_dir, rel_path, content)
        }
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            extract_js_ts_import_edges(repo_root, state_dir, rel_path, content, language)
        }
        SourceLanguage::Go => extract_go_import_edges(repo_root, state_dir, rel_path, content),
    }
}

#[derive(Debug, Clone)]
enum StringEval {
    Exact(String),
    Pattern(StringPattern),
    Unknown,
}

#[derive(Debug, Clone)]
struct StringPattern {
    parts: Vec<String>,
    anchored_start: bool,
    anchored_end: bool,
}

#[derive(Debug, Clone)]
enum ImportPath {
    Exact(String),
    Pattern(StringPattern),
}

#[derive(Debug, Clone)]
struct ImportRef {
    path: ImportPath,
    kind: &'static str,
    language: SourceLanguage,
}

#[derive(Debug, Clone)]
struct ResolvedImportTarget {
    target: String,
    kind: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ImpactEdgeBuildResult {
    pub(crate) edges: Vec<ImpactGraphEdge>,
    pub(crate) diagnostics: Option<ImpactDiagnostics>,
}

impl StringPattern {
    fn normalize(mut self) -> Self {
        self.parts.retain(|part| !part.is_empty());
        if self.parts.is_empty() {
            self.anchored_start = false;
            self.anchored_end = false;
        }
        self
    }

    fn is_useful(&self) -> bool {
        self.parts.iter().any(|part| !part.is_empty())
    }

    fn first_part(&self) -> Option<&str> {
        self.parts.first().map(|part| part.as_str())
    }

    fn last_part(&self) -> Option<&str> {
        self.parts.last().map(|part| part.as_str())
    }
}

#[derive(Debug, Default, Clone)]
struct ImportHints {
    edges: Vec<ImportMapEdge>,
    mappings: Vec<ImportMapMapping>,
    traces: Vec<ImportTraceEntry>,
}

struct HintEdgeSet {
    edges: Vec<ImpactGraphEdge>,
    override_targets: HashSet<String>,
}

#[derive(Debug, Default, Clone)]
struct ImportMapFile {
    edges: Vec<ImportMapEdge>,
    mappings: Vec<ImportMapMapping>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportMapFileRaw {
    #[serde(default)]
    edges: Vec<ImportMapEdgeRaw>,
    #[serde(default)]
    mappings: Vec<ImportMapMappingRaw>,
}

#[derive(Debug, Clone)]
struct ImportMapEdge {
    source: String,
    target: String,
    kind: Option<String>,
    override_edge: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportMapEdgeRaw {
    source: String,
    target: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default, rename = "override")]
    override_edge: bool,
}

#[derive(Debug, Clone)]
struct ImportMapMapping {
    source: Option<String>,
    spec: String,
    targets: Vec<String>,
    kind: Option<String>,
    expand: bool,
    override_edge: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportMapMappingRaw {
    #[serde(default)]
    source: Option<String>,
    spec: String,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    targets: Vec<String>,
    #[serde(default)]
    expand: bool,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default, rename = "override")]
    override_edge: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportTraceEntry {
    source: String,
    target: String,
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Debug, Clone)]
struct RepoFileIndex {
    js_ts: Vec<String>,
    python: Vec<String>,
    all: Vec<String>,
    js_ts_count: usize,
    python_count: usize,
    all_count: usize,
    limit: usize,
}

impl RepoFileIndex {
    fn js_ts_over_limit(&self) -> bool {
        self.js_ts_count > self.limit
    }

    fn python_over_limit(&self) -> bool {
        self.python_count > self.limit
    }

    fn all_over_limit(&self) -> bool {
        self.all_count > self.limit
    }
}

#[derive(Debug, Default, Clone)]
struct ImportHintCacheEntry {
    map_mtime: Option<SystemTime>,
    repo_trace_mtime: Option<SystemTime>,
    state_trace_mtime: Option<SystemTime>,
    traces_enabled: bool,
    hints: ImportHints,
}

type ImportHintCacheKey = (PathBuf, PathBuf);

static IMPORT_HINT_CACHE: Lazy<Mutex<HashMap<ImportHintCacheKey, ImportHintCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static REPO_FILE_CACHE: Lazy<Mutex<HashMap<PathBuf, RepoFileIndex>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn extract_js_ts_import_edges(
    repo_root: &Path,
    state_dir: &Path,
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(language, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let mut imports: Vec<ImportRef> = Vec::new();
    let mut bindings: HashMap<String, StringEval> = HashMap::new();
    seed_js_ts_bindings(rel_path, &mut bindings);
    collect_js_ts_imports(content, root, language, &mut imports, &mut bindings);
    build_edges(
        repo_root,
        state_dir,
        rel_path,
        imports,
        resolve_js_ts_import,
    )
}

fn extract_python_import_edges(
    repo_root: &Path,
    state_dir: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(SourceLanguage::Python, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let mut imports: Vec<ImportRef> = Vec::new();
    let mut bindings: HashMap<String, StringEval> = HashMap::new();
    collect_python_imports(content, root, &mut imports, &mut bindings);
    build_edges(
        repo_root,
        state_dir,
        rel_path,
        imports,
        resolve_python_import,
    )
}

fn extract_rust_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(SourceLanguage::Rust, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let mut edges = Vec::new();
    collect_rust_import_edges(repo_root, rel_path, content, root, &mut edges);
    ImpactEdgeBuildResult {
        edges,
        diagnostics: None,
    }
}

fn extract_go_import_edges(
    repo_root: &Path,
    state_dir: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(SourceLanguage::Go, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let module_path = go_module_path(repo_root);
    let mut imports: Vec<ImportRef> = Vec::new();
    collect_go_imports(content, root, &mut imports);
    build_edges_with_context(
        repo_root,
        state_dir,
        rel_path,
        imports,
        |root, file, import_path| {
            resolve_go_import(root, file, import_path, module_path.as_deref())
        },
    )
}

fn seed_js_ts_bindings(rel_path: &str, bindings: &mut HashMap<String, StringEval>) {
    if !bindings.contains_key("__dirname") {
        bindings.insert("__dirname".to_string(), StringEval::Exact(".".to_string()));
    }
    if !bindings.contains_key("__filename") {
        if let Some(file_name) = Path::new(rel_path)
            .file_name()
            .and_then(|name| name.to_str())
        {
            bindings.insert(
                "__filename".to_string(),
                StringEval::Exact(file_name.to_string()),
            );
        }
    }
}

fn parse_tree(
    language: SourceLanguage,
    rel_path: &str,
    content: &str,
) -> Option<tree_sitter::Tree> {
    let ts_language = tree_sitter_language(language, rel_path)?;
    let mut parser = Parser::new();
    parser.set_language(&ts_language).ok()?;
    parser.parse(content, None)
}

fn tree_sitter_language(language: SourceLanguage, rel_path: &str) -> Option<tree_sitter::Language> {
    match language {
        SourceLanguage::Rust => Some(ts_rust::language()),
        SourceLanguage::Python => Some(ts_python::language()),
        SourceLanguage::JavaScript => Some(ts_javascript::language()),
        SourceLanguage::TypeScript => {
            if rel_path.to_lowercase().ends_with(".tsx") {
                Some(ts_typescript::language_tsx())
            } else {
                Some(ts_typescript::language_typescript())
            }
        }
        SourceLanguage::Go => Some(ts_go::language()),
        SourceLanguage::Java => Some(ts_java::language()),
        SourceLanguage::CSharp => Some(ts_c_sharp::language()),
        SourceLanguage::C => Some(ts_c::language()),
        SourceLanguage::Cpp => Some(ts_cpp::language()),
        SourceLanguage::Php => Some(ts_php::language_php()),
        SourceLanguage::Kotlin => Some(ts_kotlin::language()),
        SourceLanguage::Swift => Some(ts_swift::language()),
        SourceLanguage::Ruby => Some(ts_ruby::language()),
        SourceLanguage::Lua => Some(ts_lua::language()),
        SourceLanguage::Dart => Some(ts_dart::language()),
        SourceLanguage::Markdown => None,
    }
}

fn collect_js_ts_imports(
    content: &str,
    node: Node,
    language: SourceLanguage,
    imports: &mut Vec<ImportRef>,
    bindings: &mut HashMap<String, StringEval>,
) {
    match node.kind() {
        "import_statement" | "export_statement" => {
            if let Some(source) = node.child_by_field_name("source") {
                if let Some(eval) = string_literal_eval(content, source) {
                    if let Some(path) = eval_to_import_path(eval) {
                        let kind = "import";
                        imports.push(ImportRef {
                            path,
                            kind,
                            language,
                        });
                    }
                }
            }
        }
        "call_expression" => {
            if let Some(name) = call_function_name(content, node) {
                if let Some(kind) = js_dynamic_import_kind(name.as_str()) {
                    if let Some(arg) =
                        first_argument_import_path(content, node, &|id| bindings.get(id).cloned())
                    {
                        imports.push(ImportRef {
                            path: arg,
                            kind,
                            language,
                        });
                    }
                }
            }
        }
        "import_call" => {
            if let Some(arg) =
                first_argument_import_path(content, node, &|id| bindings.get(id).cloned())
            {
                imports.push(ImportRef {
                    path: arg,
                    kind: "import",
                    language,
                });
            }
        }
        "variable_declarator" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.kind() == "identifier" {
                    if let Some(value_node) = node.child_by_field_name("value") {
                        let eval = static_string_eval_with_resolver(content, value_node, &|id| {
                            bindings.get(id).cloned()
                        });
                        if is_meaningful_eval(&eval) {
                            if let Some(name) = node_text(content, name_node)
                                .map(|text| text.trim().to_string())
                                .filter(|text| !text.is_empty())
                            {
                                bindings.insert(name, eval);
                            }
                        }
                    }
                }
            }
        }
        "assignment_expression" => {
            if assignment_operator_is_eq(content, node) {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "identifier" {
                        if let Some(right) = node.child_by_field_name("right") {
                            let eval = static_string_eval_with_resolver(content, right, &|id| {
                                bindings.get(id).cloned()
                            });
                            if is_meaningful_eval(&eval) {
                                if let Some(name) = node_text(content, left)
                                    .map(|text| text.trim().to_string())
                                    .filter(|text| !text.is_empty())
                                {
                                    bindings.insert(name, eval);
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_js_ts_imports(content, child, language, imports, bindings);
    }
}

fn collect_python_imports(
    content: &str,
    node: Node,
    imports: &mut Vec<ImportRef>,
    bindings: &mut HashMap<String, StringEval>,
) {
    match node.kind() {
        "import_statement" => {
            let text = node_text(content, node).unwrap_or_default();
            let list = text.trim().strip_prefix("import ").unwrap_or(text.trim());
            for raw in list.split(',') {
                let entry = raw.trim();
                if entry.is_empty() {
                    continue;
                }
                let name = entry.split_whitespace().next().unwrap_or(entry);
                imports.push(ImportRef {
                    path: ImportPath::Exact(name.to_string()),
                    kind: "import",
                    language: SourceLanguage::Python,
                });
            }
        }
        "import_from_statement" => {
            let text = node_text(content, node).unwrap_or_default();
            if let Some(from_idx) = text.find("from ") {
                let after_from = &text[from_idx + 5..];
                let module = after_from
                    .splitn(2, "import")
                    .next()
                    .unwrap_or(after_from)
                    .trim();
                if !module.is_empty() {
                    imports.push(ImportRef {
                        path: ImportPath::Exact(module.to_string()),
                        kind: "import",
                        language: SourceLanguage::Python,
                    });
                }
            }
        }
        "call" => {
            if let Some(name) = call_function_name(content, node) {
                if let Some((kind, arg_index)) = python_dynamic_import_spec(name.as_str()) {
                    if cfg!(test)
                        && std::env::var("DOCDEX_DEBUG_IMPORTS")
                            .map(|value| value.trim() == "1")
                            .unwrap_or(false)
                    {
                        eprintln!("[impact] python dynamic call {name}");
                    }
                    if let Some(arg) = argument_import_path(content, node, arg_index, &|id| {
                        bindings.get(id).cloned()
                    }) {
                        imports.push(ImportRef {
                            path: arg,
                            kind,
                            language: SourceLanguage::Python,
                        });
                    }
                }
            }
        }
        "assignment" => {
            if let Some((name, value_node)) = python_assignment_parts(content, node) {
                let eval = static_string_eval_with_resolver(content, value_node, &|id| {
                    bindings.get(id).cloned()
                });
                if is_meaningful_eval(&eval) {
                    bindings.insert(name, eval);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_imports(content, child, imports, bindings);
    }
}

fn collect_rust_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
    node: Node,
    edges: &mut Vec<ImpactGraphEdge>,
) {
    if node.kind() == "mod_item" {
        let has_body = node.child_by_field_name("body").is_some();
        if !has_body {
            if let Some(name) = node_name(content, node, "name") {
                if let Some(target) = resolve_rust_mod(repo_root, rel_path, &name) {
                    edges.push(ImpactGraphEdge {
                        source: rel_path.to_string(),
                        target,
                        kind: Some("import".to_string()),
                    });
                }
            }
        }
    } else if node.kind() == "use_declaration" {
        let text = node_text(content, node).unwrap_or_default();
        for path in extract_rust_use_paths(text) {
            if let Some(target) = resolve_rust_use(repo_root, rel_path, &path) {
                edges.push(ImpactGraphEdge {
                    source: rel_path.to_string(),
                    target,
                    kind: Some("import".to_string()),
                });
            }
        }
    } else if node.kind() == "macro_invocation" {
        if let Some(name) = rust_macro_name(content, node) {
            if matches!(name.as_str(), "include" | "include_str" | "include_bytes") {
                if let Some(arg) = first_string_literal_in_node(content, node) {
                    if let Some(target) = resolve_rust_include(repo_root, rel_path, &arg) {
                        edges.push(ImpactGraphEdge {
                            source: rel_path.to_string(),
                            target,
                            kind: Some("include".to_string()),
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_import_edges(repo_root, rel_path, content, child, edges);
    }
}

fn collect_go_imports(content: &str, node: Node, imports: &mut Vec<ImportRef>) {
    if node.kind() == "import_spec" {
        if let Some(path) = node.child_by_field_name("path") {
            if let Some(value) = string_literal_value(content, path) {
                imports.push(ImportRef {
                    path: ImportPath::Exact(value),
                    kind: "import",
                    language: SourceLanguage::Go,
                });
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_imports(content, child, imports);
    }
}

fn build_edges<F>(
    repo_root: &Path,
    state_dir: &Path,
    rel_path: &str,
    imports: Vec<ImportRef>,
    resolver: F,
) -> ImpactEdgeBuildResult
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    build_edges_with_context(repo_root, state_dir, rel_path, imports, resolver)
}

fn build_edges_with_context<F>(
    repo_root: &Path,
    state_dir: &Path,
    rel_path: &str,
    imports: Vec<ImportRef>,
    resolver: F,
) -> ImpactEdgeBuildResult
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let mut edges: BTreeSet<ImpactGraphEdge> = BTreeSet::new();
    let hints = import_hints_for_repo(repo_root, state_dir);
    let hint_edges = hint_edges_for_source(repo_root, rel_path, &hints, &resolver);
    for edge in hint_edges.edges {
        edges.insert(edge);
    }
    let override_targets = hint_edges.override_targets;
    let mut unresolved = Vec::new();
    for import_ref in imports {
        if let Some(targets) =
            resolve_import_ref(repo_root, rel_path, &import_ref, &hints, &resolver)
        {
            for resolved in targets {
                if resolved.target == rel_path {
                    continue;
                }
                if override_targets.contains(&resolved.target) {
                    continue;
                }
                let kind = resolved
                    .kind
                    .clone()
                    .or_else(|| Some(normalize_edge_kind(import_ref.kind).to_string()));
                edges.insert(ImpactGraphEdge {
                    source: rel_path.to_string(),
                    target: resolved.target,
                    kind,
                });
            }
        } else if should_report_unresolved(&import_ref) {
            unresolved.push(import_ref);
        }
    }
    if !unresolved.is_empty() {
        let samples: Vec<String> = unresolved
            .iter()
            .take(UNRESOLVED_IMPORT_SAMPLE_LIMIT)
            .map(|item| format_import_path(&item.path))
            .collect();
        info!(
            target: "docdexd",
            file = %rel_path,
            count = unresolved.len(),
            sample = ?samples,
            "unresolved imports skipped"
        );
    }
    let diagnostics = if unresolved.is_empty() {
        None
    } else {
        let samples = unresolved
            .iter()
            .take(UNRESOLVED_IMPORT_SAMPLE_LIMIT)
            .map(|item| format_import_path(&item.path))
            .collect();
        Some(ImpactDiagnostics {
            unresolved_imports_total: unresolved.len(),
            unresolved_imports_sample: samples,
        })
    };
    ImpactEdgeBuildResult {
        edges: edges.into_iter().collect(),
        diagnostics,
    }
}

fn resolve_import_ref<F>(
    repo_root: &Path,
    rel_path: &str,
    import_ref: &ImportRef,
    hints: &ImportHints,
    resolver: &F,
) -> Option<Vec<ResolvedImportTarget>>
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let debug_imports = cfg!(test)
        && std::env::var("DOCDEX_DEBUG_IMPORTS")
            .map(|value| value.trim() == "1")
            .unwrap_or(false);
    let (overrides, fallbacks) =
        resolve_import_map_matches(repo_root, rel_path, import_ref, hints, resolver);
    if !overrides.is_empty() {
        if debug_imports {
            eprintln!(
                "[impact] {rel_path} import {} -> overrides {}",
                format_import_path(&import_ref.path),
                overrides.len()
            );
        }
        return Some(overrides);
    }
    match &import_ref.path {
        ImportPath::Exact(path) => {
            if let Some(target) = resolver(repo_root, rel_path, path) {
                if debug_imports {
                    eprintln!(
                        "[impact] {rel_path} import {} -> {target}",
                        format_import_path(&import_ref.path)
                    );
                }
                return Some(vec![ResolvedImportTarget { target, kind: None }]);
            }
            if !fallbacks.is_empty() {
                if debug_imports {
                    eprintln!(
                        "[impact] {rel_path} import {} -> fallback {}",
                        format_import_path(&import_ref.path),
                        fallbacks.len()
                    );
                }
                return Some(fallbacks);
            }
        }
        ImportPath::Pattern(pattern) => {
            if matches!(
                import_ref.language,
                SourceLanguage::JavaScript | SourceLanguage::TypeScript
            ) {
                let targets = resolve_pattern_matches_js_ts(repo_root, rel_path, pattern);
                if !targets.is_empty() {
                    if debug_imports {
                        eprintln!(
                            "[impact] {rel_path} import {} -> {} matches",
                            format_import_path(&import_ref.path),
                            targets.len()
                        );
                    }
                    return Some(
                        targets
                            .into_iter()
                            .map(|target| ResolvedImportTarget { target, kind: None })
                            .collect(),
                    );
                }
            } else if let Some(target) =
                resolve_unique_match(repo_root, rel_path, import_ref, pattern)
            {
                if debug_imports {
                    eprintln!(
                        "[impact] {rel_path} import {} -> {target}",
                        format_import_path(&import_ref.path)
                    );
                }
                return Some(vec![ResolvedImportTarget { target, kind: None }]);
            }
            if !fallbacks.is_empty() {
                if debug_imports {
                    eprintln!(
                        "[impact] {rel_path} import {} -> fallback {}",
                        format_import_path(&import_ref.path),
                        fallbacks.len()
                    );
                }
                return Some(fallbacks);
            }
        }
    }
    if debug_imports {
        eprintln!(
            "[impact] {rel_path} import {} -> unresolved",
            format_import_path(&import_ref.path)
        );
    }
    None
}

fn should_report_unresolved(import_ref: &ImportRef) -> bool {
    match &import_ref.path {
        ImportPath::Pattern(_) => true,
        ImportPath::Exact(value) => match import_ref.language {
            SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
                value.starts_with('.') || value.starts_with('/')
            }
            SourceLanguage::Python => {
                value.starts_with('.')
                    || value.starts_with('/')
                    || value.contains('/')
                    || value.ends_with(".py")
            }
            _ => value.starts_with('.') || value.starts_with('/'),
        },
    }
}

fn hint_edges_for_source<F>(
    repo_root: &Path,
    rel_path: &str,
    hints: &ImportHints,
    resolver: &F,
) -> HintEdgeSet
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let mut edges = Vec::new();
    let mut override_targets = HashSet::new();
    for edge in &hints.edges {
        if edge.source != rel_path {
            continue;
        }
        if let Some(target) = resolve_hint_target(repo_root, rel_path, &edge.target, resolver) {
            let resolved_target = target.clone();
            edges.push(ImpactGraphEdge {
                source: rel_path.to_string(),
                target,
                kind: edge
                    .kind
                    .as_deref()
                    .map(normalize_edge_kind)
                    .map(|kind| kind.to_string()),
            });
            if edge.override_edge {
                override_targets.insert(resolved_target);
            }
        }
    }
    for trace in &hints.traces {
        if trace.source != rel_path {
            continue;
        }
        if let Some(target) = resolve_hint_target(repo_root, rel_path, &trace.target, resolver) {
            edges.push(ImpactGraphEdge {
                source: rel_path.to_string(),
                target,
                kind: trace
                    .kind
                    .as_deref()
                    .map(normalize_edge_kind)
                    .map(|kind| kind.to_string()),
            });
        }
    }
    HintEdgeSet {
        edges,
        override_targets,
    }
}

fn import_hints_for_repo(repo_root: &Path, state_dir: &Path) -> ImportHints {
    let (repo_key, state_key) = import_hint_cache_key(repo_root, state_dir);
    let map_path = repo_key.join(IMPORT_MAP_FILE);
    let repo_trace_path = repo_key.join(IMPORT_TRACES_FILE);
    let state_trace_path = import_traces_state_path(&state_key);
    let map_mtime = file_mtime(&map_path);
    let repo_trace_mtime = file_mtime(&repo_trace_path);
    let state_trace_mtime = file_mtime(&state_trace_path);
    let traces_enabled = import_traces_enabled();
    let mut cache = IMPORT_HINT_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = cache
        .entry((repo_key.clone(), state_key.clone()))
        .or_default();
    if entry.map_mtime != map_mtime {
        let map = load_import_map(&repo_key, &map_path);
        entry.hints.edges = map.edges;
        entry.hints.mappings = map.mappings;
        entry.map_mtime = map_mtime;
    }
    if entry.traces_enabled != traces_enabled {
        entry.hints.traces.clear();
        entry.repo_trace_mtime = None;
        entry.state_trace_mtime = None;
        entry.traces_enabled = traces_enabled;
    }
    if traces_enabled
        && (entry.repo_trace_mtime != repo_trace_mtime
            || entry.state_trace_mtime != state_trace_mtime)
    {
        let mut traces = load_import_traces(&repo_key, &state_trace_path);
        traces.extend(load_import_traces(&repo_key, &repo_trace_path));
        entry.hints.traces = traces;
        entry.repo_trace_mtime = repo_trace_mtime;
        entry.state_trace_mtime = state_trace_mtime;
    }
    entry.hints.clone()
}

fn import_hint_cache_key(repo_root: &Path, state_dir: &Path) -> ImportHintCacheKey {
    let repo_key = canonical_path(repo_root);
    let state_root = impact_state_root(state_dir);
    let state_key = canonical_path(&state_root);
    (repo_key, state_key)
}

fn canonical_repo_root(repo_root: &Path) -> PathBuf {
    canonical_path(repo_root)
}

fn canonical_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
}

fn load_import_map(repo_root: &Path, path: &Path) -> ImportMapFile {
    if !path.is_file() {
        return ImportMapFile::default();
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) => {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = %err,
                "failed to read import map"
            );
            return ImportMapFile::default();
        }
    };
    let parsed: ImportMapFileRaw = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = %err,
                "failed to parse import map"
            );
            return ImportMapFile::default();
        }
    };
    normalize_import_map(repo_root, parsed)
}

fn normalize_import_map(repo_root: &Path, raw: ImportMapFileRaw) -> ImportMapFile {
    let mut edges = Vec::new();
    for entry in raw.edges {
        let source = match normalize_hint_path(repo_root, &entry.source) {
            Some(source) => source,
            None => continue,
        };
        let target = match normalize_hint_path(repo_root, &entry.target) {
            Some(target) => target,
            None => continue,
        };
        edges.push(ImportMapEdge {
            source,
            target,
            kind: entry.kind,
            override_edge: entry.override_edge,
        });
    }
    let mut mappings = Vec::new();
    for entry in raw.mappings {
        let spec = entry.spec.trim().to_string();
        let mut targets = entry.targets;
        if let Some(target) = entry.target {
            targets.push(target);
        }
        let targets: Vec<String> = targets
            .into_iter()
            .map(|target| target.trim().to_string())
            .filter(|target| !target.is_empty())
            .collect();
        if spec.is_empty() || targets.is_empty() {
            continue;
        }
        let source = match entry.source.as_ref() {
            Some(source) => normalize_hint_path(repo_root, source),
            None => None,
        };
        if entry.source.is_some() && source.is_none() {
            continue;
        }
        mappings.push(ImportMapMapping {
            source,
            spec,
            kind: entry.kind,
            targets,
            expand: entry.expand,
            override_edge: entry.override_edge,
        });
    }
    ImportMapFile { edges, mappings }
}

fn load_import_traces(repo_root: &Path, path: &Path) -> Vec<ImportTraceEntry> {
    if !path.is_file() {
        return Vec::new();
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) => {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = %err,
                "failed to read import traces"
            );
            return Vec::new();
        }
    };
    let mut entries = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: ImportTraceEntry = match serde_json::from_str(trimmed) {
            Ok(record) => record,
            Err(err) => {
                warn!(
                    target: "docdexd",
                    path = %path.display(),
                    line = idx + 1,
                    error = %err,
                    "failed to parse import trace"
                );
                continue;
            }
        };
        let source = match normalize_hint_path(repo_root, &record.source) {
            Some(source) => source,
            None => continue,
        };
        let target = match normalize_hint_path(repo_root, &record.target) {
            Some(target) => target,
            None => continue,
        };
        entries.push(ImportTraceEntry {
            source,
            target,
            kind: record.kind,
        });
    }
    entries
}

fn normalize_hint_path(repo_root: &Path, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let path = Path::new(value);
    if path.is_absolute() {
        let rel = path.strip_prefix(repo_root).ok()?;
        return normalize_hint_rel_path(rel);
    }
    normalize_hint_rel_path(path)
}

pub(crate) fn normalize_hint_rel_path(path: &Path) -> Option<String> {
    use std::path::Component;

    if path
        .components()
        .any(|comp| matches!(comp, Component::ParentDir | Component::Prefix(_)))
    {
        return None;
    }
    let mut rel = normalize_rel_path(path);
    while rel.starts_with("./") {
        rel = rel.trim_start_matches("./").to_string();
    }
    if rel.starts_with("../") || rel.is_empty() {
        return None;
    }
    Some(rel)
}

fn resolve_hint_target<F>(
    repo_root: &Path,
    rel_path: &str,
    target: &str,
    resolver: &F,
) -> Option<String>
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    if target.trim().is_empty() {
        return None;
    }
    if let Some(resolved) = resolver(repo_root, rel_path, target) {
        return Some(resolved);
    }
    normalize_hint_path(repo_root, target)
}

fn resolve_hint_pattern(repo_root: &Path, rel_path: &str, pattern: &str) -> Option<String> {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = Path::new(trimmed);
    if path.is_absolute() {
        return normalize_hint_path(repo_root, trimmed);
    }
    if trimmed.starts_with("./") || trimmed.starts_with("../") {
        let base_dir = Path::new(rel_path).parent().unwrap_or(Path::new(""));
        let joined = base_dir.join(trimmed);
        return normalize_hint_rel_path(&joined);
    }
    normalize_hint_rel_path(path)
}

fn resolve_import_map_matches<F>(
    repo_root: &Path,
    rel_path: &str,
    import_ref: &ImportRef,
    hints: &ImportHints,
    resolver: &F,
) -> (Vec<ResolvedImportTarget>, Vec<ResolvedImportTarget>)
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let mut overrides = Vec::new();
    let mut fallbacks = Vec::new();
    let Some(spec) = import_path_glob(&import_ref.path) else {
        return (overrides, fallbacks);
    };
    for mapping in &hints.mappings {
        if let Some(source) = &mapping.source {
            if source != rel_path {
                continue;
            }
        }
        if !glob_matches(&mapping.spec, &spec) {
            continue;
        }
        let targets = resolve_mapping_targets(repo_root, rel_path, mapping, resolver);
        if targets.is_empty() {
            continue;
        }
        if mapping.override_edge {
            overrides.extend(targets);
        } else {
            fallbacks.extend(targets);
        }
    }
    (
        dedupe_resolved_targets(overrides),
        dedupe_resolved_targets(fallbacks),
    )
}

fn resolve_mapping_targets<F>(
    repo_root: &Path,
    rel_path: &str,
    mapping: &ImportMapMapping,
    resolver: &F,
) -> Vec<ResolvedImportTarget>
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let kind = mapping
        .kind
        .as_deref()
        .map(normalize_edge_kind)
        .map(|value| value.to_string());
    let mut resolved = Vec::new();
    for target in &mapping.targets {
        if mapping.expand {
            let matches = expand_import_map_target(repo_root, rel_path, target);
            if matches.is_empty() {
                warn!(
                    target: "docdexd",
                    file = %rel_path,
                    spec = %mapping.spec,
                    target = %target,
                    "import map expansion produced no matches"
                );
            }
            for entry in matches {
                resolved.push(ResolvedImportTarget {
                    target: entry,
                    kind: kind.clone(),
                });
            }
        } else if let Some(target) = resolve_hint_target(repo_root, rel_path, target, resolver) {
            resolved.push(ResolvedImportTarget {
                target,
                kind: kind.clone(),
            });
        } else {
            warn!(
                target: "docdexd",
                file = %rel_path,
                spec = %mapping.spec,
                target = %target,
                "import map target could not be resolved"
            );
        }
    }
    resolved
}

fn expand_import_map_target(repo_root: &Path, rel_path: &str, pattern: &str) -> Vec<String> {
    let Some(pattern) = resolve_hint_pattern(repo_root, rel_path, pattern) else {
        return Vec::new();
    };
    let index = repo_file_index(repo_root);
    if index.all_over_limit() {
        warn!(
            target: "docdexd",
            repo = %repo_root.display(),
            limit = index.limit,
            "import map expansion skipped (repo too large)"
        );
        return Vec::new();
    }
    index
        .all
        .iter()
        .filter(|candidate| glob_matches(&pattern, candidate.as_str()))
        .cloned()
        .collect()
}

fn dedupe_resolved_targets(targets: Vec<ResolvedImportTarget>) -> Vec<ResolvedImportTarget> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for target in targets {
        let key = (target.target.clone(), target.kind.clone());
        if seen.insert(key) {
            deduped.push(target);
        }
    }
    deduped
}

fn import_path_glob(path: &ImportPath) -> Option<String> {
    match path {
        ImportPath::Exact(value) => Some(value.clone()),
        ImportPath::Pattern(pattern) => pattern_to_glob(pattern),
    }
}

fn glob_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return false;
    }
    let mut idx = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if let Some(pos) = candidate[idx..].find(part) {
            if i == 0 && anchored_start && pos != 0 {
                return false;
            }
            idx += pos + part.len();
        } else {
            return false;
        }
    }
    if anchored_end {
        if let Some(last) = parts.last() {
            if !candidate.ends_with(last) {
                return false;
            }
        }
    }
    true
}

fn resolve_unique_match(
    repo_root: &Path,
    rel_path: &str,
    import_ref: &ImportRef,
    pattern: &StringPattern,
) -> Option<String> {
    match import_ref.language {
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            resolve_unique_match_js_ts(repo_root, rel_path, pattern)
        }
        SourceLanguage::Python => resolve_unique_match_python(repo_root, rel_path, pattern),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MatchScoreKey {
    primary: u8,
    spec_len: usize,
}

#[derive(Debug, Clone)]
struct MatchCandidate {
    target: String,
    score: MatchScoreKey,
}

fn resolve_unique_match_js_ts(
    repo_root: &Path,
    rel_path: &str,
    pattern: &StringPattern,
) -> Option<String> {
    if !pattern.is_useful() {
        return None;
    }
    if pattern.anchored_start {
        if let Some(first) = pattern.first_part() {
            if !first.starts_with('.') {
                return None;
            }
        }
    } else {
        return None;
    }
    let index = repo_file_index(repo_root);
    if index.js_ts_over_limit() {
        return None;
    }
    let mut matches = Vec::new();
    for target in &index.js_ts {
        if let Some(score) = js_ts_match_score(rel_path, target, pattern) {
            matches.push(MatchCandidate {
                target: target.clone(),
                score,
            });
        }
    }
    pick_unique_match(rel_path, pattern, matches, "js_ts")
}

fn resolve_pattern_matches_js_ts(
    repo_root: &Path,
    rel_path: &str,
    pattern: &StringPattern,
) -> Vec<String> {
    if !pattern.is_useful() {
        return Vec::new();
    }
    if pattern.anchored_start {
        if let Some(first) = pattern.first_part() {
            if !first.starts_with('.') {
                return Vec::new();
            }
        }
    } else {
        return Vec::new();
    }
    let index = repo_file_index(repo_root);
    if index.js_ts_over_limit() {
        return Vec::new();
    }
    let mut matches = Vec::new();
    for target in &index.js_ts {
        if let Some(score) = js_ts_match_score(rel_path, target, pattern) {
            matches.push(MatchCandidate {
                target: target.clone(),
                score,
            });
        }
    }
    matches.sort_by(|left, right| {
        left.score
            .cmp(&right.score)
            .then_with(|| left.target.cmp(&right.target))
    });
    matches.into_iter().map(|entry| entry.target).collect()
}

fn resolve_unique_match_python(
    repo_root: &Path,
    rel_path: &str,
    pattern: &StringPattern,
) -> Option<String> {
    if !pattern.is_useful() {
        return None;
    }
    let index = repo_file_index(repo_root);
    if index.python_over_limit() {
        return None;
    }
    let mut matches = Vec::new();
    for target in &index.python {
        if let Some(score) = python_match_score(rel_path, target, pattern) {
            matches.push(MatchCandidate {
                target: target.clone(),
                score,
            });
        }
    }
    pick_unique_match(rel_path, pattern, matches, "python")
}

fn pick_unique_match(
    rel_path: &str,
    pattern: &StringPattern,
    mut matches: Vec<MatchCandidate>,
    language: &str,
) -> Option<String> {
    if matches.is_empty() {
        return None;
    }
    if matches.len() == 1 {
        return matches.pop().map(|entry| entry.target);
    }
    matches.sort_by(|left, right| {
        left.score
            .cmp(&right.score)
            .then_with(|| left.target.cmp(&right.target))
    });
    let chosen = matches.first().map(|entry| entry.target.clone());
    if let Some(chosen) = chosen.as_ref() {
        info!(
            target: "docdexd",
            file = %rel_path,
            language = %language,
            pattern = %pattern_to_glob(pattern).unwrap_or_else(|| "*".to_string()),
            count = matches.len(),
            chosen = %chosen,
            "dynamic import resolved with deterministic tie-break"
        );
    }
    chosen
}

fn js_ts_match_score(
    rel_path: &str,
    target: &str,
    pattern: &StringPattern,
) -> Option<MatchScoreKey> {
    let specs = js_ts_candidate_specs(rel_path, target);
    let mut best: Option<(u8, usize)> = None;
    for spec in specs {
        if !pattern_matches(pattern, spec.as_str()) {
            continue;
        }
        let relative_rank = if spec.starts_with("./") || spec.starts_with("../") {
            0
        } else {
            1
        };
        let candidate = (relative_rank, spec.len());
        if best.map(|current| candidate < current).unwrap_or(true) {
            best = Some(candidate);
        }
    }
    let (primary, _spec_len) = best?;
    Some(MatchScoreKey {
        primary,
        spec_len: 0,
    })
}

fn python_match_score(
    rel_path: &str,
    target: &str,
    pattern: &StringPattern,
) -> Option<MatchScoreKey> {
    let module_spec = python_module_name(target);
    let specs = python_candidate_specs(rel_path, target);
    let mut best_len: Option<usize> = None;
    let mut matched_module = false;
    for spec in specs {
        if !pattern_matches(pattern, spec.as_str()) {
            continue;
        }
        let is_module = module_spec.as_deref() == Some(spec.as_str());
        if is_module {
            matched_module = true;
            best_len = Some(best_len.map_or(spec.len(), |len| len.min(spec.len())));
        } else if !matched_module {
            best_len = Some(best_len.map_or(spec.len(), |len| len.min(spec.len())));
        }
    }
    let spec_len = best_len?;
    let primary = if matched_module { 0 } else { 1 };
    Some(MatchScoreKey { primary, spec_len })
}

fn pattern_matches(pattern: &StringPattern, candidate: &str) -> bool {
    if !pattern.is_useful() {
        return false;
    }
    let mut idx = 0usize;
    let mut first = true;
    for part in &pattern.parts {
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = candidate[idx..].find(part) {
            if first && pattern.anchored_start && pos != 0 {
                return false;
            }
            idx += pos + part.len();
            first = false;
        } else {
            return false;
        }
    }
    if pattern.anchored_end {
        if let Some(last) = pattern.last_part() {
            if !candidate.ends_with(last) {
                return false;
            }
        }
    }
    true
}

fn repo_file_index(repo_root: &Path) -> RepoFileIndex {
    let key = canonical_repo_root(repo_root);
    let limit = dynamic_import_scan_limit();
    let mut cache = REPO_FILE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(index) = cache.get(&key) {
        if index.limit == limit {
            return index.clone();
        }
    }
    let index = collect_repo_file_index(&key, limit);
    cache.insert(key, index.clone());
    index
}

fn collect_repo_file_index(repo_root: &Path, limit: usize) -> RepoFileIndex {
    let mut index = RepoFileIndex {
        js_ts: Vec::new(),
        python: Vec::new(),
        all: Vec::new(),
        js_ts_count: 0,
        python_count: 0,
        all_count: 0,
        limit,
    };
    let walker = WalkDir::new(repo_root).into_iter().filter_entry(|entry| {
        if entry.file_type().is_dir() {
            return !should_skip_repo_dir(entry);
        }
        true
    });
    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = match path.strip_prefix(repo_root) {
            Ok(rel) => rel,
            Err(_) => continue,
        };
        let rel_str = normalize_rel_path(rel);
        let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        index.all_count += 1;
        if index.all_count <= index.limit {
            index.all.push(rel_str.clone());
        }
        if matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
            index.js_ts_count += 1;
            if index.js_ts_count <= index.limit {
                index.js_ts.push(rel_str);
            }
        } else if ext == "py" {
            index.python_count += 1;
            if index.python_count <= index.limit {
                index.python.push(rel_str);
            }
        }
    }
    index
}

fn should_skip_repo_dir(entry: &walkdir::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    matches!(
        name.as_ref(),
        ".git" | ".docdex" | "node_modules" | "target" | ".idea" | ".vscode"
    )
}

pub(super) fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

pub(super) fn env_usize(key: &str) -> Option<usize> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<usize>().ok()
}

fn js_ts_candidate_specs(importer_rel: &str, target_rel: &str) -> Vec<String> {
    let base_dir = Path::new(importer_rel).parent().unwrap_or(Path::new(""));
    let target_path = Path::new(target_rel);
    let rel = relative_path(base_dir, target_path);
    let mut rel_str = normalize_rel_path(&rel);
    if !rel_str.starts_with("../") && !rel_str.starts_with("./") {
        rel_str = format!("./{rel_str}");
    }
    let mut specs = Vec::new();
    if !rel_str.is_empty() {
        specs.push(rel_str.clone());
    }
    if let Some(stripped) = strip_known_extension(&rel_str) {
        specs.push(stripped);
    }
    if let Some(index_spec) = js_index_spec(&rel_str) {
        specs.push(index_spec);
    }
    let mut seen = HashSet::new();
    specs
        .into_iter()
        .filter(|spec| seen.insert(spec.clone()))
        .collect()
}

fn strip_known_extension(value: &str) -> Option<String> {
    let path = Path::new(value);
    let ext = path.extension()?.to_str()?;
    if !matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
        return None;
    }
    let mut trimmed = value.to_string();
    if let Some(pos) = trimmed.rfind('.') {
        trimmed.truncate(pos);
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed);
    }
    None
}

fn js_index_spec(value: &str) -> Option<String> {
    let lowered = value.to_lowercase();
    for ext in ["js", "jsx", "ts", "tsx", "mjs", "cjs"] {
        let suffix = format!("/index.{ext}");
        if lowered.ends_with(&suffix) {
            let trimmed = value[..value.len() - suffix.len()].to_string();
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed);
        }
    }
    None
}

fn python_candidate_specs(importer_rel: &str, target_rel: &str) -> Vec<String> {
    let mut specs = Vec::new();
    if let Some(module) = python_module_name(target_rel) {
        specs.push(module.clone());
        if let Some(relative) = python_relative_spec(importer_rel, &module) {
            specs.push(relative);
        }
    }
    let target_path = Path::new(target_rel);
    let mut rel_str = normalize_rel_path(target_path);
    if !rel_str.is_empty() {
        specs.push(rel_str.clone());
    }
    let base_dir = Path::new(importer_rel).parent().unwrap_or(Path::new(""));
    let rel = relative_path(base_dir, target_path);
    rel_str = normalize_rel_path(&rel);
    if !rel_str.starts_with("../") && !rel_str.starts_with("./") {
        rel_str = format!("./{rel_str}");
    }
    if !rel_str.is_empty() {
        specs.push(rel_str);
    }
    let mut seen = HashSet::new();
    specs
        .into_iter()
        .filter(|spec| seen.insert(spec.clone()))
        .collect()
}

fn python_module_name(rel_path: &str) -> Option<String> {
    if !rel_path.ends_with(".py") {
        return None;
    }
    let path = Path::new(rel_path);
    let file_stem = path.file_stem()?.to_string_lossy();
    let mut parts = Vec::new();
    if let Some(parent) = path.parent() {
        for comp in parent.components() {
            if let std::path::Component::Normal(os) = comp {
                parts.push(os.to_string_lossy().to_string());
            }
        }
    }
    if file_stem != "__init__" {
        parts.push(file_stem.to_string());
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn python_relative_spec(importer_rel: &str, module: &str) -> Option<String> {
    let importer_path = Path::new(importer_rel);
    let importer_dir = importer_path.parent().unwrap_or(Path::new(""));
    let mut importer_parts = Vec::new();
    for comp in importer_dir.components() {
        if let std::path::Component::Normal(os) = comp {
            importer_parts.push(os.to_string_lossy().to_string());
        }
    }
    if importer_parts.is_empty() {
        return None;
    }
    let target_parts: Vec<&str> = module.split('.').collect();
    let mut common = 0usize;
    while common < importer_parts.len()
        && common < target_parts.len()
        && importer_parts[common] == target_parts[common]
    {
        common += 1;
    }
    let up = importer_parts.len().saturating_sub(common) + 1;
    let mut spec = ".".repeat(up);
    let remainder = target_parts[common..].join(".");
    if !remainder.is_empty() {
        spec.push_str(&remainder);
    }
    Some(spec)
}

fn relative_path(from: &Path, to: &Path) -> PathBuf {
    use std::path::Component;

    let from_components: Vec<Component<'_>> = from.components().collect();
    let to_components: Vec<Component<'_>> = to.components().collect();
    let mut common = 0usize;
    while common < from_components.len()
        && common < to_components.len()
        && from_components[common] == to_components[common]
    {
        common += 1;
    }
    let mut result = PathBuf::new();
    for _ in common..from_components.len() {
        result.push("..");
    }
    for comp in to_components.into_iter().skip(common) {
        result.push(comp.as_os_str());
    }
    result
}

fn resolve_js_ts_import(repo_root: &Path, rel_path: &str, import_path: &str) -> Option<String> {
    if !import_path.starts_with('.') {
        return None;
    }
    let base_dir = Path::new(rel_path).parent().unwrap_or(Path::new(""));
    let raw = Path::new(import_path);
    let mut candidates = Vec::new();
    let base = base_dir.join(raw);
    if raw.extension().is_some() {
        candidates.push(base);
    } else {
        for ext in ["ts", "tsx", "js", "jsx"] {
            candidates.push(base.with_extension(ext));
        }
        for ext in ["ts", "tsx", "js", "jsx"] {
            candidates.push(base.join(format!("index.{ext}")));
        }
    }
    resolve_first_existing(repo_root, candidates)
}

fn resolve_python_import(repo_root: &Path, rel_path: &str, import_path: &str) -> Option<String> {
    let import_path = import_path.trim();
    if import_path.is_empty() {
        return None;
    }
    let import_path = if Path::new(import_path).is_absolute() {
        let rel = Path::new(import_path).strip_prefix(repo_root).ok()?;
        return Some(normalize_rel_path(rel));
    } else {
        import_path
    };
    let (dot_count, remainder) = split_leading_dots(import_path);
    let mut base_dir = Path::new(rel_path).parent().unwrap_or(Path::new(""));
    if dot_count == 0 {
        base_dir = Path::new("");
    } else {
        let mut up = dot_count.saturating_sub(1);
        while up > 0 {
            base_dir = base_dir.parent().unwrap_or(Path::new(""));
            up -= 1;
        }
    }
    if remainder.is_empty() {
        let candidate = base_dir.join("__init__.py");
        return resolve_first_existing(repo_root, vec![candidate]);
    }
    let module_path =
        if remainder.contains('/') || remainder.contains('\\') || remainder.ends_with(".py") {
            PathBuf::from(remainder)
        } else {
            PathBuf::from(remainder.replace('.', "/"))
        };
    let base = base_dir.join(module_path);
    if base.extension().is_some() {
        return resolve_first_existing(repo_root, vec![base]);
    }
    let mut candidates = vec![base.with_extension("py")];
    candidates.push(base.join("__init__.py"));
    resolve_first_existing(repo_root, candidates)
}

fn resolve_rust_mod(repo_root: &Path, rel_path: &str, module: &str) -> Option<String> {
    let base_dir = rust_module_base_dir(rel_path)?;
    let base = base_dir.join(module);
    let mut candidates = Vec::new();
    candidates.push(base.with_extension("rs"));
    candidates.push(base.join("mod.rs"));
    resolve_first_existing(repo_root, candidates)
}

fn resolve_rust_include(repo_root: &Path, rel_path: &str, include_path: &str) -> Option<String> {
    let base_dir = Path::new(rel_path).parent().unwrap_or(Path::new(""));
    let candidate = base_dir.join(include_path);
    resolve_first_existing(repo_root, vec![candidate])
}

fn resolve_go_import(
    repo_root: &Path,
    _rel_path: &str,
    import_path: &str,
    module_path: Option<&str>,
) -> Option<String> {
    let module_path = module_path?;
    if !import_path.starts_with(module_path) {
        return None;
    }
    let mut remainder = import_path[module_path.len()..].trim_start_matches('/');
    if remainder.is_empty() {
        return None;
    }
    if remainder.ends_with('/') {
        remainder = remainder.trim_end_matches('/');
    }
    let base = PathBuf::from(remainder);
    if base.extension().is_some() {
        return resolve_first_existing(repo_root, vec![base]);
    }
    let dir = repo_root.join(&base);
    if dir.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .ok()
            .into_iter()
            .flat_map(|iter| iter.filter_map(|e| e.ok().map(|e| e.path())))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("go"))
            .collect();
        entries.sort();
        if let Some(path) = entries.first() {
            if let Ok(rel) = path.strip_prefix(repo_root) {
                return Some(normalize_rel_path(rel));
            }
        }
    }
    resolve_first_existing(repo_root, vec![base.with_extension("go")])
}

fn resolve_first_existing(repo_root: &Path, candidates: Vec<PathBuf>) -> Option<String> {
    let debug_imports = cfg!(test)
        && std::env::var("DOCDEX_DEBUG_IMPORTS")
            .map(|value| value.trim() == "1")
            .unwrap_or(false);
    let repo_root_canon = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    for rel in candidates {
        let path = repo_root.join(&rel);
        if debug_imports {
            eprintln!(
                "[impact] candidate {} (exists: {})",
                path.display(),
                path.is_file()
            );
        }
        if path.is_file() {
            if let Ok(canon) = path.canonicalize() {
                if !canon.starts_with(&repo_root_canon) {
                    continue;
                }
                if let Ok(rel_canon) = canon.strip_prefix(&repo_root_canon) {
                    return Some(normalize_rel_path(rel_canon));
                }
            }
            return Some(normalize_rel_path(&rel));
        }
    }
    None
}

fn normalize_rel_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn node_text<'a>(content: &'a str, node: Node) -> Option<&'a str> {
    content.get(node.start_byte()..node.end_byte())
}

fn string_literal_eval(content: &str, node: Node) -> Option<StringEval> {
    if !is_string_literal_kind(node.kind()) {
        return None;
    }
    let raw = node_text(content, node)?.trim();
    if raw.is_empty() {
        return None;
    }
    if is_f_string_literal(raw) && raw.contains('{') {
        return parse_f_string_pattern(raw).map(StringEval::Pattern);
    }
    if raw.starts_with('`') && raw.contains("${") {
        let pattern = parse_template_string_pattern(raw)?;
        return Some(StringEval::Pattern(pattern));
    }
    let value = string_literal_value(content, node)?;
    Some(StringEval::Exact(value))
}

fn parse_template_string_pattern(raw: &str) -> Option<StringPattern> {
    let raw = strip_string_literal_prefix(raw.trim());
    let inner = raw.strip_prefix('`')?.strip_suffix('`')?;
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = inner.chars().peekable();
    let mut saw_dynamic = false;
    let mut anchored_start = true;
    let mut last_was_dynamic = false;
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            if !saw_dynamic && current.is_empty() {
                anchored_start = false;
            }
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
            saw_dynamic = true;
            last_was_dynamic = true;
            let mut depth = 1usize;
            while let Some(next) = chars.next() {
                if next == '{' {
                    depth = depth.saturating_add(1);
                } else if next == '}' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
            }
            continue;
        }
        current.push(ch);
        last_was_dynamic = false;
    }
    if !saw_dynamic {
        return None;
    }
    if !current.is_empty() {
        parts.push(current);
    }
    let anchored_end = !last_was_dynamic;
    let pattern = StringPattern {
        parts,
        anchored_start,
        anchored_end,
    };
    Some(pattern.normalize())
}

fn parse_f_string_pattern(raw: &str) -> Option<StringPattern> {
    let raw = strip_string_literal_prefix(raw.trim());
    let (inner, triple) = if raw.starts_with("\"\"\"") {
        (raw.strip_prefix("\"\"\"")?.strip_suffix("\"\"\"")?, true)
    } else if raw.starts_with("'''") {
        (raw.strip_prefix("'''")?.strip_suffix("'''")?, true)
    } else if raw.starts_with('"') {
        (raw.strip_prefix('"')?.strip_suffix('"')?, false)
    } else if raw.starts_with('\'') {
        (raw.strip_prefix('\'')?.strip_suffix('\'')?, false)
    } else {
        return None;
    };
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = inner.chars().peekable();
    let mut saw_dynamic = false;
    let mut anchored_start = true;
    let mut last_was_dynamic = false;
    while let Some(ch) = chars.next() {
        if ch == '{' {
            if chars.peek() == Some(&'{') {
                chars.next();
                current.push('{');
                last_was_dynamic = false;
                continue;
            }
            if !saw_dynamic && current.is_empty() {
                anchored_start = false;
            }
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
            saw_dynamic = true;
            last_was_dynamic = true;
            let mut depth = 1usize;
            while let Some(next) = chars.next() {
                if next == '{' {
                    depth = depth.saturating_add(1);
                } else if next == '}' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
            }
            continue;
        }
        if ch == '}' && chars.peek() == Some(&'}') {
            chars.next();
            current.push('}');
            last_was_dynamic = false;
            continue;
        }
        current.push(ch);
        last_was_dynamic = false;
    }
    if !saw_dynamic {
        return None;
    }
    if !current.is_empty() || triple {
        parts.push(current);
    }
    let anchored_end = !last_was_dynamic;
    let pattern = StringPattern {
        parts,
        anchored_start,
        anchored_end,
    };
    Some(pattern.normalize())
}

fn string_literal_value(content: &str, node: Node) -> Option<String> {
    if !is_string_literal_kind(node.kind()) {
        return None;
    }
    let raw = node_text(content, node)?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(value) = parse_rust_raw_string(raw) {
        return Some(value);
    }
    let raw = strip_string_literal_prefix(raw);
    let first = raw.as_bytes().first().copied()?;
    if !matches!(first, b'"' | b'\'' | b'`') {
        return None;
    }
    if raw.starts_with('`') && raw.contains("${") {
        return None;
    }
    let trimmed = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .or_else(|| raw.strip_prefix('`').and_then(|s| s.strip_suffix('`')))
        .unwrap_or(raw);
    let value = trimmed.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn is_string_literal_kind(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "template_string"
            | "raw_string_literal"
            | "byte_string_literal"
            | "raw_byte_string_literal"
            | "interpreted_string_literal"
    )
}

fn parse_rust_raw_string(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut idx = 0usize;
    if matches!(bytes.get(idx), Some(b'b') | Some(b'B')) {
        idx += 1;
    }
    if !matches!(bytes.get(idx), Some(b'r') | Some(b'R')) {
        return None;
    }
    idx += 1;
    let mut hash_count = 0usize;
    while bytes.get(idx) == Some(&b'#') {
        hash_count += 1;
        idx += 1;
    }
    if bytes.get(idx) != Some(&b'"') {
        return None;
    }
    let start = idx + 1;
    let closing = format!("\"{}", "#".repeat(hash_count));
    let tail = &raw[start..];
    let end = tail.find(&closing)?;
    Some(tail[..end].to_string())
}

fn strip_string_literal_prefix(raw: &str) -> &str {
    let mut idx = 0usize;
    for ch in raw.chars() {
        match ch {
            'b' | 'B' | 'r' | 'R' | 'f' | 'F' | 'u' | 'U' => idx += ch.len_utf8(),
            _ => break,
        }
    }
    &raw[idx..]
}

fn is_f_string_literal(raw: &str) -> bool {
    let mut saw_prefix = false;
    for ch in raw.chars() {
        match ch {
            'f' | 'F' => return true,
            'b' | 'B' | 'r' | 'R' | 'u' | 'U' => saw_prefix = true,
            '"' | '\'' => break,
            _ => {
                if saw_prefix {
                    break;
                }
                return false;
            }
        }
    }
    false
}

pub(crate) fn normalize_edge_kind(raw: &str) -> &'static str {
    let lowered = raw.trim().to_ascii_lowercase();
    match lowered.as_str() {
        "include" => "include",
        "require" => "require",
        _ => "import",
    }
}

fn static_string_eval_with_resolver<F>(content: &str, node: Node, resolver: &F) -> StringEval
where
    F: Fn(&str) -> Option<StringEval>,
{
    if let Some(eval) = template_string_eval_with_resolver(content, node, resolver) {
        return eval;
    }
    if let Some(eval) = string_literal_eval(content, node) {
        return eval;
    }
    if node.kind() == "identifier" {
        let name = node_text(content, node)
            .unwrap_or_default()
            .trim()
            .to_string();
        if name.is_empty() {
            return StringEval::Unknown;
        }
        return resolver(&name).unwrap_or(StringEval::Unknown);
    }
    match node.kind() {
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            let inner = match node.named_children(&mut cursor).next() {
                Some(inner) => inner,
                None => return StringEval::Unknown,
            };
            static_string_eval_with_resolver(content, inner, resolver)
        }
        "binary_expression" | "binary_operator" => {
            let op = match binary_operator_text(content, node) {
                Some(op) => op,
                None => return StringEval::Unknown,
            };
            if op != "+" {
                return StringEval::Unknown;
            }
            let left = match node.child_by_field_name("left") {
                Some(left) => left,
                None => return StringEval::Unknown,
            };
            let right = match node.child_by_field_name("right") {
                Some(right) => right,
                None => return StringEval::Unknown,
            };
            let left_val = static_string_eval_with_resolver(content, left, resolver);
            let right_val = static_string_eval_with_resolver(content, right, resolver);
            concat_eval(left_val, right_val)
        }
        "concatenated_string" => {
            let mut cursor = node.walk();
            let mut result: Option<StringEval> = None;
            for child in node.named_children(&mut cursor) {
                let value = static_string_eval_with_resolver(content, child, resolver);
                result = Some(match result {
                    Some(existing) => concat_eval(existing, value),
                    None => value,
                });
            }
            result.unwrap_or(StringEval::Unknown)
        }
        "call_expression" | "call" => {
            let name = match call_function_name(content, node) {
                Some(name) => name,
                None => return StringEval::Unknown,
            };
            let args = match call_argument_nodes(node) {
                Some(args) => args,
                None => return StringEval::Unknown,
            };
            let mut values = Vec::new();
            for arg in args {
                values.push(static_string_eval_with_resolver(content, arg, resolver));
            }
            resolve_path_call_eval(name.as_str(), &values)
        }
        _ => StringEval::Unknown,
    }
}

fn template_string_eval_with_resolver<F>(
    content: &str,
    node: Node,
    resolver: &F,
) -> Option<StringEval>
where
    F: Fn(&str) -> Option<StringEval>,
{
    let kind = node.kind();
    if kind != "template_string" && kind != "template_literal" {
        return None;
    }
    let mut cursor = node.walk();
    let mut saw_part = false;
    let mut result = StringEval::Exact(String::new());
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_fragment" | "template_string_content" => {
                if let Some(text) = node_text(content, child) {
                    result = concat_eval(result, StringEval::Exact(text.to_string()));
                    saw_part = true;
                }
            }
            "template_substitution" => {
                let expr = child
                    .child_by_field_name("expression")
                    .or_else(|| child.named_child(0));
                let eval = expr
                    .map(|expr| static_string_eval_with_resolver(content, expr, resolver))
                    .unwrap_or(StringEval::Unknown);
                result = concat_eval(result, eval);
                saw_part = true;
            }
            _ => {}
        }
    }
    if saw_part {
        Some(result)
    } else {
        None
    }
}

fn is_meaningful_eval(eval: &StringEval) -> bool {
    match eval {
        StringEval::Exact(value) => !value.trim().is_empty(),
        StringEval::Pattern(pattern) => pattern.is_useful(),
        StringEval::Unknown => false,
    }
}

fn eval_to_import_path(eval: StringEval) -> Option<ImportPath> {
    match eval {
        StringEval::Exact(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(ImportPath::Exact(trimmed.to_string()))
            }
        }
        StringEval::Pattern(pattern) => {
            let normalized = pattern.normalize();
            if normalized.is_useful() {
                Some(ImportPath::Pattern(normalized))
            } else {
                None
            }
        }
        StringEval::Unknown => None,
    }
}

fn format_import_path(path: &ImportPath) -> String {
    match path {
        ImportPath::Exact(value) => value.clone(),
        ImportPath::Pattern(pattern) => pattern_to_glob(pattern).unwrap_or_else(|| "*".to_string()),
    }
}

fn concat_eval(left: StringEval, right: StringEval) -> StringEval {
    match (left, right) {
        (StringEval::Exact(left), StringEval::Exact(right)) => {
            StringEval::Exact(format!("{left}{right}"))
        }
        (left, right) => {
            let merged = concat_patterns(pattern_from_eval(left), pattern_from_eval(right));
            if !merged.is_useful() {
                return StringEval::Unknown;
            }
            if let Some(exact) = pattern_to_exact(&merged) {
                return StringEval::Exact(exact);
            }
            StringEval::Pattern(merged)
        }
    }
}

fn pattern_from_eval(eval: StringEval) -> StringPattern {
    match eval {
        StringEval::Exact(value) => StringPattern {
            parts: vec![value],
            anchored_start: true,
            anchored_end: true,
        },
        StringEval::Pattern(pattern) => pattern.normalize(),
        StringEval::Unknown => StringPattern {
            parts: Vec::new(),
            anchored_start: false,
            anchored_end: false,
        },
    }
}

fn concat_patterns(left: StringPattern, right: StringPattern) -> StringPattern {
    let left = left.normalize();
    let right = right.normalize();
    let anchored_start = left.anchored_start;
    let anchored_end = right.anchored_end;
    if left.parts.is_empty() {
        return StringPattern {
            parts: right.parts,
            anchored_start,
            anchored_end,
        };
    }
    if right.parts.is_empty() {
        return StringPattern {
            parts: left.parts,
            anchored_start,
            anchored_end,
        };
    }
    let mut parts = if left.anchored_end && right.anchored_start {
        let mut merged = left.parts;
        if let Some(first) = right.parts.first() {
            let last_idx = merged.len().saturating_sub(1);
            merged[last_idx].push_str(first);
        }
        merged.extend(right.parts.into_iter().skip(1));
        merged
    } else {
        let mut merged = left.parts;
        merged.extend(right.parts);
        merged
    };
    parts.retain(|part| !part.is_empty());
    StringPattern {
        parts,
        anchored_start,
        anchored_end,
    }
}

fn pattern_to_exact(pattern: &StringPattern) -> Option<String> {
    if pattern.anchored_start && pattern.anchored_end && pattern.parts.len() == 1 {
        Some(pattern.parts[0].clone())
    } else {
        None
    }
}

fn pattern_to_glob(pattern: &StringPattern) -> Option<String> {
    if !pattern.is_useful() {
        return None;
    }
    let mut value = String::new();
    if !pattern.anchored_start {
        value.push('*');
    }
    for (idx, part) in pattern.parts.iter().enumerate() {
        if idx > 0 {
            value.push('*');
        }
        value.push_str(part);
    }
    if !pattern.anchored_end {
        value.push('*');
    }
    Some(value)
}

fn binary_operator_text(content: &str, node: Node) -> Option<String> {
    if let Some(op) = node.child_by_field_name("operator") {
        return node_text(content, op).map(|value| value.trim().to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            continue;
        }
        if let Some(text) = node_text(content, child) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn assignment_operator_is_eq(content: &str, node: Node) -> bool {
    if let Some(op) = node.child_by_field_name("operator") {
        if let Some(text) = node_text(content, op) {
            return text.trim() == "=";
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            continue;
        }
        if let Some(text) = node_text(content, child) {
            if text.trim() == "=" {
                return true;
            }
        }
    }
    false
}

fn call_argument_nodes(node: Node) -> Option<Vec<Node>> {
    let args = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument"))?;
    if matches!(args.kind(), "arguments" | "argument_list") {
        let mut cursor = args.walk();
        let list = args.named_children(&mut cursor).collect::<Vec<_>>();
        if list.is_empty() {
            None
        } else {
            Some(list)
        }
    } else {
        Some(vec![args])
    }
}

fn resolve_path_call_eval(name: &str, args: &[StringEval]) -> StringEval {
    if args.is_empty() {
        return StringEval::Unknown;
    }
    if args.iter().all(|arg| matches!(arg, StringEval::Exact(_))) {
        let values = args
            .iter()
            .map(|value| match value {
                StringEval::Exact(value) => value.clone(),
                _ => String::new(),
            })
            .collect::<Vec<_>>();
        if let Some(resolved) = resolve_path_call(name, &values) {
            return StringEval::Exact(resolved);
        }
    }
    let trimmed = name.trim();
    let is_join = matches!(
        trimmed,
        "path.join"
            | "path.posix.join"
            | "path.win32.join"
            | "os.path.join"
            | "posixpath.join"
            | "ntpath.join"
    );
    let is_resolve = matches!(
        trimmed,
        "path.resolve"
            | "path.posix.resolve"
            | "path.win32.resolve"
            | "os.path.abspath"
            | "pathlib.Path"
            | "Path"
            | "pathlib.PurePath"
            | "PurePath"
    );
    if !is_join && !is_resolve {
        return StringEval::Unknown;
    }
    let mut force_dot = false;
    let mut result = StringEval::Unknown;
    for (idx, arg) in args.iter().enumerate() {
        if idx == 0 {
            if !eval_is_relative(arg) {
                return StringEval::Unknown;
            }
        } else if !matches!(arg, StringEval::Unknown) && !eval_is_relative(arg) {
            return StringEval::Unknown;
        }
        if idx == 0 {
            if eval_has_relative_prefix(arg) {
                force_dot = true;
            }
            result = arg.clone();
        } else {
            result = concat_eval(result, StringEval::Exact("/".to_string()));
            result = concat_eval(result, arg.clone());
        }
    }
    if force_dot {
        result = prefix_eval(result, "./");
    }
    result
}

fn resolve_path_call(name: &str, args: &[String]) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let trimmed = name.trim();
    let is_join = matches!(
        trimmed,
        "path.join"
            | "path.posix.join"
            | "path.win32.join"
            | "os.path.join"
            | "posixpath.join"
            | "ntpath.join"
    );
    let is_resolve = matches!(
        trimmed,
        "path.resolve"
            | "path.posix.resolve"
            | "path.win32.resolve"
            | "os.path.abspath"
            | "pathlib.Path"
            | "Path"
            | "pathlib.PurePath"
            | "PurePath"
    );
    if !is_join && !is_resolve {
        return None;
    }
    let mut force_dot = false;
    let mut path = PathBuf::new();
    for (idx, part) in args.iter().enumerate() {
        if part.starts_with('/') {
            return None;
        }
        if part.contains(':') {
            return None;
        }
        if idx == 0 && (part.starts_with("./") || part.starts_with(".\\")) {
            force_dot = true;
        }
        path.push(part);
    }
    let mut normalized = path.to_string_lossy().replace('\\', "/");
    if force_dot && !normalized.starts_with('.') {
        normalized = format!("./{normalized}");
    }
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn eval_is_relative(eval: &StringEval) -> bool {
    match eval {
        StringEval::Exact(value) => is_relative_path_fragment(value),
        StringEval::Pattern(pattern) => {
            if !pattern.anchored_start {
                return false;
            }
            if let Some(first) = pattern.first_part() {
                is_relative_path_fragment(first)
            } else {
                false
            }
        }
        StringEval::Unknown => false,
    }
}

fn is_relative_path_fragment(value: &str) -> bool {
    if value.starts_with('/') || value.contains(':') {
        return false;
    }
    true
}

fn eval_has_relative_prefix(eval: &StringEval) -> bool {
    match eval {
        StringEval::Exact(value) => value.starts_with("./") || value.starts_with(".\\"),
        StringEval::Pattern(pattern) => pattern
            .first_part()
            .map(|part| part.starts_with("./") || part.starts_with(".\\"))
            .unwrap_or(false),
        StringEval::Unknown => false,
    }
}

fn prefix_eval(eval: StringEval, prefix: &str) -> StringEval {
    match eval {
        StringEval::Exact(value) => StringEval::Exact(format!("{prefix}{value}")),
        StringEval::Pattern(pattern) => {
            let mut pattern = pattern.normalize();
            if let Some(first) = pattern.parts.first_mut() {
                first.insert_str(0, prefix);
            } else {
                pattern.parts.push(prefix.to_string());
                pattern.anchored_start = true;
            }
            StringEval::Pattern(pattern)
        }
        StringEval::Unknown => StringEval::Unknown,
    }
}

fn python_assignment_parts<'a>(content: &str, node: Node<'a>) -> Option<(String, Node<'a>)> {
    let left = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("target"));
    let right = node
        .child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"));
    if let (Some(left), Some(right)) = (left, right) {
        if left.kind() == "identifier" {
            let name = node_text(content, left)?.trim().to_string();
            if !name.is_empty() {
                return Some((name, right));
            }
        }
    }
    let mut cursor = node.walk();
    let named: Vec<Node<'a>> = node.named_children(&mut cursor).collect();
    if named.len() >= 2 {
        let left = named.first()?;
        let right = named.last()?;
        if left.kind() == "identifier" {
            let name = node_text(content, *left)?.trim().to_string();
            if !name.is_empty() {
                return Some((name, *right));
            }
        }
    }
    None
}

fn call_function_name(content: &str, node: Node) -> Option<String> {
    let func = node.child_by_field_name("function")?;
    let text = node_text(content, func)?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn js_dynamic_import_kind(name: &str) -> Option<&'static str> {
    let trimmed = name.trim();
    if trimmed == "import" {
        return Some("import");
    }
    if trimmed == "require" || trimmed.ends_with(".require") {
        return Some("require");
    }
    if trimmed == "require.resolve" || trimmed.ends_with(".require.resolve") {
        return Some("require");
    }
    None
}

fn python_dynamic_import_spec(name: &str) -> Option<(&'static str, usize)> {
    let trimmed = name.trim();
    if matches!(
        trimmed,
        "__import__" | "import_module" | "importlib.import_module"
    ) {
        return Some(("import", 0));
    }
    if matches!(
        trimmed,
        "importlib.util.spec_from_file_location" | "spec_from_file_location"
    ) {
        return Some(("import", 1));
    }
    if matches!(
        trimmed,
        "importlib.machinery.SourceFileLoader"
            | "importlib.machinery.SourcelessFileLoader"
            | "importlib.machinery.ExtensionFileLoader"
            | "SourceFileLoader"
            | "SourcelessFileLoader"
            | "ExtensionFileLoader"
    ) {
        return Some(("import", 1));
    }
    None
}

fn first_argument_import_path<F>(content: &str, node: Node, resolver: &F) -> Option<ImportPath>
where
    F: Fn(&str) -> Option<StringEval>,
{
    argument_import_path(content, node, 0, resolver)
}

fn argument_import_path<F>(
    content: &str,
    node: Node,
    arg_index: usize,
    resolver: &F,
) -> Option<ImportPath>
where
    F: Fn(&str) -> Option<StringEval>,
{
    let args = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument"))?;
    if matches!(args.kind(), "arguments" | "argument_list") {
        let mut cursor = args.walk();
        let list = args.named_children(&mut cursor).collect::<Vec<_>>();
        let arg = list.get(arg_index)?;
        if cfg!(test)
            && std::env::var("DOCDEX_DEBUG_IMPORTS")
                .map(|value| value.trim() == "1")
                .unwrap_or(false)
        {
            eprintln!(
                "[impact] arg node {} text {:?}",
                arg.kind(),
                node_text(content, *arg)
            );
        }
        let eval = static_string_eval_with_resolver(content, *arg, resolver);
        if cfg!(test)
            && std::env::var("DOCDEX_DEBUG_IMPORTS")
                .map(|value| value.trim() == "1")
                .unwrap_or(false)
        {
            eprintln!("[impact] arg eval {:?}", eval);
        }
        return eval_to_import_path(eval);
    }
    if arg_index > 0 {
        return None;
    }
    let eval = static_string_eval_with_resolver(content, args, resolver);
    if cfg!(test)
        && std::env::var("DOCDEX_DEBUG_IMPORTS")
            .map(|value| value.trim() == "1")
            .unwrap_or(false)
    {
        eprintln!("[impact] arg eval {:?}", eval);
    }
    eval_to_import_path(eval)
}

fn node_name(content: &str, node: Node, field: &str) -> Option<String> {
    let name_node = node.child_by_field_name(field)?;
    let name = node_text(content, name_node)?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn rust_macro_name(content: &str, node: Node) -> Option<String> {
    let name_node = node.child_by_field_name("macro")?;
    let name = node_text(content, name_node)?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn first_string_literal_in_node(content: &str, node: Node) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "string_literal" | "raw_string_literal" | "byte_string_literal" | "raw_byte_string_literal"
    ) {
        return string_literal_value(content, node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(value) = first_string_literal_in_node(content, child) {
            return Some(value);
        }
    }
    None
}

fn split_leading_dots(input: &str) -> (usize, &str) {
    let mut count = 0usize;
    for ch in input.chars() {
        if ch == '.' {
            count += 1;
        } else {
            break;
        }
    }
    (count, input[count..].trim())
}

fn extract_rust_use_paths(text: &str) -> Vec<String> {
    let mut trimmed = text.trim();
    if let Some(rest) = trimmed.strip_prefix("use ") {
        trimmed = rest.trim();
    }
    if trimmed.ends_with(';') {
        trimmed = trimmed.trim_end_matches(';').trim();
    }
    if trimmed.contains('*') {
        return Vec::new();
    }
    if let Some(idx) = trimmed.find('{') {
        let prefix = trimmed[..idx].trim_end_matches("::").trim();
        let suffix = trimmed[idx + 1..].split('}').next().unwrap_or("").trim();
        let mut paths = Vec::new();
        for entry in suffix.split(',') {
            let entry = entry.trim();
            if entry.is_empty() || entry.contains('{') {
                continue;
            }
            let entry = entry.split(" as ").next().unwrap_or(entry).trim();
            if entry == "self" {
                if !prefix.is_empty() {
                    paths.push(prefix.to_string());
                }
                continue;
            }
            if prefix.is_empty() {
                paths.push(entry.to_string());
            } else {
                paths.push(format!("{prefix}::{entry}"));
            }
        }
        return paths;
    }
    let simple = trimmed.split(" as ").next().unwrap_or(trimmed).trim();
    if simple.is_empty() {
        Vec::new()
    } else {
        vec![simple.to_string()]
    }
}

fn resolve_rust_use(repo_root: &Path, rel_path: &str, use_path: &str) -> Option<String> {
    if use_path.starts_with("crate::") {
        let remainder = use_path.trim_start_matches("crate::");
        return resolve_rust_module_path(repo_root, Some(Path::new("src")), remainder);
    }
    if use_path.starts_with("self::") {
        let remainder = use_path.trim_start_matches("self::");
        let base_dir = rust_module_base_dir(rel_path)?;
        return resolve_rust_module_path(repo_root, Some(&base_dir), remainder);
    }
    if use_path.starts_with("super::") {
        let remainder = use_path.trim_start_matches("super::");
        let base_dir = rust_module_base_dir(rel_path)?.parent()?.to_path_buf();
        return resolve_rust_module_path(repo_root, Some(&base_dir), remainder);
    }
    None
}

fn resolve_rust_module_path(
    repo_root: &Path,
    base: Option<&Path>,
    module_path: &str,
) -> Option<String> {
    let cleaned = module_path.trim_matches(':').trim();
    if cleaned.is_empty() {
        return None;
    }
    let parts: Vec<&str> = cleaned.split("::").filter(|p| !p.is_empty()).collect();
    for len in (1..=parts.len()).rev() {
        let candidate = PathBuf::from(parts[..len].join("/"));
        let base_dir = base.map(|b| b.to_path_buf()).unwrap_or_default();
        let mut candidates = Vec::new();
        candidates.push(base_dir.join(&candidate).with_extension("rs"));
        candidates.push(base_dir.join(&candidate).join("mod.rs"));
        if let Some(found) = resolve_first_existing(repo_root, candidates) {
            return Some(found);
        }
    }
    None
}

fn rust_module_base_dir(rel_path: &str) -> Option<PathBuf> {
    let path = Path::new(rel_path);
    let file_name = path.file_name()?.to_string_lossy();
    let parent = path.parent().unwrap_or(Path::new(""));
    let base = if file_name == "mod.rs" || file_name == "lib.rs" || file_name == "main.rs" {
        parent.to_path_buf()
    } else {
        let stem = path.file_stem()?.to_string_lossy();
        parent.join(stem.to_string())
    };
    Some(base)
}

fn go_module_path(repo_root: &Path) -> Option<String> {
    let path = repo_root.join("go.mod");
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("module ") {
            let module = rest.trim();
            if !module.is_empty() {
                return Some(module.to_string());
            }
        }
    }
    None
}

pub fn build_impact_response(
    repo_id: &str,
    source: &str,
    traversal: ImpactTraversalResult,
    applied: &ImpactQueryControls,
    diagnostics: Option<ImpactDiagnostics>,
) -> ImpactGraphResponseV1 {
    let mut inbound_set: BTreeSet<String> = BTreeSet::new();
    let mut outbound_set: BTreeSet<String> = BTreeSet::new();

    for edge in &traversal.edges {
        if edge.source == source {
            outbound_set.insert(edge.target.clone());
        }
        if edge.target == source {
            inbound_set.insert(edge.source.clone());
        }
    }

    let edge_types = applied.edge_types.as_ref().map(|set| {
        let mut list = set.iter().cloned().collect::<Vec<_>>();
        list.sort();
        list
    });

    let applied_controls = AppliedImpactControls {
        max_edges: applied.max_edges,
        max_depth: applied.max_depth,
        edge_types,
    };

    ImpactGraphResponseV1 {
        schema: default_impact_schema(),
        repo_id: repo_id.to_string(),
        source: source.to_string(),
        inbound: inbound_set.into_iter().collect(),
        outbound: outbound_set.into_iter().collect(),
        edges: traversal.edges,
        truncated: traversal.truncated,
        applied: applied_controls.clone(),
        applied_limits: applied_controls,
        diagnostics,
    }
}

pub fn build_impact_diagnostics_response(
    repo_id: &str,
    diagnostics: Vec<ImpactDiagnosticsEntry>,
    total: usize,
    limit: usize,
    offset: usize,
) -> ImpactDiagnosticsResponseV1 {
    let truncated = offset.saturating_add(diagnostics.len()) < total;
    ImpactDiagnosticsResponseV1 {
        schema: default_impact_diagnostics_schema(),
        repo_id: repo_id.to_string(),
        total,
        limit,
        offset,
        truncated,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fs;
    use std::sync::MutexGuard;
    use tempfile::TempDir;

    static IMPACT_SETTINGS_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct ImpactSettingsGuard {
        previous: ImpactSettings,
        _lock: MutexGuard<'static, ()>,
    }

    impl ImpactSettingsGuard {
        fn apply(settings: ImpactSettings) -> Self {
            let lock = IMPACT_SETTINGS_LOCK.lock().expect("impact settings lock");
            let previous = impact_settings();
            apply_impact_settings(settings);
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for ImpactSettingsGuard {
        fn drop(&mut self) {
            apply_impact_settings(self.previous);
        }
    }

    fn fixture_edges() -> Vec<ImpactGraphEdge> {
        vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "b.ts".into(),
                target: "c.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "c.ts".into(),
                target: "d.ts".into(),
                kind: Some("require".into()),
            },
            ImpactGraphEdge {
                source: "x.ts".into(),
                target: "a.ts".into(),
                kind: Some("include".into()),
            },
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "z.ts".into(),
                kind: None,
            },
        ]
    }

    #[test]
    fn detect_cycles_finds_simple_cycle() {
        let edges = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "b.ts".into(),
                target: "c.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "c.ts".into(),
                target: "a.ts".into(),
                kind: Some("import".into()),
            },
        ];

        let cycles = detect_cycles(&edges);
        assert_eq!(cycles.len(), 1);
        assert_eq!(cycles[0], vec!["a.ts", "b.ts", "c.ts"]);
    }

    #[test]
    fn validate_controls_reports_multiple_fields() {
        let err = ImpactQueryControlsRaw {
            max_edges: Some(-1),
            max_depth: Some(-2),
            edge_types: Some(vec!["".into()]),
        }
        .validate()
        .unwrap_err();

        let mut fields = err
            .details
            .issues
            .iter()
            .map(|issue| issue.field)
            .collect::<Vec<_>>();
        fields.sort();
        assert_eq!(fields, vec!["edgeTypes", "maxDepth", "maxEdges"]);
    }

    #[test]
    fn traverse_respects_max_edges_and_sets_truncated() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(1),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.truncated);
        assert_eq!(res.edges.len(), 1);
    }

    #[test]
    fn traverse_max_edges_zero_returns_empty_and_marks_truncated_when_edges_exist() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(0),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.edges.is_empty());
        assert!(res.truncated);
    }

    #[test]
    fn traverse_max_edges_does_not_truncate_when_only_duplicates_remain() {
        let edges = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
        ];
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(1),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &edges, &controls);
        assert_eq!(res.edges.len(), 1);
        assert!(!res.truncated);
    }

    #[test]
    fn traverse_is_deterministic_across_input_order() {
        let edges_a = fixture_edges();
        let mut edges_b = fixture_edges();
        edges_b.reverse();

        let controls = ImpactQueryControlsRaw {
            max_edges: Some(3),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();

        let res_a = traverse_impact("a.ts", &edges_a, &controls);
        let res_b = traverse_impact("a.ts", &edges_b, &controls);
        assert_eq!(res_a, res_b);
    }

    #[test]
    fn traverse_respects_max_depth() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(1),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(!res
            .edges
            .iter()
            .any(|e| e.source == "b.ts" && e.target == "c.ts"));
    }

    #[test]
    fn traverse_max_depth_zero_returns_no_edges() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(0),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.edges.is_empty());
        assert!(res.truncated);
    }

    #[test]
    fn traverse_max_depth_two_includes_second_hop_but_not_third() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(2),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res
            .edges
            .iter()
            .any(|e| e.source == "b.ts" && e.target == "c.ts"));
        assert!(!res
            .edges
            .iter()
            .any(|e| e.source == "c.ts" && e.target == "d.ts"));
        assert!(res.truncated);
    }

    #[test]
    fn traverse_depth_limit_not_marked_truncated_when_fully_explored() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(3),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert_eq!(res.edges.len(), fixture_edges().len());
        assert!(!res.truncated);
    }

    #[test]
    fn traverse_filters_edge_types_by_kind() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res
            .edges
            .iter()
            .all(|e| e.kind.as_deref() == Some("include")));
        assert_eq!(res.edges.len(), 1);
        assert_eq!(res.edges[0].source, "x.ts");
        assert_eq!(res.edges[0].target, "a.ts");
    }

    #[test]
    fn traverse_edge_type_filter_marks_truncated_when_edges_are_excluded() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.truncated);
    }

    #[test]
    fn traverse_edge_type_filter_not_truncated_when_filter_excludes_nothing() {
        let edges = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("include".into()),
            },
            ImpactGraphEdge {
                source: "b.ts".into(),
                target: "c.ts".into(),
                kind: Some("include".into()),
            },
        ];
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &edges, &controls);
        assert!(!res.truncated);
    }

    #[test]
    fn expand_from_diff_files_one_hop() {
        let edges = fixture_edges();
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(10),
            max_depth: Some(1),
            edge_types: None,
        }
        .validate()
        .expect("controls");
        let result = expand_impact_from_edges(&vec!["./a.ts".into()], &edges, &controls);
        let expected: BTreeSet<ImpactGraphEdge> = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "x.ts".into(),
                target: "a.ts".into(),
                kind: Some("include".into()),
            },
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "z.ts".into(),
                kind: None,
            },
        ]
        .into_iter()
        .collect();
        let actual: BTreeSet<ImpactGraphEdge> = result.edges.into_iter().collect();
        assert_eq!(actual, expected);
        assert!(result.truncated);
    }

    #[test]
    fn assemble_context_tracks_expanded_files_and_prune_trace() {
        let edges = fixture_edges();
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(10),
            max_depth: Some(1),
            edge_types: None,
        }
        .validate()
        .expect("controls");
        let diff_files = vec!["./a.ts".to_string()];
        let expansion = expand_impact_from_edges(&diff_files, &edges, &controls);
        let context = assemble_impact_context(&diff_files, expansion, &controls);
        assert_eq!(context.sources, vec!["a.ts".to_string()]);
        assert_eq!(
            context.expanded_files,
            vec!["b.ts".to_string(), "x.ts".to_string(), "z.ts".to_string()]
        );
        assert_eq!(context.prune_trace.requested_sources, 1);
        assert_eq!(context.prune_trace.normalized_sources, 1);
        assert_eq!(context.prune_trace.dropped_sources, 0);
        assert_eq!(context.prune_trace.expanded_files, 3);
        assert_eq!(context.prune_trace.max_edges, 10);
        assert_eq!(context.prune_trace.max_depth, 1);
    }

    fn write_fixture(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent dir");
        }
        std::fs::write(path, content).expect("write fixture");
    }

    fn clear_import_hint_cache(repo_root: &Path, state_dir: &Path) {
        let key = import_hint_cache_key(repo_root, state_dir);
        let mut cache = IMPORT_HINT_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.remove(&key);
    }

    fn clear_repo_file_cache(repo_root: &Path) {
        let key = canonical_repo_root(repo_root);
        let mut cache = REPO_FILE_CACHE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.remove(&key);
    }

    #[test]
    fn js_template_literal_with_static_bindings_resolves() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("src/foo/bar.ts"), "export const x = 1;");
        let content = r#"
const part = "foo";
const name = "bar";
import(`./${part}/${name}.ts`);
"#;
        let result = extract_js_ts_import_edges(
            repo_root,
            repo_root,
            "src/main.ts",
            content,
            SourceLanguage::TypeScript,
        );
        assert!(
            result
                .edges
                .iter()
                .any(|edge| { edge.source == "src/main.ts" && edge.target == "src/foo/bar.ts" }),
            "expected template literal import to resolve"
        );
    }

    #[test]
    fn js_path_join_with_bindings_resolves() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(
            &repo_root.join("src/util/index.ts"),
            "export const util = true;",
        );
        let content = r#"
const segment = "util";
const target = path.join("./", segment, "index.ts");
require(target);
"#;
        let result = extract_js_ts_import_edges(
            repo_root,
            repo_root,
            "src/main.ts",
            content,
            SourceLanguage::JavaScript,
        );
        assert!(
            result
                .edges
                .iter()
                .any(|edge| { edge.source == "src/main.ts" && edge.target == "src/util/index.ts" }),
            "expected path.join import to resolve"
        );
    }

    #[test]
    fn python_os_path_join_resolves_spec_from_file_location() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("pkg/mod.py"), "value = 42");
        let content = r#"
import os
from importlib.util import spec_from_file_location
module_path = os.path.join("pkg", "mod.py")
spec_from_file_location("mod", module_path)
"#;
        let result = extract_python_import_edges(repo_root, repo_root, "main.py", content);
        assert!(
            result
                .edges
                .iter()
                .any(|edge| edge.source == "main.py" && edge.target == "pkg/mod.py"),
            "expected os.path.join to resolve in spec_from_file_location"
        );
    }

    #[test]
    fn js_path_resolve_with_bindings_resolves() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("src/dir/entry.js"), "module.exports = {};");
        let content = r#"
const base = "./dir";
const target = path.resolve(base, "entry.js");
require(target);
"#;
        let result = extract_js_ts_import_edges(
            repo_root,
            repo_root,
            "src/main.js",
            content,
            SourceLanguage::JavaScript,
        );
        assert!(
            result
                .edges
                .iter()
                .any(|edge| { edge.source == "src/main.js" && edge.target == "src/dir/entry.js" }),
            "expected path.resolve import to resolve"
        );
    }

    #[test]
    fn python_import_module_with_concat_resolves() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("pkg/extra.py"), "value = 42");
        let content = r#"
import importlib
BASE = "pkg"
importlib.import_module(BASE + ".extra")
"#;
        let result = extract_python_import_edges(repo_root, repo_root, "main.py", content);
        assert!(
            result
                .edges
                .iter()
                .any(|edge| edge.source == "main.py" && edge.target == "pkg/extra.py"),
            "expected importlib.import_module to resolve"
        );
    }

    #[test]
    fn js_template_pattern_expands_to_multiple_matches() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("src/tpl/alpha.js"), "export const a = 1;");
        write_fixture(&repo_root.join("src/tpl/beta.js"), "export const b = 2;");
        let content = r#"
const choice = getChoice();
require(`./tpl/${choice}.js`);
"#;
        let result = extract_js_ts_import_edges(
            repo_root,
            repo_root,
            "src/main.js",
            content,
            SourceLanguage::JavaScript,
        );
        assert!(
            result
                .edges
                .iter()
                .any(|edge| edge.source == "src/main.js" && edge.target == "src/tpl/alpha.js"),
            "expected template import to match alpha.js"
        );
        assert!(
            result
                .edges
                .iter()
                .any(|edge| edge.source == "src/main.js" && edge.target == "src/tpl/beta.js"),
            "expected template import to match beta.js"
        );
        assert!(result.diagnostics.is_none());
    }

    #[test]
    fn js_path_posix_join_resolves() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("src/posix/mod.js"), "module.exports = {};");
        let content = r#"
const target = path.posix.join("./posix", "mod.js");
require(target);
"#;
        let result = extract_js_ts_import_edges(
            repo_root,
            repo_root,
            "src/main.js",
            content,
            SourceLanguage::JavaScript,
        );
        assert!(
            result
                .edges
                .iter()
                .any(|edge| { edge.source == "src/main.js" && edge.target == "src/posix/mod.js" }),
            "expected path.posix.join import to resolve"
        );
    }

    #[test]
    fn python_f_string_spec_from_file_location_resolves() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("pkg/fmod.py"), "value = 42");
        let content = r#"
import importlib.util
name = "fmod"
spec_path = f"pkg/{name}.py"
importlib.util.spec_from_file_location(name, spec_path)
"#;
        let result = extract_python_import_edges(repo_root, repo_root, "main.py", content);
        assert!(
            result
                .edges
                .iter()
                .any(|edge| edge.source == "main.py" && edge.target == "pkg/fmod.py"),
            "expected f-string path in spec_from_file_location to resolve"
        );
    }

    #[test]
    fn python_source_file_loader_resolves() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        write_fixture(&repo_root.join("pkg/loader.py"), "value = 42");
        let content = r#"
import importlib.machinery
importlib.machinery.SourceFileLoader("loader", "pkg/loader.py")
"#;
        let result = extract_python_import_edges(repo_root, repo_root, "main.py", content);
        assert!(
            result
                .edges
                .iter()
                .any(|edge| edge.source == "main.py" && edge.target == "pkg/loader.py"),
            "expected SourceFileLoader to resolve"
        );
    }

    #[test]
    fn unresolved_import_samples_are_capped() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        let content = r#"
import "./missing-1.js";
import "./missing-2.js";
import "./missing-3.js";
import "./missing-4.js";
import "./missing-5.js";
import "./missing-6.js";
import "./missing-7.js";
"#;
        let result = extract_js_ts_import_edges(
            repo_root,
            repo_root,
            "src/main.js",
            content,
            SourceLanguage::JavaScript,
        );
        let diagnostics = result.diagnostics.expect("expected diagnostics");
        assert_eq!(diagnostics.unresolved_imports_total, 7);
        assert_eq!(
            diagnostics.unresolved_imports_sample.len(),
            UNRESOLVED_IMPORT_SAMPLE_LIMIT
        );
    }

    #[test]
    fn unresolved_relative_imports_reported() {
        let dir = TempDir::new().expect("tempdir");
        let repo_root = dir.path();
        let content = r#"import "./missing.js";"#;
        let result = extract_js_ts_import_edges(
            repo_root,
            repo_root,
            "src/main.ts",
            content,
            SourceLanguage::TypeScript,
        );
        let diagnostics = result.diagnostics.expect("expected diagnostics");
        assert_eq!(diagnostics.unresolved_imports_total, 1);
        assert_eq!(diagnostics.unresolved_imports_sample, vec!["./missing.js"]);
    }

    #[test]
    fn traverse_does_not_expand_through_excluded_edge_types() {
        let edges = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("include".into()),
            },
            ImpactGraphEdge {
                source: "b.ts".into(),
                target: "c.ts".into(),
                kind: Some("require".into()),
            },
            ImpactGraphEdge {
                source: "c.ts".into(),
                target: "d.ts".into(),
                kind: Some("include".into()),
            },
        ];
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &edges, &controls);

        assert!(res
            .edges
            .iter()
            .all(|edge| edge.kind.as_deref() == Some("include")));
        assert!(
            !res.edges
                .iter()
                .any(|edge| edge.source == "c.ts" && edge.target == "d.ts"),
            "should not reach c.ts without traversing the excluded b.ts -> c.ts require edge"
        );
    }

    #[test]
    fn store_accepts_type_alias_for_kind() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        std::fs::write(
            state_root.join("impact_graph.json"),
            r#"{ "edges": [ { "source": "a.ts", "target": "b.ts", "type": "import" } ] }"#,
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let edges = store.read_edges().expect("read edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind.as_deref(), Some("import"));
    }

    #[test]
    fn store_rejects_future_schema_versions() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        let payload = serde_json::json!({
            "schema": { "name": "docdex.impact_graph", "version": 99, "compatible": { "min": 99, "max": 99 } },
            "repo_id": "test-repo",
            "graphs": [
                {
                    "schema": { "name": "docdex.impact_graph", "version": 99, "compatible": { "min": 99, "max": 99 } },
                    "repo_id": "test-repo",
                    "source": "a.ts",
                    "inbound": [],
                    "outbound": [],
                    "edges": []
                }
            ]
        });
        std::fs::write(
            state_root.join("impact_graph.json"),
            serde_json::to_vec_pretty(&payload).expect("serialize impact_graph.json"),
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let err = store
            .read_edges()
            .expect_err("expected schema version error");
        assert!(
            err.to_string()
                .contains("impact graph schema version 99 is not compatible with current"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn store_accepts_newer_compatible_schema() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        let payload = serde_json::json!({
            "schema": { "name": "docdex.impact_graph", "version": 3, "compatible": { "min": 1, "max": 3 } },
            "repo_id": "test-repo",
            "graphs": [
                {
                    "schema": { "name": "docdex.impact_graph", "version": 3, "compatible": { "min": 1, "max": 3 } },
                    "repo_id": "test-repo",
                    "source": "a.ts",
                    "inbound": [],
                    "outbound": [],
                    "edges": [
                        { "source": "a.ts", "target": "b.ts", "kind": "import" }
                    ]
                }
            ]
        });
        std::fs::write(
            state_root.join("impact_graph.json"),
            serde_json::to_vec_pretty(&payload).expect("serialize impact_graph.json"),
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let edges = store.read_edges().expect("read edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].target, "b.ts");
    }

    #[test]
    fn store_migrates_v1_kind_normalization() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        let payload = serde_json::json!({
            "schema": { "name": "docdex.impact_graph", "version": 1, "compatible": { "min": 1, "max": 1 } },
            "repo_id": "test-repo",
            "graphs": [
                {
                    "schema": { "name": "docdex.impact_graph", "version": 1, "compatible": { "min": 1, "max": 1 } },
                    "repo_id": "test-repo",
                    "source": "a.ts",
                    "inbound": [],
                    "outbound": [],
                    "edges": [
                        { "source": "a.ts", "target": "b.ts", "kind": "Require" }
                    ]
                }
            ]
        });
        std::fs::write(
            state_root.join("impact_graph.json"),
            serde_json::to_vec_pretty(&payload).expect("serialize impact_graph.json"),
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let edges = store.read_edges().expect("read edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind.as_deref(), Some("require"));
    }

    #[test]
    fn store_migrates_entries_missing_schema() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        let payload = serde_json::json!([
            {
                "repo_id": "test-repo",
                "source": "a.ts",
                "inbound": [],
                "outbound": ["b.ts"],
                "edges": [
                    { "source": "a.ts", "target": "b.ts", "kind": "import" }
                ],
                "diagnostics": {
                    "unresolvedImportsTotal": 1,
                    "unresolvedImportsSample": ["./dyn.js"]
                }
            }
        ]);
        std::fs::write(
            state_root.join("impact_graph.json"),
            serde_json::to_vec_pretty(&payload).expect("serialize impact_graph.json"),
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let edges = store.read_edges().expect("read edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source, "a.ts");
        let diagnostics = store
            .read_diagnostics("a.ts")
            .expect("read diagnostics")
            .expect("missing diagnostics");
        assert_eq!(diagnostics.unresolved_imports_total, 1);
        assert_eq!(diagnostics.unresolved_imports_sample, vec!["./dyn.js"]);
    }

    #[test]
    fn store_cache_invalidates_when_file_changes_on_disk() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");

        let path = state_root.join("impact_graph.json");
        std::fs::write(
            &path,
            r#"{ "edges": [ { "source": "a.ts", "target": "b.ts", "type": "import" } ] }"#,
        )
        .expect("write initial impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let first = store.read_edges().expect("read initial edges");
        assert_eq!(first[0].target, "b.ts");

        std::fs::write(
            &path,
            r#"{ "edges": [ { "source": "a.ts", "target": "longer-target.ts", "type": "import" } ] }"#,
        )
        .expect("overwrite impact_graph.json");

        let second = store.read_edges().expect("read updated edges");
        assert_eq!(second[0].target, "longer-target.ts");
    }

    #[test]
    fn import_traces_and_map_edges_merge_for_source() {
        let repo = TempDir::new().expect("tempdir");
        let repo_root = repo.path();
        let state_root = repo_root.join(".docdex");
        let state_dir = state_root.join("index");
        fs::create_dir_all(&state_dir).expect("create state dir");
        fs::create_dir_all(repo_root.join("src")).expect("create src");

        fs::write(
            repo_root.join("docdex.import_map.json"),
            r#"
{
  "edges": [
    { "source": "src/app.js", "target": "src/hint.js", "kind": "import", "override": true }
  ],
  "mappings": [
    { "source": "src/app.js", "spec": "./util", "target": "src/override.js", "override": true }
  ]
}
"#,
        )
        .expect("write import map");
        fs::write(
            repo_root.join("docdex.import_traces.jsonl"),
            r#"
{ "source": "src/app.js", "target": "src/trace.js", "kind": "import" }
"#,
        )
        .expect("write import traces");
        fs::write(
            state_root.join("import_traces.jsonl"),
            r#"
{ "source": "src/app.js", "target": "src/state-trace.js", "kind": "import" }
"#,
        )
        .expect("write state import traces");

        let _settings_guard = ImpactSettingsGuard::apply(ImpactSettings {
            dynamic_import_scan_limit: 10_000,
            import_traces_enabled: true,
        });
        clear_import_hint_cache(repo_root, &state_dir);

        let hints = import_hints_for_repo(repo_root, &state_dir);
        assert_eq!(hints.edges.len(), 1);
        assert_eq!(hints.mappings.len(), 1);
        assert_eq!(hints.traces.len(), 2);

        let resolver = |root: &Path, _rel: &str, target: &str| normalize_hint_path(root, target);
        let merged = hint_edges_for_source(repo_root, "src/app.js", &hints, &resolver);
        assert!(merged.edges.iter().any(|edge| edge.target == "src/hint.js"));
        assert!(merged
            .edges
            .iter()
            .any(|edge| edge.target == "src/trace.js"));
        assert!(merged
            .edges
            .iter()
            .any(|edge| edge.target == "src/state-trace.js"));
        assert!(merged.override_targets.contains("src/hint.js"));
    }

    #[test]
    fn import_map_override_takes_priority_over_fallback() {
        let repo = TempDir::new().expect("tempdir");
        let repo_root = repo.path();
        let hints = ImportHints {
            edges: Vec::new(),
            mappings: vec![
                ImportMapMapping {
                    source: Some("src/app.js".to_string()),
                    spec: "./util".to_string(),
                    targets: vec!["src/override.js".to_string()],
                    kind: Some("import".to_string()),
                    expand: false,
                    override_edge: true,
                },
                ImportMapMapping {
                    source: Some("src/app.js".to_string()),
                    spec: "./util".to_string(),
                    targets: vec!["src/fallback.js".to_string()],
                    kind: Some("import".to_string()),
                    expand: false,
                    override_edge: false,
                },
            ],
            traces: Vec::new(),
        };
        let import_ref = ImportRef {
            path: ImportPath::Exact("./util".to_string()),
            kind: "import",
            language: SourceLanguage::JavaScript,
        };
        let resolver = |root: &Path, _rel: &str, target: &str| normalize_hint_path(root, target);
        let (overrides, fallbacks) =
            resolve_import_map_matches(repo_root, "src/app.js", &import_ref, &hints, &resolver);
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].target, "src/override.js");
        assert_eq!(fallbacks.len(), 1);
        assert_eq!(fallbacks[0].target, "src/fallback.js");
    }

    #[test]
    fn import_map_fallback_skips_when_matches_exist() {
        let repo = TempDir::new().expect("tempdir");
        let repo_root = repo.path();
        write_fixture(&repo_root.join("src/foo/a.js"), "export const a = 1;");
        write_fixture(&repo_root.join("src/foo/b.js"), "export const b = 2;");
        write_fixture(&repo_root.join("src/fallback.js"), "export const f = 3;");

        let hints = ImportHints {
            edges: Vec::new(),
            mappings: vec![ImportMapMapping {
                source: Some("src/main.js".to_string()),
                spec: "./foo/*.js".to_string(),
                targets: vec!["src/fallback.js".to_string()],
                kind: Some("import".to_string()),
                expand: false,
                override_edge: false,
            }],
            traces: Vec::new(),
        };
        let import_ref = ImportRef {
            path: ImportPath::Pattern(StringPattern {
                parts: vec!["./foo/".to_string(), ".js".to_string()],
                anchored_start: true,
                anchored_end: true,
            }),
            kind: "import",
            language: SourceLanguage::JavaScript,
        };

        let _settings_guard = ImpactSettingsGuard::apply(ImpactSettings {
            dynamic_import_scan_limit: 10_000,
            import_traces_enabled: false,
        });
        clear_repo_file_cache(repo_root);

        let resolver = |root: &Path, _rel: &str, target: &str| normalize_hint_path(root, target);
        let resolved = resolve_import_ref(repo_root, "src/main.js", &import_ref, &hints, &resolver)
            .expect("missing resolution");
        assert_eq!(resolved.len(), 2);
        let targets: BTreeSet<String> = resolved.into_iter().map(|item| item.target).collect();
        assert!(targets.contains("src/foo/a.js"));
        assert!(targets.contains("src/foo/b.js"));
        assert!(!targets.contains("src/fallback.js"));
    }
}
