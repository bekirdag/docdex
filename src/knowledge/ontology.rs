use crate::config::{
    MemoryConversationGraphConfig, MemoryConversationGraphEntityTypeConfig,
    MemoryConversationGraphRelationTypeConfig,
};
use crate::knowledge::entity_registry::{normalize_entity_name, normalize_relation_name};
use crate::knowledge::types::KnowledgeFactCandidate;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelationCardinality {
    ManyToMany,
    OneToMany,
    ManyToOne,
    OneToOne,
}

impl RelationCardinality {
    fn from_config(value: Option<&str>) -> Option<Self> {
        let normalized = value
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(normalize_relation_name)?;
        match normalized.as_str() {
            "many_to_many" => Some(Self::ManyToMany),
            "one_to_many" => Some(Self::OneToMany),
            "many_to_one" => Some(Self::ManyToOne),
            "one_to_one" => Some(Self::OneToOne),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KnowledgeEntityType {
    pub name: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KnowledgeRelationType {
    pub name: String,
    pub aliases: Vec<String>,
    pub subject_types: Vec<String>,
    pub object_types: Vec<String>,
    pub allow_literal_object: bool,
    pub cardinality: RelationCardinality,
}

#[derive(Debug, Clone)]
pub struct KnowledgeOntology {
    strict_validation: bool,
    entity_types: HashMap<String, KnowledgeEntityType>,
    entity_aliases: HashMap<String, String>,
    relation_types: HashMap<String, KnowledgeRelationType>,
    relation_aliases: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedKnowledgeCandidate {
    pub relation: String,
    pub subject_type: String,
    pub object_type: Option<String>,
    pub cardinality: RelationCardinality,
}

impl KnowledgeOntology {
    pub fn builtin() -> Self {
        let mut ontology = Self {
            strict_validation: true,
            entity_types: HashMap::new(),
            entity_aliases: HashMap::new(),
            relation_types: HashMap::new(),
            relation_aliases: HashMap::new(),
        };
        for entity in builtin_entity_types() {
            ontology.upsert_entity_type(entity);
        }
        for relation in builtin_relation_types() {
            ontology.upsert_relation_type(relation);
        }
        ontology
    }

    pub fn from_graph_config(config: Option<&MemoryConversationGraphConfig>) -> Self {
        let mut ontology = Self::builtin();
        if let Some(config) = config {
            ontology.strict_validation = config.strict_ontology_validation;
            for entity in &config.entity_types {
                ontology.upsert_entity_type(entity_from_config(entity));
            }
            for relation in &config.relation_types {
                ontology.upsert_relation_type(relation_from_config(relation));
            }
        }
        ontology
    }

    pub fn validate_candidate(
        &self,
        candidate: &KnowledgeFactCandidate,
        subject: &str,
        object_text: &str,
    ) -> Option<ValidatedKnowledgeCandidate> {
        let relation = self.resolve_relation(&candidate.relation)?;
        let relation_def = self
            .relation_types
            .get(&relation)
            .cloned()
            .unwrap_or_else(|| KnowledgeRelationType {
                name: relation.clone(),
                aliases: Vec::new(),
                subject_types: Vec::new(),
                object_types: Vec::new(),
                allow_literal_object: true,
                cardinality: RelationCardinality::ManyToMany,
            });
        let subject_type = self.resolve_entity_type(
            candidate.subject_type_hint.as_deref(),
            subject,
            &candidate.subject_aliases,
            subject_fallback_type(candidate.category.as_str()),
        )?;
        if !relation_def.subject_types.is_empty()
            && !relation_def
                .subject_types
                .iter()
                .any(|value| value == &subject_type)
        {
            return if self.strict_validation {
                None
            } else {
                Some(ValidatedKnowledgeCandidate {
                    relation,
                    subject_type: "concept".to_string(),
                    object_type: resolve_object_type(self, &relation_def, candidate, object_text),
                    cardinality: relation_def.cardinality,
                })
            };
        }
        let object_type = resolve_object_type(self, &relation_def, candidate, object_text);
        if candidate.object_entity.is_none()
            && !relation_def.allow_literal_object
            && self.strict_validation
        {
            return None;
        }
        if let Some(object_type) = object_type.as_ref() {
            if !relation_def.object_types.is_empty()
                && !relation_def
                    .object_types
                    .iter()
                    .any(|value| value == object_type)
                && self.strict_validation
            {
                return None;
            }
        }
        Some(ValidatedKnowledgeCandidate {
            relation,
            subject_type,
            object_type,
            cardinality: relation_def.cardinality,
        })
    }

    fn upsert_entity_type(&mut self, entity: KnowledgeEntityType) {
        let canonical = normalize_entity_name(&entity.name);
        if canonical.is_empty() {
            return;
        }
        let aliases = normalize_alias_list(&entity.aliases);
        self.entity_aliases
            .insert(canonical.clone(), canonical.clone());
        for alias in &aliases {
            self.entity_aliases.insert(alias.clone(), canonical.clone());
        }
        self.entity_types.insert(
            canonical.clone(),
            KnowledgeEntityType {
                name: canonical,
                aliases,
            },
        );
    }

    fn upsert_relation_type(&mut self, relation: KnowledgeRelationType) {
        let canonical = normalize_relation_name(&relation.name);
        if canonical.is_empty() {
            return;
        }
        let aliases = normalize_relation_alias_list(&relation.aliases);
        self.relation_aliases
            .insert(canonical.clone(), canonical.clone());
        for alias in &aliases {
            self.relation_aliases
                .insert(alias.clone(), canonical.clone());
        }
        self.relation_types.insert(
            canonical.clone(),
            KnowledgeRelationType {
                name: canonical,
                aliases,
                subject_types: normalize_type_list(&relation.subject_types),
                object_types: normalize_type_list(&relation.object_types),
                allow_literal_object: relation.allow_literal_object,
                cardinality: relation.cardinality,
            },
        );
    }

    fn resolve_relation(&self, relation: &str) -> Option<String> {
        let normalized = normalize_relation_name(relation);
        if normalized.is_empty() {
            return None;
        }
        if let Some(canonical) = self.relation_aliases.get(&normalized) {
            return Some(canonical.clone());
        }
        if self.strict_validation {
            None
        } else {
            Some(normalized)
        }
    }

    fn resolve_entity_type(
        &self,
        hint: Option<&str>,
        primary_name: &str,
        aliases: &[String],
        fallback: Option<&str>,
    ) -> Option<String> {
        if let Some(hint) = hint
            .map(normalize_entity_name)
            .filter(|value| !value.is_empty())
        {
            if let Some(canonical) = self.entity_aliases.get(&hint) {
                return Some(canonical.clone());
            }
            if self.strict_validation {
                return None;
            }
            return Some(hint);
        }
        if let Some(inferred) = infer_entity_type(primary_name, aliases) {
            if let Some(canonical) = self.entity_aliases.get(&inferred) {
                return Some(canonical.clone());
            }
            if !self.strict_validation {
                return Some(inferred);
            }
        }
        let fallback = fallback
            .map(normalize_entity_name)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "concept".to_string());
        if let Some(canonical) = self.entity_aliases.get(&fallback) {
            return Some(canonical.clone());
        }
        if self.strict_validation {
            None
        } else {
            Some(fallback)
        }
    }
}

fn resolve_object_type(
    ontology: &KnowledgeOntology,
    relation: &KnowledgeRelationType,
    candidate: &KnowledgeFactCandidate,
    object_text: &str,
) -> Option<String> {
    if let Some(object_entity) = candidate
        .object_entity
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return ontology.resolve_entity_type(
            candidate.object_type_hint.as_deref(),
            object_entity,
            &candidate.object_aliases,
            object_fallback_type(candidate.category.as_str()),
        );
    }
    if let Some(hint) = candidate.object_type_hint.as_deref() {
        return ontology.resolve_entity_type(
            Some(hint),
            object_text,
            &candidate.object_aliases,
            None,
        );
    }
    if relation.allow_literal_object {
        return ontology.resolve_entity_type(
            None,
            object_text,
            &candidate.object_aliases,
            object_fallback_type(candidate.category.as_str()),
        );
    }
    None
}

fn entity_from_config(config: &MemoryConversationGraphEntityTypeConfig) -> KnowledgeEntityType {
    KnowledgeEntityType {
        name: config.name.clone(),
        aliases: config.aliases.clone(),
    }
}

fn relation_from_config(
    config: &MemoryConversationGraphRelationTypeConfig,
) -> KnowledgeRelationType {
    KnowledgeRelationType {
        name: config.name.clone(),
        aliases: config.aliases.clone(),
        subject_types: config.subject_types.clone(),
        object_types: config.object_types.clone(),
        allow_literal_object: config.allow_literal_object,
        cardinality: RelationCardinality::from_config(config.cardinality.as_deref())
            .unwrap_or(RelationCardinality::ManyToMany),
    }
}

fn builtin_entity_types() -> Vec<KnowledgeEntityType> {
    vec![
        KnowledgeEntityType {
            name: "concept".to_string(),
            aliases: vec!["entity".to_string()],
        },
        KnowledgeEntityType {
            name: "repo".to_string(),
            aliases: vec!["repository".to_string(), "project".to_string()],
        },
        KnowledgeEntityType {
            name: "file".to_string(),
            aliases: vec!["path".to_string(), "document".to_string()],
        },
        KnowledgeEntityType {
            name: "symbol".to_string(),
            aliases: vec![
                "function".to_string(),
                "module".to_string(),
                "class".to_string(),
            ],
        },
        KnowledgeEntityType {
            name: "tool".to_string(),
            aliases: vec!["library".to_string(), "technology".to_string()],
        },
        KnowledgeEntityType {
            name: "decision".to_string(),
            aliases: vec!["policy".to_string()],
        },
        KnowledgeEntityType {
            name: "preference".to_string(),
            aliases: vec!["style".to_string()],
        },
        KnowledgeEntityType {
            name: "constraint".to_string(),
            aliases: vec!["rule".to_string()],
        },
        KnowledgeEntityType {
            name: "workflow".to_string(),
            aliases: vec!["process".to_string()],
        },
    ]
}

fn builtin_relation_types() -> Vec<KnowledgeRelationType> {
    vec![
        relation(
            "repo_fact",
            &["repo"],
            &["concept", "file", "symbol", "tool"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "decision",
            &["repo", "concept"],
            &["decision", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "style_preference",
            &["repo", "concept"],
            &["preference", "tool", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "tooling_choice",
            &["repo", "concept"],
            &["tool", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "constraint",
            &["repo", "concept"],
            &["constraint", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "workflow",
            &["repo", "concept"],
            &["workflow", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "located_in",
            &["symbol", "file", "concept"],
            &["file", "repo", "concept"],
            true,
            RelationCardinality::ManyToOne,
        ),
        relation(
            "uses",
            &["repo", "symbol", "file", "concept"],
            &["tool", "symbol", "file", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "depends_on",
            &["repo", "symbol", "file", "concept"],
            &["tool", "symbol", "file", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "prefers",
            &["repo", "concept"],
            &["tool", "preference", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
        relation(
            "avoid_prefer",
            &["repo", "concept"],
            &["tool", "preference", "concept"],
            true,
            RelationCardinality::ManyToMany,
        ),
    ]
}

fn relation(
    name: &str,
    subject_types: &[&str],
    object_types: &[&str],
    allow_literal_object: bool,
    cardinality: RelationCardinality,
) -> KnowledgeRelationType {
    KnowledgeRelationType {
        name: name.to_string(),
        aliases: Vec::new(),
        subject_types: subject_types.iter().map(|item| item.to_string()).collect(),
        object_types: object_types.iter().map(|item| item.to_string()).collect(),
        allow_literal_object,
        cardinality,
    }
}

fn normalize_alias_list(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for value in values {
        let normalized = normalize_entity_name(value);
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }
        items.push(normalized);
    }
    items
}

fn normalize_relation_alias_list(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for value in values {
        let normalized = normalize_relation_name(value);
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }
        items.push(normalized);
    }
    items
}

fn normalize_type_list(values: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();
    for value in values {
        let normalized = normalize_entity_name(value);
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }
        items.push(normalized);
    }
    items
}

fn infer_entity_type(primary_name: &str, aliases: &[String]) -> Option<String> {
    let normalized = normalize_entity_name(primary_name);
    if normalized.is_empty() {
        return None;
    }
    if looks_like_repo(&normalized) {
        return Some("repo".to_string());
    }
    if looks_like_file(primary_name) || aliases.iter().any(|alias| looks_like_file(alias)) {
        return Some("file".to_string());
    }
    if looks_like_symbol(primary_name) || aliases.iter().any(|alias| looks_like_symbol(alias)) {
        return Some("symbol".to_string());
    }
    if looks_like_tool(&normalized) {
        return Some("tool".to_string());
    }
    None
}

fn looks_like_repo(value: &str) -> bool {
    value == "repo"
        || value.ends_with(" repo")
        || value == "repository"
        || value.ends_with(" repository")
        || value == "project"
        || value.ends_with(" project")
}

fn looks_like_file(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.contains('/')
        || trimmed.ends_with(".rs")
        || trimmed.ends_with(".ts")
        || trimmed.ends_with(".tsx")
        || trimmed.ends_with(".js")
        || trimmed.ends_with(".json")
        || trimmed.ends_with(".toml")
        || trimmed.ends_with(".md")
}

fn looks_like_symbol(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.contains("::")
        || trimmed.contains('#')
        || trimmed.contains("()")
        || trimmed
            .chars()
            .next()
            .map(|ch| ch.is_ascii_uppercase())
            .unwrap_or(false)
}

fn looks_like_tool(value: &str) -> bool {
    matches!(
        value,
        "sqlite" | "rust" | "tokio" | "serde" | "axum" | "mcp" | "ollama" | "cargo" | "docdex"
    )
}

fn subject_fallback_type(category: &str) -> Option<&'static str> {
    match normalize_relation_name(category).as_str() {
        "repo_fact" | "decision" | "style" | "tooling" | "constraint" | "workflow" => Some("repo"),
        _ => None,
    }
}

fn object_fallback_type(category: &str) -> Option<&'static str> {
    match normalize_relation_name(category).as_str() {
        "decision" => Some("decision"),
        "style" => Some("preference"),
        "tooling" => Some("tool"),
        "constraint" => Some("constraint"),
        "workflow" => Some("workflow"),
        _ => None,
    }
}
