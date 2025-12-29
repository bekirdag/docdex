use once_cell::sync::Lazy;
use regex::Regex;

use crate::impact::ImpactGraphEdge;
use crate::index::Indexer;
use crate::symbols::is_any_type_node;
use anyhow::Result;
use std::collections::HashSet;

const DEFAULT_AST_CHECK_NODES: usize = 20_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstraintRule {
    NoAnyTypes,
    NoCircularDependencies,
}

#[derive(Debug, Clone)]
pub struct ConstraintViolation {
    pub rule: ConstraintRule,
    pub message: String,
    pub file: Option<String>,
    pub line: Option<u32>,
}

struct ConstraintMatcher {
    rule: ConstraintRule,
    pattern: Regex,
}

static MATCHERS: Lazy<Vec<ConstraintMatcher>> = Lazy::new(|| {
    vec![
        ConstraintMatcher {
            rule: ConstraintRule::NoAnyTypes,
            pattern: Regex::new(r"(no|avoid|ban)\s+any(\s+types?)?").expect("regex"),
        },
        ConstraintMatcher {
            rule: ConstraintRule::NoCircularDependencies,
            pattern: Regex::new(r"(no|avoid|ban)\s+(circular|cycle)\s+(deps|dependencies)?")
                .expect("regex"),
        },
    ]
});

pub fn match_constraint_rules(text: &str) -> Vec<ConstraintRule> {
    let lowered = text.to_ascii_lowercase();
    MATCHERS
        .iter()
        .filter_map(|matcher| {
            if matcher.pattern.is_match(&lowered) {
                Some(matcher.rule)
            } else {
                None
            }
        })
        .collect()
}

pub fn check_any_type_usage(
    indexer: &Indexer,
    files: &[String],
) -> Result<Vec<ConstraintViolation>> {
    let mut violations = Vec::new();
    for file in files {
        let Some(ast) = indexer.read_ast(file, DEFAULT_AST_CHECK_NODES)? else {
            continue;
        };
        for node in &ast.nodes {
            if is_any_type_node(node) {
                violations.push(ConstraintViolation {
                    rule: ConstraintRule::NoAnyTypes,
                    message: "TypeScript `any` type is not allowed".to_string(),
                    file: Some(file.clone()),
                    line: Some(node.range.start_line.saturating_add(1)),
                });
            }
        }
    }
    Ok(violations)
}

pub fn check_circular_dependencies(
    edges: &[ImpactGraphEdge],
    staged_files: &[String],
) -> Vec<ConstraintViolation> {
    let staged: HashSet<&str> = staged_files.iter().map(|path| path.as_str()).collect();
    crate::impact::detect_cycles(edges)
        .into_iter()
        .filter(|cycle| staged.is_empty() || cycle.iter().any(|node| staged.contains(node.as_str())))
        .map(|cycle| {
            let mut cycle_path = cycle.clone();
            if let Some(first) = cycle.first() {
                cycle_path.push(first.clone());
            }
            ConstraintViolation {
                rule: ConstraintRule::NoCircularDependencies,
                message: format!("Circular dependency detected: {}", cycle_path.join(" -> ")),
                file: cycle.first().cloned(),
                line: None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_no_any_types() {
        let rules = match_constraint_rules("No any types in TypeScript.");
        assert!(rules.contains(&ConstraintRule::NoAnyTypes));
    }

    #[test]
    fn matches_no_circular_dependencies() {
        let rules = match_constraint_rules("Avoid circular dependencies in core.");
        assert!(rules.contains(&ConstraintRule::NoCircularDependencies));
    }

    #[test]
    fn ignores_style_or_tooling_text() {
        let rules = match_constraint_rules("Use Tailwind and CSS Modules.");
        assert!(rules.is_empty());
    }
}
