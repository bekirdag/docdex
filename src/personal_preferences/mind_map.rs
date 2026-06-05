use super::*;

#[derive(Debug, Clone)]
pub(super) struct MindMapEntity {
    pub(super) node_id: String,
    pub(super) node_type: String,
    pub(super) label: String,
    pub(super) summary: String,
    pub(super) relation: String,
    pub(super) weight: f32,
}

pub(super) fn upsert_mind_map_node(
    nodes: &mut Vec<PersonalPreferenceMindMapNode>,
    node_index: &mut BTreeMap<String, usize>,
    id: &str,
    node_type: &str,
    label: &str,
    summary: &str,
    weight: f32,
    claim_id: Option<&str>,
    metadata: Value,
) {
    if let Some(index) = node_index.get(id).copied() {
        let node = &mut nodes[index];
        node.weight = node.weight.max(weight);
        if let Some(claim_id) = claim_id {
            if !node.claim_ids.iter().any(|value| value == claim_id) {
                node.claim_ids.push(claim_id.to_string());
            }
        }
        return;
    }
    let mut claim_ids = Vec::new();
    if let Some(claim_id) = claim_id {
        claim_ids.push(claim_id.to_string());
    }
    node_index.insert(id.to_string(), nodes.len());
    nodes.push(PersonalPreferenceMindMapNode {
        id: id.to_string(),
        node_type: node_type.to_string(),
        label: label.to_string(),
        summary: summary.to_string(),
        weight,
        claim_ids,
        metadata,
    });
}

pub(super) fn push_mind_map_edge(
    edges: &mut Vec<PersonalPreferenceMindMapEdge>,
    edge_keys: &mut HashSet<String>,
    source_id: &str,
    target_id: &str,
    relation: &str,
    summary: &str,
    weight: f32,
    claim_id: Option<&str>,
    metadata: Value,
) {
    let key = format!("{source_id}->{relation}->{target_id}");
    if !edge_keys.insert(key.clone()) {
        if let Some(edge) = edges.iter_mut().find(|edge| edge.id == key) {
            edge.weight = edge.weight.max(weight);
            if let Some(claim_id) = claim_id {
                if !edge.claim_ids.iter().any(|value| value == claim_id) {
                    edge.claim_ids.push(claim_id.to_string());
                }
            }
        }
        return;
    }
    let mut claim_ids = Vec::new();
    if let Some(claim_id) = claim_id {
        claim_ids.push(claim_id.to_string());
    }
    edges.push(PersonalPreferenceMindMapEdge {
        id: key,
        source_id: source_id.to_string(),
        target_id: target_id.to_string(),
        relation: relation.to_string(),
        summary: summary.to_string(),
        weight,
        claim_ids,
        metadata,
    });
}

pub(super) fn mind_map_claim_score(claim: &PersonalPreferenceClaim, query: &str) -> f32 {
    let content = render_claim_content(claim);
    let mut score = claim.confidence * 10.0
        + truth_status_rank(&claim.truth_status) as f32
        + stability_rank(&claim.stability_class) as f32
        + clone_term_match_score(&content, query);
    if query_is_operator_style(query)
        && matches!(
            claim.category.as_str(),
            "operator_routine" | "workflow_method" | "quality_bar" | "delivery_preference"
        )
    {
        score += 4.0;
    }
    if claim.claim_origin == CLAIM_ORIGIN_CROSS_SESSION_INFERENCE {
        score += 1.0;
    }
    score
}

pub(super) fn query_is_operator_style(query: &str) -> bool {
    let normalized = query.to_ascii_lowercase();
    [
        "how", "usually", "workflow", "routine", "operator", "ship", "fix", "build", "develop",
        "project",
    ]
    .iter()
    .any(|term| normalized.contains(term))
}

pub(super) fn mind_map_relation_for_claim(claim: &PersonalPreferenceClaim) -> &'static str {
    match claim.category.as_str() {
        "operator_routine" => "runs_routine",
        "workflow_method" | "decision_style" => "asks_agents_to",
        "quality_bar" => "validates_with",
        "delivery_preference" => "prefers_delivery_flow",
        "tooling_preference" | "coding_preference" | "architecture_preference" => "prefers",
        "current_projects" | "product_goals" | "business_context" => "works_toward",
        "cross_project_bridge" => "reuses_across_projects",
        _ => "prefers",
    }
}

pub(super) fn mind_map_node_type_for_claim(claim: &PersonalPreferenceClaim) -> &'static str {
    match claim.category.as_str() {
        "operator_routine" => "operator_routine",
        "workflow_method" | "decision_style" => "workflow_method",
        "quality_bar" => "validation_habit",
        "delivery_preference" => "delivery_habit",
        "current_projects" | "product_goals" | "business_context" => "project_goal",
        "cross_project_bridge" => "cross_project_bridge",
        "tooling_preference" => "tool_preference",
        _ => "claim",
    }
}

pub(super) fn mind_map_label_for_claim(claim: &PersonalPreferenceClaim) -> String {
    claim
        .attribute
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| claim.subcategory.clone())
        .unwrap_or_else(|| claim.category.clone())
}

pub(super) fn mind_map_entities_for_claim(claim: &PersonalPreferenceClaim) -> Vec<MindMapEntity> {
    let blob = render_claim_content(claim).to_ascii_lowercase();
    let mut entities = Vec::new();
    if blob.contains("docs/planning")
        || blob.contains("progress markdown")
        || blob.contains("progress file")
    {
        entities.push(MindMapEntity {
            node_id: "docs_folder:docs/planning".to_string(),
            node_type: "docs_folder".to_string(),
            label: "docs/planning".to_string(),
            summary: "User stores implementation plans and progress documents under docs/planning."
                .to_string(),
            relation: "stores_progress_in".to_string(),
            weight: 0.9,
        });
    }
    if blob.contains("docdex") || blob.contains("impact graph") || blob.contains("dag") {
        entities.push(MindMapEntity {
            node_id: "tool:docdex".to_string(),
            node_type: "tool".to_string(),
            label: "Docdex".to_string(),
            summary: "User expects agents to use Docdex search, symbols, impact graphs, memory, or DAG reasoning for repo work.".to_string(),
            relation: "uses".to_string(),
            weight: 0.9,
        });
    }
    if blob.contains("test")
        || blob.contains("run-tests")
        || blob.contains("build")
        || blob.contains("validation")
    {
        entities.push(MindMapEntity {
            node_id: "validation_flow:tests".to_string(),
            node_type: "validation_flow".to_string(),
            label: "Tests And Validation".to_string(),
            summary: "User validates meaningful work with targeted tests, builds, or recorded validation evidence.".to_string(),
            relation: "validates_with".to_string(),
            weight: 0.85,
        });
    }
    if blob.contains("git")
        || blob.contains("commit")
        || blob.contains("tag")
        || blob.contains("push")
    {
        entities.push(MindMapEntity {
            node_id: "git_flow:commit_tag_push".to_string(),
            node_type: "git_flow".to_string(),
            label: "Commit, Tag, Push".to_string(),
            summary: "User often wants validated work committed, tagged, pushed, or kept synchronized when requested.".to_string(),
            relation: "commits_after".to_string(),
            weight: 0.82,
        });
    }
    if blob.contains("deploy")
        || blob.contains("production")
        || blob.contains("ci/cd")
        || blob.contains("docker")
    {
        entities.push(MindMapEntity {
            node_id: "deployment_flow:controlled_deploy".to_string(),
            node_type: "deployment_flow".to_string(),
            label: "Controlled Deploy".to_string(),
            summary: "User expects production/deployment actions to be deliberate and validated."
                .to_string(),
            relation: "deploys_via".to_string(),
            weight: 0.8,
        });
    }
    if blob.contains("backup") || blob.contains("rollback") || blob.contains("fallback") {
        entities.push(MindMapEntity {
            node_id: "backup_pattern:rollback_awareness".to_string(),
            node_type: "backup_pattern".to_string(),
            label: "Backup Or Rollback Awareness".to_string(),
            summary:
                "User wants backup, rollback, or fallback-state awareness around high-risk work."
                    .to_string(),
            relation: "backs_up_before".to_string(),
            weight: 0.78,
        });
    }
    entities
}
