use crate::impact::{ImpactDiagnostics, ImpactGraphEdge, ImpactGraphStore};
use anyhow::Result;
use std::collections::BTreeSet;
use std::collections::HashMap;

use super::Indexer;

impl Indexer {
    pub(super) fn write_impact_graph(
        &self,
        edges: Vec<ImpactGraphEdge>,
        diagnostics: HashMap<String, ImpactDiagnostics>,
    ) -> Result<()> {
        let store = ImpactGraphStore::new(self.config.state_dir());
        let repo_id = crate::symbols::repo_id_for_root(self.repo_root())?;
        store.write_graph(&repo_id, &edges, Some(&diagnostics))
    }

    pub(super) fn update_impact_graph_for_file(
        &self,
        rel_path: &str,
        new_edges: &[ImpactGraphEdge],
        diagnostics: Option<ImpactDiagnostics>,
    ) -> Result<()> {
        let store = ImpactGraphStore::new(self.config.state_dir());
        let (existing, mut diagnostics_map) = store.read_snapshot_for_update()?;
        let mut merged: BTreeSet<ImpactGraphEdge> = BTreeSet::new();
        for edge in existing {
            if edge.source == rel_path {
                continue;
            }
            merged.insert(edge);
        }
        for edge in new_edges {
            merged.insert(edge.clone());
        }
        if let Some(diag) = diagnostics {
            diagnostics_map.insert(rel_path.to_string(), diag);
        } else {
            diagnostics_map.remove(rel_path);
        }
        let repo_id = crate::symbols::repo_id_for_root(self.repo_root())?;
        store.write_graph(
            &repo_id,
            &merged.into_iter().collect::<Vec<_>>(),
            Some(&diagnostics_map),
        )
    }

    pub(super) fn remove_impact_edges_for_file(&self, rel_path: &str) -> Result<()> {
        let store = ImpactGraphStore::new(self.config.state_dir());
        let (existing, mut diagnostics_map) = store.read_snapshot_for_update()?;
        let mut merged: BTreeSet<ImpactGraphEdge> = BTreeSet::new();
        for edge in existing {
            if edge.source == rel_path || edge.target == rel_path {
                continue;
            }
            merged.insert(edge);
        }
        diagnostics_map.remove(rel_path);
        let repo_id = crate::symbols::repo_id_for_root(self.repo_root())?;
        store.write_graph(
            &repo_id,
            &merged.into_iter().collect::<Vec<_>>(),
            Some(&diagnostics_map),
        )
    }
}
