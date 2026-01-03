use crate::symbols::{self as doc_symbols, SymbolOutcome, SymbolOutcomeStatus, SymbolsStore};
use std::path::Path;
use tracing::warn;

use super::{DocumentIngest, Indexer};

pub(super) fn open_symbols_store(
    repo_root: &Path,
    state_dir: &Path,
    warn_on_error: bool,
) -> Option<SymbolsStore> {
    match SymbolsStore::new(repo_root, state_dir) {
        Ok(store) => Some(store),
        Err(err) => {
            if warn_on_error {
                warn!(target: "docdexd", error = ?err, "symbols store init failed; symbol + impact extraction disabled for this run");
            }
            None
        }
    }
}

impl Indexer {
    pub(super) fn reset_symbols_store(&self) {
        let Some(store) = self.symbols_store.as_ref() else {
            return;
        };
        if let Err(err) = store.reset() {
            warn!(target: "docdexd", error = ?err, "failed to reset symbols store; continuing without clearing old symbols");
        }
    }

    pub(super) fn delete_symbols_record(&self, rel_path: &str) {
        let Some(store) = self.symbols_store.as_ref() else {
            return;
        };
        if let Err(err) = store.delete_symbols(rel_path) {
            warn!(target: "docdexd", error = ?err, rel_path = %rel_path, "failed to delete symbols record");
        }
    }

    pub(super) fn maybe_update_symbols(&self, ingest: &DocumentIngest) {
        let Some(store) = self.symbols_store.as_ref() else {
            return;
        };

        let Some(language) = doc_symbols::language_for_path(&ingest.rel_path) else {
            let payload = doc_symbols::build_symbols_payload(
                store.repo_id(),
                &ingest.rel_path,
                Vec::new(),
                SymbolOutcome {
                    status: SymbolOutcomeStatus::Skipped,
                    reason: Some("unsupported_language".to_string()),
                    error_summary: None,
                },
            );
            if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
            }
            let ast_payload = doc_symbols::build_ast_payload(
                store.repo_id(),
                &ingest.rel_path,
                None,
                Vec::new(),
                0,
                false,
                SymbolOutcome {
                    status: SymbolOutcomeStatus::Skipped,
                    reason: Some("unsupported_language".to_string()),
                    error_summary: None,
                },
            );
            if let Err(err) = store.upsert_ast(&ingest.rel_path, &ast_payload) {
                warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist ast outcome");
            }
            return;
        };

        if let Some(err) = ingest.read_error.as_ref() {
            let payload = doc_symbols::build_symbols_payload(
                store.repo_id(),
                &ingest.rel_path,
                Vec::new(),
                SymbolOutcome {
                    status: SymbolOutcomeStatus::Failed,
                    reason: Some(format!("read_failed ({})", language.as_str())),
                    error_summary: Some(err.clone()),
                },
            );
            if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
            }
            let ast_payload = doc_symbols::build_ast_payload(
                store.repo_id(),
                &ingest.rel_path,
                Some(language.as_str().to_string()),
                Vec::new(),
                0,
                false,
                SymbolOutcome {
                    status: SymbolOutcomeStatus::Failed,
                    reason: Some(format!("read_failed ({})", language.as_str())),
                    error_summary: Some(err.clone()),
                },
            );
            if let Err(err) = store.upsert_ast(&ingest.rel_path, &ast_payload) {
                warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist ast outcome");
            }
            return;
        }

        match doc_symbols::extract_symbols_best_effort(
            store.repo_id(),
            &ingest.rel_path,
            &ingest.content,
            language,
        ) {
            Ok(symbols) => {
                let payload = doc_symbols::build_symbols_payload(
                    store.repo_id(),
                    &ingest.rel_path,
                    symbols,
                    SymbolOutcome {
                        status: SymbolOutcomeStatus::Ok,
                        reason: None,
                        error_summary: None,
                    },
                );
                if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                    warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
                }
            }
            Err(err) => {
                let payload = doc_symbols::build_symbols_payload(
                    store.repo_id(),
                    &ingest.rel_path,
                    Vec::new(),
                    SymbolOutcome {
                        status: SymbolOutcomeStatus::Failed,
                        reason: Some(format!("extract_failed ({})", language.as_str())),
                        error_summary: Some(err.to_string()),
                    },
                );
                if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                    warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
                }
            }
        };

        if matches!(language, doc_symbols::SourceLanguage::Markdown) {
            let ast_payload = doc_symbols::build_ast_payload(
                store.repo_id(),
                &ingest.rel_path,
                Some(language.as_str().to_string()),
                Vec::new(),
                0,
                false,
                SymbolOutcome {
                    status: SymbolOutcomeStatus::Skipped,
                    reason: Some("unsupported_language".to_string()),
                    error_summary: None,
                },
            );
            if let Err(err) = store.upsert_ast(&ingest.rel_path, &ast_payload) {
                warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist ast outcome");
            }
        } else {
            match doc_symbols::extract_ast_nodes_best_effort(
                &ingest.rel_path,
                &ingest.content,
                language,
            ) {
                Ok(result) => {
                    let ast_payload = doc_symbols::build_ast_payload(
                        store.repo_id(),
                        &ingest.rel_path,
                        Some(language.as_str().to_string()),
                        result.nodes,
                        result.total_nodes,
                        result.truncated,
                        SymbolOutcome {
                            status: SymbolOutcomeStatus::Ok,
                            reason: None,
                            error_summary: None,
                        },
                    );
                    if let Err(err) = store.upsert_ast(&ingest.rel_path, &ast_payload) {
                        warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist ast outcome");
                    }
                }
                Err(err) => {
                    let ast_payload = doc_symbols::build_ast_payload(
                        store.repo_id(),
                        &ingest.rel_path,
                        Some(language.as_str().to_string()),
                        Vec::new(),
                        0,
                        false,
                        SymbolOutcome {
                            status: SymbolOutcomeStatus::Failed,
                            reason: Some(format!("extract_failed ({})", language.as_str())),
                            error_summary: Some(err.to_string()),
                        },
                    );
                    if let Err(err) = store.upsert_ast(&ingest.rel_path, &ast_payload) {
                        warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist ast outcome");
                    }
                }
            }
        }
    }
}
