use serde::Serialize;

pub const CAPABILITY_CONTRACT_VERSION: &str = "2026-03-03";
pub const RERANK_MAX_CANDIDATES: usize = 200;
pub const BATCH_SEARCH_MAX_QUERIES: usize = 16;
pub const EXPLANATION_MAX_CHARS: usize = 240;

#[derive(Debug, Clone, Serialize)]
pub struct DocdexCapabilities {
    pub contract_version: &'static str,
    pub retrieval: RetrievalCapabilities,
    pub mcp: McpCapabilities,
    pub http: HttpCapabilities,
    pub limits: CapabilityLimits,
}

#[derive(Debug, Clone, Serialize)]
pub struct RetrievalCapabilities {
    pub score_breakdown: bool,
    pub rerank: bool,
    pub snippet_provenance: bool,
    pub retrieval_explanation: bool,
    pub batch_search: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct McpCapabilities {
    pub docdex_capabilities: bool,
    pub docdex_rerank: bool,
    pub docdex_batch_search: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpCapabilities {
    pub capabilities_endpoint: bool,
    pub rerank_endpoint: bool,
    pub batch_search_endpoint: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityLimits {
    pub rerank_max_candidates: usize,
    pub batch_search_max_queries: usize,
    pub explanation_max_chars: usize,
}

pub fn current_capabilities() -> DocdexCapabilities {
    DocdexCapabilities {
        contract_version: CAPABILITY_CONTRACT_VERSION,
        retrieval: RetrievalCapabilities {
            score_breakdown: true,
            rerank: true,
            snippet_provenance: true,
            retrieval_explanation: true,
            batch_search: true,
        },
        mcp: McpCapabilities {
            docdex_capabilities: true,
            docdex_rerank: true,
            docdex_batch_search: true,
        },
        http: HttpCapabilities {
            capabilities_endpoint: true,
            rerank_endpoint: true,
            batch_search_endpoint: true,
        },
        limits: CapabilityLimits {
            rerank_max_candidates: RERANK_MAX_CANDIDATES,
            batch_search_max_queries: BATCH_SEARCH_MAX_QUERIES,
            explanation_max_chars: EXPLANATION_MAX_CHARS,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epic10_capability_contract_defaults_are_enabled() {
        let caps = current_capabilities();
        assert_eq!(caps.contract_version, CAPABILITY_CONTRACT_VERSION);
        assert!(caps.retrieval.score_breakdown);
        assert!(caps.retrieval.rerank);
        assert!(caps.retrieval.snippet_provenance);
        assert!(caps.retrieval.retrieval_explanation);
        assert!(caps.retrieval.batch_search);
        assert!(caps.mcp.docdex_capabilities);
        assert!(caps.mcp.docdex_rerank);
        assert!(caps.mcp.docdex_batch_search);
        assert!(caps.http.capabilities_endpoint);
        assert!(caps.http.rerank_endpoint);
        assert!(caps.http.batch_search_endpoint);
        assert_eq!(caps.limits.rerank_max_candidates, RERANK_MAX_CANDIDATES);
        assert_eq!(
            caps.limits.batch_search_max_queries,
            BATCH_SEARCH_MAX_QUERIES
        );
        assert_eq!(caps.limits.explanation_max_chars, EXPLANATION_MAX_CHARS);
    }
}
