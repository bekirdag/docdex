use crate::auth::{AuthCapabilities, AuthConfig};
use crate::repo_encryption::{RepoEncryptionCapabilities, RepoEncryptionConfig};
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
    pub auth: AuthCapabilities,
    pub repo_encryption: RepoEncryptionCapabilities,
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
    current_capabilities_with_config(&RepoEncryptionConfig::default(), &AuthConfig::default())
}

pub fn current_capabilities_with_repo_encryption_config(
    repo_encryption_config: &RepoEncryptionConfig,
) -> DocdexCapabilities {
    current_capabilities_with_config(repo_encryption_config, &AuthConfig::default())
}

pub fn current_capabilities_with_config(
    repo_encryption_config: &RepoEncryptionConfig,
    auth_config: &AuthConfig,
) -> DocdexCapabilities {
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
        auth: AuthCapabilities::from_config(auth_config),
        repo_encryption: RepoEncryptionCapabilities::from_config(repo_encryption_config),
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
        assert!(caps.auth.static_token_enabled);
        assert!(!caps.auth.external_introspection_enabled);
        assert!(caps.auth.repo_access_policy_enabled);
        assert!(!caps.repo_encryption.enabled);
        assert_eq!(
            caps.repo_encryption.encryption_mode,
            crate::repo_encryption::RepoEncryptionMode::Disabled
        );
        assert_eq!(caps.limits.rerank_max_candidates, RERANK_MAX_CANDIDATES);
        assert_eq!(
            caps.limits.batch_search_max_queries,
            BATCH_SEARCH_MAX_QUERIES
        );
        assert_eq!(caps.limits.explanation_max_chars, EXPLANATION_MAX_CHARS);
    }

    #[test]
    fn repo_encryption_capabilities_reflect_enabled_config() {
        let mut config = RepoEncryptionConfig {
            encryption_mode:
                crate::repo_encryption::RepoEncryptionMode::ApplicationManagedEncryption,
            shared_bearer_token_sufficient: true,
            semantic_search_enabled: false,
            web_discovery_enabled: false,
            full_file_open_enabled: false,
            ..RepoEncryptionConfig::default()
        };
        config.apply_defaults();

        let caps = current_capabilities_with_config(&config, &AuthConfig::default());
        assert!(caps.repo_encryption.enabled);
        assert_eq!(
            caps.repo_encryption.encryption_mode,
            crate::repo_encryption::RepoEncryptionMode::ApplicationManagedEncryption
        );
        assert!(caps.repo_encryption.access_checks_required);
        assert!(caps.repo_encryption.audit_required);
        assert!(caps.repo_encryption.repository_isolation_required);
        assert!(!caps.repo_encryption.shared_bearer_token_sufficient);
        assert!(!caps.repo_encryption.semantic_search_enabled);
        assert!(!caps.repo_encryption.web_discovery_enabled);
    }

    #[test]
    fn auth_capabilities_reflect_external_provider_config() {
        let auth = AuthConfig {
            external_api_key_introspection: crate::auth::ExternalApiKeyIntrospectionConfig {
                enabled: true,
                ..Default::default()
            },
            service_token: crate::auth::ServiceTokenAuthConfig {
                enabled: true,
                ..Default::default()
            },
            ..AuthConfig::default()
        };

        let caps = current_capabilities_with_config(&RepoEncryptionConfig::default(), &auth);
        assert!(caps.auth.static_token_enabled);
        assert!(caps.auth.external_introspection_enabled);
        assert!(caps.auth.service_token_enabled);
        assert!(caps
            .auth
            .providers
            .contains(&"external_api_key_introspection"));
    }
}
