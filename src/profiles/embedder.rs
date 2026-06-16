use crate::embeddings::{EmbeddingEmbedder, EmbeddingTarget};
use anyhow::Result;
use std::time::Duration;
use tracing::warn;

#[cfg(test)]
use crate::error::{AppError, ERR_EMBEDDING_FAILED};

#[derive(Clone)]
pub struct ProfileEmbedder {
    embedder: Option<EmbeddingEmbedder>,
    fallback: FallbackEmbedder,
    expected_dim: usize,
    #[cfg(test)]
    test_embedding: Option<Vec<f32>>,
}

pub struct ProfileEmbedding {
    pub embedding: Vec<f32>,
    pub provider: String,
    pub model: String,
}

#[derive(Clone)]
struct FallbackEmbedder {
    expected_dim: usize,
}

impl ProfileEmbedder {
    pub fn new(
        base_url: String,
        model: String,
        timeout: Duration,
        expected_dim: usize,
    ) -> Result<Self> {
        let target = EmbeddingTarget::ollama(base_url, model, "profile-ollama")?;
        Self::with_target(target, timeout, expected_dim)
    }

    pub fn with_target(
        target: EmbeddingTarget,
        timeout: Duration,
        expected_dim: usize,
    ) -> Result<Self> {
        let embedder = match EmbeddingEmbedder::with_target(target, timeout) {
            Ok(embedder) => Some(embedder),
            Err(err) => {
                warn!(
                    error = ?err,
                    "profile embedder init failed; falling back to local hash embeddings"
                );
                None
            }
        };
        Ok(Self {
            embedder,
            fallback: FallbackEmbedder::new(expected_dim),
            expected_dim,
            #[cfg(test)]
            test_embedding: None,
        })
    }

    #[cfg(test)]
    pub fn new_test(expected_dim: usize, embedding: Vec<f32>) -> Result<Self> {
        let embedder = EmbeddingEmbedder::new(
            "http://127.0.0.1:11434".to_string(),
            "nomic-embed-text".to_string(),
            Duration::from_millis(0),
        )?;
        Ok(Self {
            embedder: Some(embedder),
            fallback: FallbackEmbedder::new(expected_dim),
            expected_dim,
            test_embedding: Some(embedding),
        })
    }

    pub fn provider(&self) -> &str {
        match self.embedder.as_ref() {
            Some(embedder) => embedder.provider(),
            None => "fallback",
        }
    }

    pub fn model(&self) -> &str {
        match self.embedder.as_ref() {
            Some(embedder) => embedder.model(),
            None => "hash-embed-v1",
        }
    }

    pub async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        self.embed_with_metadata(text)
            .await
            .map(|result| result.embedding)
    }

    pub async fn embed_with_metadata(&self, text: &str) -> Result<ProfileEmbedding> {
        #[cfg(test)]
        if let Some(embedding) = self.test_embedding.as_ref() {
            if embedding.len() != self.expected_dim {
                return Err(AppError::new(
                    ERR_EMBEDDING_FAILED,
                    format!(
                        "profile embedding dimension mismatch: expected {}, got {}",
                        self.expected_dim,
                        embedding.len()
                    ),
                )
                .into());
            }
            return Ok(ProfileEmbedding {
                embedding: embedding.clone(),
                provider: self.provider().to_string(),
                model: self.model().to_string(),
            });
        }
        if let Some(embedder) = self.embedder.as_ref() {
            match embedder.embed(text).await {
                Ok(embedding) => {
                    if embedding.len() == self.expected_dim {
                        return Ok(ProfileEmbedding {
                            embedding,
                            provider: embedder.provider().to_string(),
                            model: embedder.model().to_string(),
                        });
                    }
                    warn!(
                        provider = self.provider(),
                        model = self.model(),
                        expected = self.expected_dim,
                        actual = embedding.len(),
                        "profile embedding dimension mismatch; falling back to local hash"
                    );
                }
                Err(err) => {
                    warn!(
                        error = ?err,
                        "profile embedding failed; falling back to local hash"
                    );
                }
            }
        }
        Ok(ProfileEmbedding {
            embedding: self.fallback.embed(text),
            provider: "fallback".to_string(),
            model: "hash-embed-v1".to_string(),
        })
    }

    pub(crate) fn fallback_embedding(text: &str, expected_dim: usize) -> Vec<f32> {
        FallbackEmbedder::new(expected_dim).embed(text)
    }
}

impl FallbackEmbedder {
    fn new(expected_dim: usize) -> Self {
        Self { expected_dim }
    }

    fn embed(&self, text: &str) -> Vec<f32> {
        let dim = self.expected_dim;
        if dim == 0 {
            return Vec::new();
        }
        let mut out = vec![0f32; dim];
        let mut had_token = false;
        for token in text.split_whitespace() {
            had_token = true;
            let hash = fnv1a64(token.as_bytes());
            let idx = (hash % dim as u64) as usize;
            let sign = if (hash >> 63) == 0 { 1.0 } else { -1.0 };
            out[idx] += sign;
        }
        if !had_token {
            return out;
        }
        let norm = out.iter().map(|v| v * v).sum::<f32>().sqrt();
        if norm > 0.0 {
            for value in &mut out {
                *value /= norm;
            }
        }
        out
    }
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut hash = FNV_OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mismatch_dimension_returns_error() -> Result<()> {
        let embedder = ProfileEmbedder::new_test(2, vec![0.0, 0.0, 0.0])?;
        let err = embedder.embed("test").await.err();
        assert!(err.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn correct_dimension_passes() -> Result<()> {
        let embedder = ProfileEmbedder::new_test(2, vec![0.0, 0.0])?;
        let embedding = embedder.embed("test").await?;
        assert_eq!(embedding.len(), 2);
        Ok(())
    }
}
