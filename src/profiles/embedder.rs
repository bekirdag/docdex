use crate::error::{AppError, ERR_EMBEDDING_FAILED};
use crate::ollama::OllamaEmbedder;
use anyhow::Result;
use std::time::Duration;
use tracing::warn;

#[derive(Clone)]
pub struct ProfileEmbedder {
    embedder: OllamaEmbedder,
    expected_dim: usize,
    #[cfg(test)]
    test_embedding: Option<Vec<f32>>,
}

impl ProfileEmbedder {
    pub fn new(
        base_url: String,
        model: String,
        timeout: Duration,
        expected_dim: usize,
    ) -> Result<Self> {
        let embedder = OllamaEmbedder::new(base_url, model, timeout)?;
        Ok(Self {
            embedder,
            expected_dim,
            #[cfg(test)]
            test_embedding: None,
        })
    }

    #[cfg(test)]
    pub fn new_test(expected_dim: usize, embedding: Vec<f32>) -> Result<Self> {
        let embedder = OllamaEmbedder::new(
            "http://127.0.0.1:11434".to_string(),
            "nomic-embed-text".to_string(),
            Duration::from_millis(0),
        )?;
        Ok(Self {
            embedder,
            expected_dim,
            test_embedding: Some(embedding),
        })
    }

    pub fn provider(&self) -> &str {
        self.embedder.provider()
    }

    pub fn model(&self) -> &str {
        self.embedder.model()
    }

    pub async fn embed(&self, text: &str) -> Result<Vec<f32>> {
        #[cfg(test)]
        if let Some(embedding) = self.test_embedding.as_ref() {
            return Ok(embedding.clone());
        }
        let embedding = self.embedder.embed(text).await?;
        if embedding.len() != self.expected_dim {
            warn!(
                provider = self.provider(),
                model = self.model(),
                expected = self.expected_dim,
                actual = embedding.len(),
                "profile embedding dimension mismatch"
            );
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
        Ok(embedding)
    }
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
