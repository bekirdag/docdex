use crate::error::StartupError;

pub const DEFAULT_MAX_OPEN_REPOS: usize = 12;
pub const MIN_MAX_OPEN_REPOS: usize = 4;
pub const MAX_MAX_OPEN_REPOS: usize = 16;

#[derive(Clone, Debug)]
pub struct RepoManagerConfig {
    pub max_open_repos: usize,
}

impl RepoManagerConfig {
    pub fn new(max_open_repos: usize) -> Result<Self, StartupError> {
        let max_open_repos = validate_max_open_repos(max_open_repos)?;
        Ok(Self { max_open_repos })
    }
}

pub fn parse_max_open_repos(value: &str) -> Result<usize, String> {
    let trimmed = value.trim();
    let parsed = trimmed
        .parse::<usize>()
        .map_err(|_| "max-open-repos must be an integer".to_string())?;
    validate_max_open_repos(parsed).map_err(|err| err.message)
}

fn validate_max_open_repos(value: usize) -> Result<usize, StartupError> {
    if (MIN_MAX_OPEN_REPOS..=MAX_MAX_OPEN_REPOS).contains(&value) {
        Ok(value)
    } else {
        Err(StartupError::new(
            "startup_config_invalid",
            format!(
                "max-open-repos must be between {MIN_MAX_OPEN_REPOS} and {MAX_MAX_OPEN_REPOS} (got {value})"
            ),
        )
        .with_hint("Set --max-open-repos within the supported range."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_open_repos_is_valid() {
        let config = RepoManagerConfig::new(DEFAULT_MAX_OPEN_REPOS).expect("default should be valid");
        assert_eq!(config.max_open_repos, DEFAULT_MAX_OPEN_REPOS);
    }

    #[test]
    fn max_open_repos_rejects_below_min() {
        let below_min = MIN_MAX_OPEN_REPOS - 1;
        let err = RepoManagerConfig::new(below_min).expect_err("below-min should error");
        assert_eq!(err.code, "startup_config_invalid");
        assert!(err.message.contains("between"));
    }

    #[test]
    fn max_open_repos_rejects_above_max() {
        let above_max = MAX_MAX_OPEN_REPOS + 1;
        let err = RepoManagerConfig::new(above_max).expect_err("above-max should error");
        assert_eq!(err.code, "startup_config_invalid");
        assert!(err.message.contains("between"));
    }
}
