use std::env;

const MIN_NOFILE_ENV: &str = "DOCDEX_MIN_NOFILE_SOFT";
pub const DEFAULT_MIN_NOFILE_SOFT: u64 = 4_096;
const MIN_ALLOWED_MIN_NOFILE_SOFT: u64 = 256;
const MAX_ALLOWED_MIN_NOFILE_SOFT: u64 = 1_048_576;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NofileLimits {
    pub soft: u64,
    pub hard: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LowNofileWarning {
    pub limits: NofileLimits,
    pub threshold: u64,
}

pub fn min_nofile_soft_threshold() -> u64 {
    let raw = env::var(MIN_NOFILE_ENV).ok();
    parse_min_nofile_soft(raw.as_deref())
}

pub fn parse_min_nofile_soft(raw: Option<&str>) -> u64 {
    let Some(raw) = raw else {
        return DEFAULT_MIN_NOFILE_SOFT;
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return DEFAULT_MIN_NOFILE_SOFT;
    }
    let Ok(parsed) = trimmed.parse::<u64>() else {
        return DEFAULT_MIN_NOFILE_SOFT;
    };
    if parsed == 0 {
        return DEFAULT_MIN_NOFILE_SOFT;
    }
    parsed.clamp(MIN_ALLOWED_MIN_NOFILE_SOFT, MAX_ALLOWED_MIN_NOFILE_SOFT)
}

#[cfg(unix)]
pub fn current_nofile_limits() -> Option<NofileLimits> {
    use nix::libc;

    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limits` is valid writable memory and the call does not outlive it.
    let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits as *mut libc::rlimit) };
    if rc != 0 {
        return None;
    }

    let soft = rlim_to_u64(limits.rlim_cur).unwrap_or(u64::MAX);
    let hard = rlim_to_u64(limits.rlim_max);
    Some(NofileLimits { soft, hard })
}

#[cfg(not(unix))]
pub fn current_nofile_limits() -> Option<NofileLimits> {
    None
}

#[cfg(unix)]
fn rlim_to_u64(value: nix::libc::rlim_t) -> Option<u64> {
    if value == nix::libc::RLIM_INFINITY {
        None
    } else {
        u64::try_from(value).ok()
    }
}

pub fn detect_low_nofile(limits: NofileLimits, threshold: u64) -> Option<LowNofileWarning> {
    if limits.soft < threshold {
        Some(LowNofileWarning { limits, threshold })
    } else {
        None
    }
}

pub fn format_low_nofile_warning(warning: LowNofileWarning) -> String {
    let hard = warning
        .limits
        .hard
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unlimited".to_string());
    format!(
        "low open-file soft limit detected at startup (soft={}, hard={}, threshold={}); this commonly happens when launchd/systemd applies conservative limits and can cause EMFILE/read-only fallback under multi-repo load. Raise launchd `SoftResourceLimits/HardResourceLimits` `NumberOfFiles` or systemd `LimitNOFILE`, or tune {} for this host.",
        warning.limits.soft,
        hard,
        warning.threshold,
        MIN_NOFILE_ENV
    )
}

pub fn startup_low_nofile_warning() -> Option<String> {
    let threshold = min_nofile_soft_threshold();
    let limits = current_nofile_limits()?;
    let warning = detect_low_nofile(limits, threshold)?;
    Some(format_low_nofile_warning(warning))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_min_nofile_soft_uses_default_when_missing_or_invalid() {
        assert_eq!(parse_min_nofile_soft(None), DEFAULT_MIN_NOFILE_SOFT);
        assert_eq!(parse_min_nofile_soft(Some("")), DEFAULT_MIN_NOFILE_SOFT);
        assert_eq!(parse_min_nofile_soft(Some("  ")), DEFAULT_MIN_NOFILE_SOFT);
        assert_eq!(parse_min_nofile_soft(Some("abc")), DEFAULT_MIN_NOFILE_SOFT);
        assert_eq!(parse_min_nofile_soft(Some("0")), DEFAULT_MIN_NOFILE_SOFT);
    }

    #[test]
    fn parse_min_nofile_soft_accepts_valid_and_clamps_edges() {
        assert_eq!(parse_min_nofile_soft(Some("4096")), 4_096);
        assert_eq!(
            parse_min_nofile_soft(Some("128")),
            MIN_ALLOWED_MIN_NOFILE_SOFT
        );
        assert_eq!(
            parse_min_nofile_soft(Some("99999999")),
            MAX_ALLOWED_MIN_NOFILE_SOFT
        );
    }

    #[test]
    fn detect_low_nofile_returns_warning_only_below_threshold() {
        let low = NofileLimits {
            soft: 1024,
            hard: Some(4096),
        };
        let high = NofileLimits {
            soft: 8192,
            hard: Some(16384),
        };

        assert!(detect_low_nofile(low, 4096).is_some());
        assert!(detect_low_nofile(high, 4096).is_none());
    }

    #[test]
    fn format_low_nofile_warning_contains_remediation_and_context() {
        let msg = format_low_nofile_warning(LowNofileWarning {
            limits: NofileLimits {
                soft: 256,
                hard: Some(10240),
            },
            threshold: 4096,
        });

        assert!(msg.contains("soft=256"));
        assert!(msg.contains("hard=10240"));
        assert!(msg.contains("threshold=4096"));
        assert!(msg.contains("launchd"));
        assert!(msg.contains("LimitNOFILE"));
        assert!(msg.contains("DOCDEX_MIN_NOFILE_SOFT"));
    }
}
