use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Default)]
struct DomainPacer {
    next_allowed: Mutex<HashMap<String, Instant>>,
}

impl DomainPacer {
    fn schedule_wait(&self, host: &str, min_delay: Duration) -> Duration {
        let mut wait = Duration::ZERO;
        let now = Instant::now();
        let mut state = self.next_allowed.lock();
        let next_allowed = state.get(host).copied().unwrap_or(now);
        let scheduled = if next_allowed > now { next_allowed } else { now };
        let next = scheduled + min_delay;
        if scheduled > now {
            wait = scheduled.duration_since(now);
        }
        state.insert(host.to_string(), next);
        wait
    }
}

static DOMAIN_PACER: Lazy<DomainPacer> = Lazy::new(DomainPacer::default);

pub async fn enforce_domain_delay(url: &Url, min_delay: Duration) {
    if min_delay.is_zero() {
        return;
    }
    let Some(host) = url.host_str() else {
        return;
    };
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty() {
        return;
    }
    let wait = DOMAIN_PACER.schedule_wait(&host, min_delay);
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}
