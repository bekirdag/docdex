use once_cell::sync::Lazy;
use std::sync::Mutex;

pub(crate) static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
