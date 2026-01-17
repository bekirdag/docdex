use once_cell::sync::Lazy;
use parking_lot::ReentrantMutex;

pub(crate) static ENV_LOCK: Lazy<ReentrantMutex<()>> = Lazy::new(|| ReentrantMutex::new(()));
