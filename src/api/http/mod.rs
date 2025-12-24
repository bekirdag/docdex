//! HTTP API surface.
//!
//! The HTTP router and middleware still live in `crate::search` today; this
//! module provides a stable import path and re-exports the public types while
//! the codebase converges on the planned layout.

pub use crate::search::{router, AppState, SecurityConfig};
