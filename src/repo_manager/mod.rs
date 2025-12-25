pub mod fingerprint;
pub mod registry;
pub mod resolution;

pub use fingerprint::{normalize_path, repo_fingerprint_sha256};
pub use registry::{
    inspect_repo, reassociate_repo_path, record_repo_opened, resolve_shared_index_state_dir,
    resolve_shared_state_key, resolve_shared_state_key_lenient, split_scoped_state_dir,
    validate_repo_state_dir, RepoHandle, RepoHandleManager, RepoIdentityError, RepoInspectReport,
    RepoReassociateResult,
};
pub use resolution::resolve_repo_root;
