use std::path::{Path, PathBuf};

pub fn conversation_path(state_dir: &Path) -> PathBuf {
    crate::memory::repo_state_root_from_state_dir(state_dir).join("conversation.db")
}

pub fn conversation_namespace_state_dir(base_state_dir: &Path, namespace: &str) -> PathBuf {
    crate::state_layout::conversation_namespace_state_dir(base_state_dir, namespace)
}

pub fn conversation_namespace_path(base_state_dir: &Path, namespace: &str) -> PathBuf {
    conversation_namespace_state_dir(base_state_dir, namespace).join("conversation.db")
}

pub fn conversation_lock_path(state_dir: &Path) -> PathBuf {
    let repo_state_root = crate::memory::repo_state_root_from_state_dir(state_dir);
    let state_key = repo_state_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo");
    crate::memory::locks_dir_from_state_dir(state_dir)
        .join(format!("conversation-{state_key}.lock"))
}

pub fn conversation_namespace_lock_path(base_state_dir: &Path, namespace: &str) -> PathBuf {
    let state_key = crate::state_layout::conversation_namespace_state_key(namespace);
    crate::state_layout::StateLayout::new(base_state_dir.to_path_buf())
        .locks_dir()
        .join(format!("conversation-namespace-{state_key}.lock"))
}
