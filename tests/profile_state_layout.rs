use docdexd::state_layout::StateLayout;
use tempfile::tempdir;

#[test]
fn state_layout_creates_profile_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let base = dir.path().join("state");
    let layout = StateLayout::new(base.clone());
    layout.ensure_global_dirs()?;

    let profiles_dir = layout.profiles_dir();
    let profiles_sync_dir = layout.profiles_sync_dir();
    let browser_profiles_dir = layout.browser_profiles_dir();
    assert!(profiles_dir.exists());
    assert!(profiles_sync_dir.exists());
    assert!(browser_profiles_dir.exists());
    Ok(())
}
