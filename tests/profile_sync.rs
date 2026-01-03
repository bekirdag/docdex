use docdexd::profiles::{Agent, Preference, PreferenceCategory, ProfileManager};
use std::error::Error;
use tempfile::TempDir;

#[test]
fn profile_import_last_write_wins() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let manager = ProfileManager::new(state_root.path(), 3)?;

    let agent = Agent {
        id: "agent-1".to_string(),
        role: "test".to_string(),
        created_at: 0,
    };

    let old = Preference {
        id: "pref-1".to_string(),
        agent_id: agent.id.clone(),
        content: "old content".to_string(),
        embedding: Some(vec![0.1, 0.1, 0.1]),
        category: PreferenceCategory::Constraint,
        last_updated: 1000,
    };
    let new = Preference {
        id: "pref-1".to_string(),
        agent_id: agent.id.clone(),
        content: "new content".to_string(),
        embedding: Some(vec![0.2, 0.2, 0.2]),
        category: PreferenceCategory::Constraint,
        last_updated: 2000,
    };

    let summary_old = manager.import_preferences(&[agent.clone()], &[old])?;
    assert_eq!(summary_old.inserted, 1);

    let summary_new = manager.import_preferences(&[agent.clone()], &[new])?;
    assert_eq!(summary_new.updated, 1);

    let prefs = manager.list_preferences(Some(&agent.id))?;
    let stored = prefs
        .iter()
        .find(|pref| pref.id == "pref-1")
        .ok_or("missing preference after import")?;
    assert_eq!(stored.content, "new content");
    assert_eq!(stored.last_updated, 2000);
    Ok(())
}

#[test]
fn profile_import_rejects_embedding_dim_mismatch() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let manager = ProfileManager::new(state_root.path(), 3)?;

    let agent = Agent {
        id: "agent-1".to_string(),
        role: "test".to_string(),
        created_at: 0,
    };

    let pref = Preference {
        id: "pref-1".to_string(),
        agent_id: agent.id.clone(),
        content: "content".to_string(),
        embedding: Some(vec![0.1, 0.2]),
        category: PreferenceCategory::Constraint,
        last_updated: 1000,
    };

    let result = manager.import_preferences(&[agent], &[pref]);
    assert!(result.is_err(), "expected embedding mismatch error");
    Ok(())
}

#[test]
fn profile_import_skips_older_or_equal_updates() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let manager = ProfileManager::new(state_root.path(), 3)?;

    let agent = Agent {
        id: "agent-1".to_string(),
        role: "test".to_string(),
        created_at: 0,
    };

    let base = Preference {
        id: "pref-1".to_string(),
        agent_id: agent.id.clone(),
        content: "base content".to_string(),
        embedding: Some(vec![0.1, 0.1, 0.1]),
        category: PreferenceCategory::Constraint,
        last_updated: 2000,
    };
    let older = Preference {
        id: "pref-1".to_string(),
        agent_id: agent.id.clone(),
        content: "older content".to_string(),
        embedding: Some(vec![0.2, 0.2, 0.2]),
        category: PreferenceCategory::Constraint,
        last_updated: 1000,
    };
    let equal = Preference {
        id: "pref-1".to_string(),
        agent_id: agent.id.clone(),
        content: "equal content".to_string(),
        embedding: Some(vec![0.3, 0.3, 0.3]),
        category: PreferenceCategory::Constraint,
        last_updated: 2000,
    };

    let summary_base = manager.import_preferences(&[agent.clone()], &[base])?;
    assert_eq!(summary_base.inserted, 1);

    let summary_older = manager.import_preferences(&[agent.clone()], &[older])?;
    assert_eq!(summary_older.updated, 0);
    assert_eq!(summary_older.skipped, 1);

    let summary_equal = manager.import_preferences(&[agent.clone()], &[equal])?;
    assert_eq!(summary_equal.updated, 0);
    assert_eq!(summary_equal.skipped, 1);

    let prefs = manager.list_preferences(Some(&agent.id))?;
    let stored = prefs
        .iter()
        .find(|pref| pref.id == "pref-1")
        .ok_or("missing preference after import")?;
    assert_eq!(stored.content, "base content");
    assert_eq!(stored.last_updated, 2000);
    Ok(())
}
