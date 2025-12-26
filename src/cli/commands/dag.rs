use crate::dag;
use anyhow::Result;

pub(crate) fn run(command: super::super::DagCommand) -> Result<()> {
    match command {
        super::super::DagCommand::View {
            repo,
            session_id,
            format,
            max_nodes,
        } => {
            let repo_root = repo.repo_root();
            let state_dir = repo.state_dir_override();
            let format = format.trim().to_ascii_lowercase();
            if format == "json" {
                let payload =
                    dag::view::export_session(&repo_root, &session_id, state_dir, max_nodes)?;
                println!("{}", serde_json::to_string(&payload)?);
            } else {
                let output = if format == "dot" {
                    dag::view::render_session_as_dot(&repo_root, &session_id, state_dir, max_nodes)?
                } else {
                    dag::view::render_session_as_text(&repo_root, &session_id, state_dir, max_nodes)?
                };
                println!("{output}");
            }
        }
    }
    Ok(())
}
