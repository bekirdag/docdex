use crate::dag;
use anyhow::Result;

pub(crate) fn run(command: super::super::DagCommand) -> Result<()> {
    match command {
        super::super::DagCommand::View { repo, session_id } => {
            let repo_root = repo.repo_root();
            let state_dir = repo.state_dir_override();
            let text = dag::view::render_session_as_text(&repo_root, &session_id, state_dir)?;
            println!("{text}");
        }
    }
    Ok(())
}
