use crate::cli::http_client::CliHttpClient;
use crate::dag;
use anyhow::Result;
use reqwest::Method;

pub(crate) async fn run(command: super::super::DagCommand) -> Result<()> {
    match command {
        super::super::DagCommand::View {
            repo,
            session_id,
            format,
            max_nodes,
        } => {
            if !crate::cli::cli_local_mode() {
                return run_via_http(repo, session_id, format, max_nodes).await;
            }
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
                    dag::view::render_session_as_text(
                        &repo_root,
                        &session_id,
                        state_dir,
                        max_nodes,
                    )?
                };
                println!("{output}");
            }
        }
    }
    Ok(())
}

async fn run_via_http(
    repo: crate::config::RepoArgs,
    session_id: String,
    format: String,
    max_nodes: Option<usize>,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let format = format.trim().to_ascii_lowercase();
    let client = CliHttpClient::new()?;
    client.ensure_repo(&repo_root).await?;
    let mut req = client.request(Method::GET, "/v1/dag/export");
    let mut params: Vec<(&str, String)> =
        vec![("session_id", session_id), ("format", format.clone())];
    if let Some(max_nodes) = max_nodes {
        params.push(("max_nodes", max_nodes.to_string()));
    }
    req = req.query(&params);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    let status = resp.status();
    if format == "json" {
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("docdexd dag export failed ({}): {}", status, text);
        }
        let value: serde_json::Value = serde_json::from_str(&text)?;
        println!("{}", serde_json::to_string(&value)?);
        Ok(())
    } else {
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!("docdexd dag export failed ({}): {}", status, text);
        }
        println!("{text}");
        Ok(())
    }
}
