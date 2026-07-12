use super::*;

impl McpServer {
    pub(super) async fn handle_profile_save_preference(
        &self,
        args: ProfileSaveArgs,
    ) -> Result<serde_json::Value> {
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| self.default_agent_id.as_deref());
        let content = args.content.trim();
        let category = args.category.trim().to_ascii_lowercase();
        if agent_id.is_none() || content.is_empty() || category.is_empty() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "agent_id, content, and category are required",
            )
            .into());
        }
        if !matches!(
            category.as_str(),
            "style" | "tooling" | "constraint" | "workflow"
        ) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "category must be one of: style, tooling, constraint, workflow",
            )
            .into());
        }
        let agent_id = agent_id.ok_or_else(|| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                "agent_id, content, and category are required",
            )
        })?;
        let payload = json!({
            "agent_id": agent_id,
            "content": content,
            "category": category,
            "role": args.role,
        });
        self.call_profile_endpoint(Method::POST, "/v1/profile/save", None, Some(payload))
            .await
    }

    pub(super) async fn handle_profile_get_profile(
        &self,
        args: ProfileGetArgs,
    ) -> Result<serde_json::Value> {
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| self.default_agent_id.as_deref());
        let query = agent_id.map(|value| vec![("agent_id", value.to_string())]);
        self.call_profile_endpoint(Method::GET, "/v1/profile/list", query, None)
            .await
    }

    pub(super) async fn call_profile_endpoint(
        &self,
        method: Method,
        path: &str,
        query: Option<Vec<(&str, String)>>,
        body: Option<Value>,
    ) -> Result<Value> {
        let base_url = resolve_docdexd_base_url(self.docdex_http_base_url.as_deref())?;
        let client = docdexd_http_client()?;
        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = client.request(method, url);
        let token = self
            .auth_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .or_else(|| env_non_empty("DOCDEX_AUTH_TOKEN"));
        if let Some(token) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(query) = query.as_ref() {
            req = req.query(query);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await.context("profile HTTP request failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::new(
                ERR_INTERNAL_ERROR,
                format!("profile request failed ({status}): {text}"),
            )
            .into());
        }
        let payload = serde_json::from_str(&text).context("parse profile response")?;
        Ok(payload)
    }

    pub(super) async fn call_index_endpoint(&self, path: &str, body: Value) -> Result<Value> {
        let base_url = resolve_docdexd_base_url(self.docdex_http_base_url.as_deref())?;
        let client = docdexd_http_client()?;
        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = client.request(Method::POST, url).json(&body);
        let token = self
            .auth_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .or_else(|| env_non_empty("DOCDEX_AUTH_TOKEN"));
        if let Some(token) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let resp = req.send().await.context("index HTTP request failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::new(
                ERR_INTERNAL_ERROR,
                format!("index request failed ({status}): {text}"),
            )
            .into());
        }
        let payload = serde_json::from_str(&text).context("parse index response")?;
        Ok(payload)
    }

    pub(super) async fn handle_resource_read(
        &self,
        params: ResourceReadParams,
    ) -> Result<serde_json::Value> {
        // Expect uri like docdex://path
        let uri = params.uri.trim();
        let prefix = "docdex://";
        if !uri.starts_with(prefix) {
            return Err(InvalidUriError.into());
        }
        let raw_path = &uri[prefix.len()..];
        let rel = if raw_path.starts_with('/') {
            &raw_path[1..]
        } else {
            raw_path
        };
        let open_args = OpenArgs {
            path: rel.to_string(),
            project_root: self.default_project_root.clone(),
            repo_path: None,
            start_line: None,
            end_line: None,
            clamp: None,
            head: None,
        };
        self.handle_open(open_args).await
    }
}
