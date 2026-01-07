use anyhow::{anyhow, Context, Result};
use regex::Regex;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

const DOCDEX_INFO_START_PREFIX: &str = "---- START OF DOCDEX INFO V";
const DOCDEX_INFO_END: &str = "---- END OF DOCDEX INFO -----";
const VSCODE_INSTRUCTIONS_KEY: &str = "copilot.chat.codeGeneration.instructions";
const AGENTS_INSTRUCTIONS: &str =
    include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/npm/assets/agents.md"));

#[derive(Debug)]
struct InstructionPaths {
    claude: PathBuf,
    continue_config: PathBuf,
    zed: PathBuf,
    vscode_settings: PathBuf,
    vscode_global_instructions: PathBuf,
    windsurf_global_rules: PathBuf,
    roo_rules: PathBuf,
    pearai_agent: PathBuf,
    aider_config: PathBuf,
    goose_config: PathBuf,
    open_interpreter_config: PathBuf,
    codex_agents: PathBuf,
}

pub(crate) fn run(remove: bool) -> Result<()> {
    let instructions = build_docdex_instruction_block();
    if !remove && normalize_instruction_text(&instructions).is_empty() {
        return Err(anyhow!(
            "packaged Docdex agent instructions are missing or empty"
        ));
    }

    let paths = client_instruction_paths()?;
    let mut updated = 0usize;
    let mut failed = 0usize;
    let mut attempted = 0usize;

    if remove {
        attempted += 1;
        record_result(
            "vscode-global",
            remove_prompt_file(&paths.vscode_global_instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "vscode-settings",
            remove_vscode_instructions(&paths.vscode_settings, &paths.vscode_global_instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "windsurf",
            remove_prompt_file(&paths.windsurf_global_rules),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "roo",
            remove_prompt_file(&paths.roo_rules),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "pearai",
            remove_prompt_file(&paths.pearai_agent),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "claude",
            remove_claude_instructions(&paths.claude),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "continue",
            remove_continue_instructions(&paths.continue_config),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "zed",
            remove_zed_instructions(&paths.zed),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "aider",
            remove_yaml_instruction(&paths.aider_config, "system-prompt"),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "goose",
            remove_yaml_instruction(&paths.goose_config, "instructions"),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "open-interpreter",
            remove_yaml_instruction(&paths.open_interpreter_config, "system_message"),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "codex",
            remove_prompt_file(&paths.codex_agents),
            &mut updated,
            &mut failed,
        );
    } else {
        attempted += 1;
        record_result(
            "vscode-global",
            upsert_prompt_file(&paths.vscode_global_instructions, &instructions, true),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "vscode-settings",
            upsert_vscode_instructions(&paths.vscode_settings, &paths.vscode_global_instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "windsurf",
            upsert_prompt_file(&paths.windsurf_global_rules, &instructions, true),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "roo",
            upsert_prompt_file(&paths.roo_rules, &instructions, false),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "pearai",
            upsert_prompt_file(&paths.pearai_agent, &instructions, true),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "claude",
            upsert_claude_instructions(&paths.claude, &instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "continue",
            upsert_continue_instructions(&paths.continue_config, &instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "zed",
            upsert_zed_instructions(&paths.zed, &instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "aider",
            upsert_yaml_instruction(&paths.aider_config, "system-prompt", &instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "goose",
            upsert_yaml_instruction(&paths.goose_config, "instructions", &instructions),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "open-interpreter",
            upsert_yaml_instruction(
                &paths.open_interpreter_config,
                "system_message",
                &instructions,
            ),
            &mut updated,
            &mut failed,
        );
        attempted += 1;
        record_result(
            "codex",
            upsert_prompt_file(&paths.codex_agents, &instructions, false),
            &mut updated,
            &mut failed,
        );
    }

    let skipped = attempted.saturating_sub(updated + failed);
    let mode = if remove { "remove" } else { "apply" };
    println!(
        "[docdexd agents-apply] {mode} complete (updated {updated}, skipped {skipped}, failed {failed})"
    );
    Ok(())
}

fn record_result(label: &str, result: Result<bool>, updated: &mut usize, failed: &mut usize) {
    match result {
        Ok(true) => *updated += 1,
        Ok(false) => {}
        Err(err) => {
            *failed += 1;
            eprintln!("[docdexd agents-apply] {label} failed: {err}");
        }
    }
}

fn build_docdex_instruction_block() -> String {
    let next = normalize_instruction_text(AGENTS_INSTRUCTIONS);
    if next.is_empty() {
        return String::new();
    }
    let version = env!("CARGO_PKG_VERSION");
    format!(
        "{}{} ----\n{}\n{}",
        DOCDEX_INFO_START_PREFIX, version, next, DOCDEX_INFO_END
    )
}

fn normalize_instruction_text(value: &str) -> String {
    value.trim().to_string()
}

fn docdex_block_start(version: &str) -> String {
    format!("{DOCDEX_INFO_START_PREFIX}{version} ----")
}

fn extract_docdex_block_version(text: &str) -> Option<String> {
    let re = Regex::new(&format!(
        "{}([^\\s]+) ----",
        regex::escape(DOCDEX_INFO_START_PREFIX)
    ))
    .ok()?;
    re.captures(text)
        .and_then(|cap| cap.get(1).map(|m| m.as_str().to_string()))
}

fn has_docdex_block_version(text: &str, version: &str) -> bool {
    text.contains(&docdex_block_start(version))
}

fn extract_docdex_block_body(text: &str) -> Option<String> {
    let pattern = format!(
        "(?s){}[^\\r\\n]* ----\\r?\\n(.*?)\\r?\\n{}",
        regex::escape(DOCDEX_INFO_START_PREFIX),
        regex::escape(DOCDEX_INFO_END)
    );
    let re = Regex::new(&pattern).ok()?;
    re.captures(text).and_then(|cap| cap.get(1)).map(|m| {
        normalize_instruction_text(m.as_str())
    })
}

fn collapse_blank_lines(text: &str) -> String {
    let normalized = text.replace("\r\n", "\n");
    let re = Regex::new("\n{3,}").expect("valid newline regex");
    re.replace_all(&normalized, "\n\n").to_string()
}

fn strip_docdex_blocks(text: &str) -> String {
    if text.trim().is_empty() {
        return String::new();
    }
    let pattern = format!(
        "(?s){}[^\\r\\n]* ----\\r?\\n.*?\\r?\\n{}\\r?\\n?",
        regex::escape(DOCDEX_INFO_START_PREFIX),
        regex::escape(DOCDEX_INFO_END)
    );
    let re = Regex::new(&pattern).expect("valid docdex instruction regex");
    let stripped = re.replace_all(text, "");
    collapse_blank_lines(stripped.trim())
}

fn strip_docdex_blocks_except(text: &str, version: &str) -> String {
    if text.trim().is_empty() {
        return String::new();
    }
    let pattern = format!(
        "(?s){}[^\\r\\n]* ----\\r?\\n.*?\\r?\\n{}\\r?\\n?",
        regex::escape(DOCDEX_INFO_START_PREFIX),
        regex::escape(DOCDEX_INFO_END)
    );
    let re = Regex::new(&pattern).expect("valid docdex instruction regex");
    let mut result = String::new();
    let mut last = 0usize;
    for m in re.find_iter(text) {
        result.push_str(&text[last..m.start()]);
        let block = m.as_str();
        if extract_docdex_block_version(block)
            .as_deref()
            .map(|v| v == version)
            .unwrap_or(false)
        {
            result.push_str(block);
        }
        last = m.end();
    }
    result.push_str(&text[last..]);
    collapse_blank_lines(result.trim())
}

fn strip_legacy_docdex_body_segment(segment: &str, body: &str) -> String {
    if body.trim().is_empty() {
        return segment.to_string();
    }
    let normalized_segment = segment.replace("\r\n", "\n");
    let normalized_body = body.replace("\r\n", "\n");
    if normalized_body.trim().is_empty() {
        return normalized_segment;
    }
    let pattern = format!("\\n?{}\\n?", regex::escape(&normalized_body));
    let re = Regex::new(&pattern).expect("valid legacy docdex regex");
    let stripped = re.replace_all(&normalized_segment, "\n");
    collapse_blank_lines(stripped.as_ref())
}

fn strip_legacy_docdex_body(text: &str, body: &str) -> String {
    if body.trim().is_empty() {
        return text.to_string();
    }
    let source = text.replace("\r\n", "\n");
    let pattern = format!(
        "(?s){}[^\\n]* ----\\n.*?\\n{}\\n?",
        regex::escape(DOCDEX_INFO_START_PREFIX),
        regex::escape(DOCDEX_INFO_END)
    );
    let re = Regex::new(&pattern).expect("valid docdex instruction regex");
    let mut result = String::new();
    let mut last = 0usize;
    for m in re.find_iter(&source) {
        result.push_str(&strip_legacy_docdex_body_segment(&source[last..m.start()], body));
        result.push_str(m.as_str());
        last = m.end();
    }
    result.push_str(&strip_legacy_docdex_body_segment(&source[last..], body));
    collapse_blank_lines(result.trim())
}

fn merge_instruction_text(existing: &str, instructions: &str, prepend: bool) -> String {
    let next = normalize_instruction_text(instructions);
    if next.is_empty() {
        return normalize_instruction_text(existing);
    }
    let existing_text = existing.to_string();
    let current = normalize_instruction_text(&existing_text);
    if current.is_empty() {
        return next;
    }
    if let Some(version) = extract_docdex_block_version(&next) {
        let body = extract_docdex_block_body(&next).unwrap_or_default();
        let cleaned = strip_legacy_docdex_body(&existing_text, &body);
        let without_old_blocks = strip_docdex_blocks_except(&cleaned, &version);
        if has_docdex_block_version(&without_old_blocks, &version) {
            return without_old_blocks;
        }
        let remainder = normalize_instruction_text(&strip_docdex_blocks(&without_old_blocks));
        if remainder.is_empty() {
            return next;
        }
        return if prepend {
            format!("{next}\n\n{remainder}")
        } else {
            format!("{remainder}\n\n{next}")
        };
    }
    if existing_text.contains(&next) {
        return existing_text;
    }
    if prepend {
        format!("{next}\n\n{current}")
    } else {
        format!("{current}\n\n{next}")
    }
}

fn write_text_file(path: &Path, contents: &str) -> Result<bool> {
    let next = if contents.ends_with('\n') {
        contents.to_string()
    } else {
        format!("{contents}\n")
    };
    if path.exists() {
        let current = fs::read_to_string(path)?;
        if current == next {
            return Ok(false);
        }
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, next)?;
    Ok(true)
}

fn upsert_prompt_file(path: &Path, instructions: &str, prepend: bool) -> Result<bool> {
    let next = normalize_instruction_text(instructions);
    if next.is_empty() {
        return Ok(false);
    }
    let current = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };
    let merged = merge_instruction_text(&current, instructions, prepend);
    if merged.is_empty() || merged == current {
        return Ok(false);
    }
    write_text_file(path, &merged)
}

fn remove_prompt_file(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let current = fs::read_to_string(path)?;
    let stripped = strip_docdex_blocks(&current);
    if stripped == normalize_instruction_text(&current) {
        return Ok(false);
    }
    if stripped.is_empty() {
        fs::remove_file(path)?;
        return Ok(true);
    }
    write_text_file(path, &stripped)
}

fn read_json(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    let raw = fs::read_to_string(path)?;
    if raw.trim().is_empty() {
        return Ok(Value::Object(serde_json::Map::new()));
    }
    let parsed = serde_json::from_str(&raw).unwrap_or_else(|_| Value::Object(serde_json::Map::new()));
    Ok(parsed)
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let pretty = serde_json::to_string_pretty(value)?;
    fs::write(path, format!("{pretty}\n"))?;
    Ok(())
}

fn upsert_claude_instructions(path: &Path, instructions: &str) -> Result<bool> {
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    let current = obj
        .get("instructions")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let merged = merge_instruction_text(current, instructions, false);
    if merged.is_empty() || merged == current {
        return Ok(false);
    }
    obj.insert("instructions".to_string(), Value::String(merged));
    write_json(path, &value)?;
    Ok(true)
}

fn remove_claude_instructions(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    let current = obj
        .get("instructions")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let stripped = strip_docdex_blocks(current);
    if stripped == normalize_instruction_text(current) {
        return Ok(false);
    }
    if stripped.is_empty() {
        obj.remove("instructions");
    } else {
        obj.insert("instructions".to_string(), Value::String(stripped));
    }
    write_json(path, &value)?;
    Ok(true)
}

fn upsert_continue_instructions(path: &Path, instructions: &str) -> Result<bool> {
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    let current = obj
        .get("systemMessage")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let merged = merge_instruction_text(current, instructions, false);
    if merged.is_empty() || merged == current {
        return Ok(false);
    }
    obj.insert("systemMessage".to_string(), Value::String(merged));
    write_json(path, &value)?;
    Ok(true)
}

fn remove_continue_instructions(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    let current = obj
        .get("systemMessage")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let stripped = strip_docdex_blocks(current);
    if stripped == normalize_instruction_text(current) {
        return Ok(false);
    }
    if stripped.is_empty() {
        obj.remove("systemMessage");
    } else {
        obj.insert("systemMessage".to_string(), Value::String(stripped));
    }
    write_json(path, &value)?;
    Ok(true)
}

fn upsert_zed_instructions(path: &Path, instructions: &str) -> Result<bool> {
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    if !obj
        .get("assistant")
        .map(|value| value.is_object())
        .unwrap_or(false)
    {
        obj.insert("assistant".to_string(), Value::Object(serde_json::Map::new()));
    }
    let assistant = obj
        .get_mut("assistant")
        .and_then(|value| value.as_object_mut())
        .context("assistant settings is not an object")?;
    let current = assistant
        .get("system_prompt")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let merged = merge_instruction_text(current, instructions, false);
    if merged.is_empty() || merged == current {
        return Ok(false);
    }
    assistant.insert("system_prompt".to_string(), Value::String(merged));
    write_json(path, &value)?;
    Ok(true)
}

fn remove_zed_instructions(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    let assistant = match obj.get_mut("assistant").and_then(|value| value.as_object_mut()) {
        Some(assistant) => assistant,
        None => return Ok(false),
    };
    let current = assistant
        .get("system_prompt")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let stripped = strip_docdex_blocks(current);
    if stripped == normalize_instruction_text(current) {
        return Ok(false);
    }
    if stripped.is_empty() {
        assistant.remove("system_prompt");
    } else {
        assistant.insert("system_prompt".to_string(), Value::String(stripped));
    }
    if assistant.is_empty() {
        obj.remove("assistant");
    }
    write_json(path, &value)?;
    Ok(true)
}

fn upsert_vscode_instructions(path: &Path, instructions_path: &Path) -> Result<bool> {
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    let instructions_value = instructions_path.to_string_lossy().to_string();
    if obj
        .get(VSCODE_INSTRUCTIONS_KEY)
        .and_then(|value| value.as_str())
        == Some(instructions_value.as_str())
    {
        return Ok(false);
    }
    obj.insert(
        VSCODE_INSTRUCTIONS_KEY.to_string(),
        Value::String(instructions_value),
    );
    write_json(path, &value)?;
    Ok(true)
}

fn remove_vscode_instructions(path: &Path, instructions_path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let mut value = read_json(path)?;
    let obj = match value.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(false),
    };
    let expected = instructions_path.to_string_lossy();
    let current = obj
        .get(VSCODE_INSTRUCTIONS_KEY)
        .and_then(|value| value.as_str());
    if current != Some(expected.as_ref()) {
        return Ok(false);
    }
    obj.remove(VSCODE_INSTRUCTIONS_KEY);
    write_json(path, &value)?;
    Ok(true)
}

fn upsert_yaml_instruction(path: &Path, key: &str, instructions: &str) -> Result<bool> {
    let next = normalize_instruction_text(instructions);
    if next.is_empty() {
        return Ok(false);
    }
    let current = if path.exists() {
        fs::read_to_string(path)?
    } else {
        String::new()
    };
    let key_re = Regex::new(&format!(r"(?m)^\s*{}\s*:", regex::escape(key)))?;
    if key_re.is_match(&current) {
        if current.contains(&next) {
            return Ok(false);
        }
        return Ok(false);
    }
    let lines: Vec<String> = next.lines().map(|line| format!("  {line}")).collect();
    let block = format!("{key}: |\n{}", lines.join("\n"));
    let merged = if current.trim().is_empty() {
        block
    } else {
        format!("{}\n\n{block}", current.trim())
    };
    write_text_file(path, &merged)
}

fn remove_yaml_instruction(path: &Path, key: &str) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let contents = fs::read_to_string(path)?;
    let lines: Vec<&str> = contents.lines().collect();
    let mut output: Vec<String> = Vec::new();
    let mut index = 0usize;
    let mut removed = false;

    while index < lines.len() {
        let line = lines[index];
        if is_yaml_key_line(line, key) {
            let key_indent = count_leading_whitespace(line);
            let mut block_lines = Vec::new();
            block_lines.push(line);
            index += 1;
            while index < lines.len() {
                let next = lines[index];
                if next.trim().is_empty() {
                    block_lines.push(next);
                    index += 1;
                    continue;
                }
                let indent = count_leading_whitespace(next);
                if indent <= key_indent {
                    break;
                }
                block_lines.push(next);
                index += 1;
            }
            let block_text = block_lines.join("\n");
            if block_text.contains(DOCDEX_INFO_START_PREFIX) && block_text.contains(DOCDEX_INFO_END) {
                removed = true;
                continue;
            }
            output.extend(block_lines.into_iter().map(|line| line.to_string()));
            continue;
        }
        output.push(line.to_string());
        index += 1;
    }

    if !removed {
        return Ok(false);
    }
    let merged = output.join("\n");
    let trimmed = merged.trim();
    if trimmed.is_empty() {
        fs::remove_file(path)?;
        return Ok(true);
    }
    write_text_file(path, trimmed)
}

fn count_leading_whitespace(line: &str) -> usize {
    line.chars().take_while(|ch| ch.is_whitespace()).count()
}

fn is_yaml_key_line(line: &str, key: &str) -> bool {
    let trimmed = line.trim_start();
    if !trimmed.starts_with(key) {
        return false;
    }
    trimmed[key.len()..].trim_start().starts_with(':')
}

fn home_dir() -> Result<PathBuf> {
    let primary = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let value = std::env::var(primary)
        .or_else(|_| std::env::var("HOME"))
        .with_context(|| format!("{primary} not set"))?;
    Ok(PathBuf::from(value))
}

fn client_instruction_paths() -> Result<InstructionPaths> {
    let home = home_dir()?;
    let app_data = std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join("AppData").join("Roaming"));
    let user_profile = if cfg!(windows) {
        std::env::var("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| home.clone())
    } else {
        home.clone()
    };

    let vscode_global_instructions = home.join(".vscode").join("global_instructions.md");
    let windsurf_global_rules = user_profile
        .join(".codeium")
        .join("windsurf")
        .join("memories")
        .join("global_rules.md");
    let roo_rules = home.join(".roo").join("rules").join("docdex.md");
    let pearai_agent = home.join(".config").join("pearai").join("agent.md");
    let aider_config = home.join(".aider.conf.yml");
    let goose_config = home.join(".config").join("goose").join("config.yaml");
    let open_interpreter_config = home
        .join(".openinterpreter")
        .join("profiles")
        .join("default.yaml");
    let codex_agents = user_profile.join(".codex").join("AGENTS.md");

    if cfg!(windows) {
        return Ok(InstructionPaths {
            claude: app_data.join("Claude").join("claude_desktop_config.json"),
            continue_config: user_profile.join(".continue").join("config.json"),
            zed: app_data.join("Zed").join("settings.json"),
            vscode_settings: app_data.join("Code").join("User").join("settings.json"),
            vscode_global_instructions,
            windsurf_global_rules,
            roo_rules,
            pearai_agent,
            aider_config,
            goose_config,
            open_interpreter_config,
            codex_agents,
        });
    }

    if cfg!(target_os = "macos") {
        return Ok(InstructionPaths {
            claude: home
                .join("Library")
                .join("Application Support")
                .join("Claude")
                .join("claude_desktop_config.json"),
            continue_config: home.join(".continue").join("config.json"),
            zed: home.join(".config").join("zed").join("settings.json"),
            vscode_settings: home
                .join("Library")
                .join("Application Support")
                .join("Code")
                .join("User")
                .join("settings.json"),
            vscode_global_instructions,
            windsurf_global_rules,
            roo_rules,
            pearai_agent,
            aider_config,
            goose_config,
            open_interpreter_config,
            codex_agents,
        });
    }

    Ok(InstructionPaths {
        claude: home
            .join(".config")
            .join("Claude")
            .join("claude_desktop_config.json"),
        continue_config: home.join(".continue").join("config.json"),
        zed: home.join(".config").join("zed").join("settings.json"),
        vscode_settings: home
            .join(".config")
            .join("Code")
            .join("User")
            .join("settings.json"),
        vscode_global_instructions,
        windsurf_global_rules,
        roo_rules,
        pearai_agent,
        aider_config,
        goose_config,
        open_interpreter_config,
        codex_agents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn strip_docdex_blocks_removes_block() {
        let block = build_docdex_instruction_block();
        let text = format!("Keep this.\n\n{block}\n\nAnd this.");
        let stripped = strip_docdex_blocks(&text);
        assert_eq!(stripped, "Keep this.\n\nAnd this.");
    }

    #[test]
    fn merge_instruction_text_replaces_versioned_block() {
        let old_block = format!(
            "{DOCDEX_INFO_START_PREFIX}0.0.1 ----\nOLD DOCDEX INSTRUCTIONS\n{DOCDEX_INFO_END}"
        );
        let existing = format!("Keep\n\n{old_block}\n\nExtra");
        let new_block = build_docdex_instruction_block();
        let merged = merge_instruction_text(&existing, &new_block, false);
        assert!(merged.contains("Keep"));
        assert!(merged.contains("Extra"));
        assert!(merged.contains(&new_block));
        assert!(!merged.contains("OLD DOCDEX INSTRUCTIONS"));
    }

    #[test]
    fn remove_prompt_file_removes_block() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("AGENTS.md");
        fs::write(&path, build_docdex_instruction_block())?;
        assert!(remove_prompt_file(&path)?);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn remove_yaml_instruction_removes_docdex_block() -> Result<()> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.yaml");
        let block = build_docdex_instruction_block();
        let indented = block
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n");
        let yaml = format!("system-prompt: |\n{indented}\n");
        fs::write(&path, yaml)?;
        assert!(remove_yaml_instruction(&path, "system-prompt")?);
        assert!(!path.exists());
        Ok(())
    }
}
