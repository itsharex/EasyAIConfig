fn run_command(command: &str, args: &[&str], cwd: Option<&Path>) -> Result<Value, String> {
  let mut cmd = Command::new(command);
  cmd.args(args);
  if let Some(dir) = cwd {
    cmd.current_dir(dir);
  }
  let output = cmd.output().map_err(|error| error.to_string())?;
  let stdout = String::from_utf8_lossy(&output.stdout).to_string();
  let stderr = String::from_utf8_lossy(&output.stderr).to_string();
  Ok(json!({
    "ok": output.status.success(),
    "code": output.status.code(),
    "stdout": stdout,
    "stderr": stderr,
  }))
}

fn command_exists(command: &str) -> Option<String> {
  which::which(command).ok().map(|path| path.to_string_lossy().to_string())
}

fn codex_candidates() -> Vec<String> {
  let mut paths = which::which_all("codex")
    .map(|items| items.map(|item| item.to_string_lossy().to_string()).collect::<Vec<_>>())
    .unwrap_or_default();

  if cfg!(not(target_os = "windows")) {
    if let Ok(home) = home_dir() {
      paths.push(home.join(".npm-global/bin/codex").to_string_lossy().to_string());
    }
    paths.push("/usr/local/bin/codex".to_string());
    paths.push("/opt/homebrew/bin/codex".to_string());
  }

  paths.sort();
  paths.dedup();
  paths
}

pub(crate) fn find_codex_binary() -> Value {
  let mut candidates = codex_candidates()
    .into_iter()
    .filter_map(|candidate_path| {
      let output = Command::new(&candidate_path).arg("--version").output().ok()?;
      if !output.status.success() {
        return None;
      }
      let version_output = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
      )
      .trim()
      .to_string();
      Some(json!({
        "path": candidate_path,
        "installed": true,
        "version": version_output,
      }))
    })
    .collect::<Vec<_>>();

  candidates.sort_by(|left, right| {
    let left_version = left.get("version").and_then(Value::as_str).unwrap_or_default();
    let right_version = right.get("version").and_then(Value::as_str).unwrap_or_default();
    compare_versions(right_version, left_version)
  });

  let selected = candidates.first().cloned();
  json!({
    "installed": selected.is_some(),
    "version": selected.as_ref().and_then(|item| item.get("version")).cloned().unwrap_or(Value::Null),
    "path": selected
      .as_ref()
      .and_then(|item| item.get("path").and_then(Value::as_str).map(|text| text.to_string()))
      .or_else(|| command_exists("codex"))
      .unwrap_or_default(),
    "candidates": candidates,
    "installCommand": format!("{} install -g {}", npm_command(), OPENAI_CODEX_PACKAGE),
  })
}

pub(crate) fn codex_npm_action(args: &[&str]) -> Result<Value, String> {
  let result = run_command(npm_command(), args, None)?;
  Ok(json!({
    "ok": result.get("ok").and_then(Value::as_bool).unwrap_or(false),
    "code": result.get("code").cloned().unwrap_or(Value::Null),
    "stdout": result.get("stdout").cloned().unwrap_or(Value::String(String::new())),
    "stderr": result.get("stderr").cloned().unwrap_or(Value::String(String::new())),
    "command": format!("{} {}", npm_command(), args.join(" ")),
  }))
}

fn escape_applescript(text: &str) -> String {
  text.replace('\\', "\\\\").replace('"', "\\\"")
}

fn launch_terminal_command(cwd: &Path) -> Result<String, String> {
  let codex_binary = find_codex_binary();
  let codex_path = codex_binary
    .get("path")
    .and_then(Value::as_str)
    .filter(|path| !path.is_empty())
    .unwrap_or("codex");
  let cwd_text = cwd.to_string_lossy().to_string();

  if cfg!(target_os = "macos") {
    let script = [
      "tell application \"Terminal\"",
      "activate",
      &format!(
        "do script \"cd {} && {}\"",
        escape_applescript(&cwd_text),
        escape_applescript(codex_path)
      ),
      "end tell",
    ]
    .join("\n");

    let output = Command::new("osascript")
      .arg("-e")
      .arg(script)
      .output()
      .map_err(|error| error.to_string())?;
    if !output.status.success() {
      return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    return Ok("Codex 已在 Terminal 中启动".to_string());
  }

  if cfg!(target_os = "windows") {
    Command::new("cmd.exe")
      .args([
        "/c",
        "start",
        "",
        "cmd",
        "/k",
        &format!("cd /d \"{}\" && \"{}\"", cwd_text, codex_path),
      ])
      .spawn()
      .map_err(|error| error.to_string())?;
    return Ok("Codex 已在新命令窗口中启动".to_string());
  }

  let terminals = vec![
    ("x-terminal-emulator", vec!["-e".to_string(), format!("bash -lc \"cd '{}' && '{}'\"", cwd_text, codex_path)]),
    ("gnome-terminal", vec!["--".to_string(), "bash".to_string(), "-lc".to_string(), format!("cd '{}' && '{}'", cwd_text, codex_path)]),
    ("konsole", vec!["-e".to_string(), "bash".to_string(), "-lc".to_string(), format!("cd '{}' && '{}'", cwd_text, codex_path)]),
  ];

  for (command, args) in terminals {
    if command_exists(command).is_none() {
      continue;
    }
    Command::new(command)
      .args(args)
      .spawn()
      .map_err(|error| error.to_string())?;
    return Ok("Codex 已在新终端中启动".to_string());
  }

  Err("没有找到可用终端，请先手动运行 codex".to_string())
}


pub(crate) fn get_codex_release_info() -> Result<Value, String> {
  let result = codex_npm_action(&["view", OPENAI_CODEX_PACKAGE, "dist-tags", "--json"])?;
  if !result.get("ok").and_then(Value::as_bool).unwrap_or(false) {
    let message = result
      .get("stderr")
      .and_then(Value::as_str)
      .filter(|text| !text.trim().is_empty())
      .or_else(|| result.get("stdout").and_then(Value::as_str))
      .unwrap_or("获取版本信息失败")
      .trim()
      .to_string();
    return Err(message);
  }

  let tags = serde_json::from_str::<Value>(result.get("stdout").and_then(Value::as_str).unwrap_or("{}"))
    .unwrap_or_else(|_| json!({}));
  let current = find_codex_binary();
  let current_version = current
    .get("version")
    .and_then(Value::as_str)
    .and_then(extract_version);
  let latest_stable = tags.get("latest").and_then(Value::as_str).map(|text| text.to_string());
  let latest_alpha = tags.get("alpha").and_then(Value::as_str).map(|text| text.to_string());

  let has_stable_update = match (&current_version, &latest_stable) {
    (Some(current), Some(latest)) => compare_versions(latest, current) == Ordering::Greater,
    _ => false,
  };
  let has_alpha_update = match (&current_version, &latest_alpha) {
    (Some(current), Some(latest)) => compare_versions(latest, current) == Ordering::Greater,
    _ => false,
  };

  Ok(json!({
    "currentVersion": current_version,
    "latestStable": latest_stable,
    "latestAlpha": latest_alpha,
    "hasStableUpdate": has_stable_update,
    "hasAlphaUpdate": has_alpha_update,
    "isInstalled": current.get("installed").and_then(Value::as_bool).unwrap_or(false),
  }))
}

pub(crate) fn launch_codex(body: &Value) -> Result<Value, String> {
  let object = parse_json_object(body);
  let cwd = {
    let input = get_string(&object, "cwd");
    if input.is_empty() { home_dir()? } else { PathBuf::from(input) }
  };
  let codex_binary = find_codex_binary();
  if !codex_binary.get("installed").and_then(Value::as_bool).unwrap_or(false) {
    return Err("Codex 尚未安装，请先点击安装".to_string());
  }
  let message = launch_terminal_command(&cwd)?;
  Ok(json!({ "ok": true, "cwd": cwd.to_string_lossy().to_string(), "message": message }))
}

pub(crate) fn check_setup_environment(query: &Value) -> Result<Value, String> {
  let query_object = parse_json_object(query);
  let codex_home = {
    let input = get_string(&query_object, "codexHome");
    if input.is_empty() { default_codex_home()? } else { PathBuf::from(input) }
  };

  // 1. Check Node.js
  let node_output = Command::new("node").arg("--version").output();
  let (node_installed, node_version, node_major) = match node_output {
    Ok(output) if output.status.success() => {
      let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
      let major = version
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
      (true, Some(version), major)
    }
    _ => (false, None, 0),
  };

  // 2. Check npm
  let npm_output = Command::new(npm_command()).arg("--version").output();
  let (npm_installed, npm_version) = match npm_output {
    Ok(output) if output.status.success() => {
      let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
      (true, Some(version))
    }
    _ => (false, None),
  };

  // 3. Check codex binary
  let codex_binary = find_codex_binary();
  let codex_installed = codex_binary.get("installed").and_then(Value::as_bool).unwrap_or(false);

  // 4. Check config files
  let global_config_path = codex_home.join("config.toml");
  let global_env_path = codex_home.join(".env");
  let config_content = read_text(&global_config_path)?;
  let env_content = read_text(&global_env_path)?;
  let config_exists = !config_content.trim().is_empty();
  let env_exists = !env_content.trim().is_empty();

  // 5. Check if there are any providers configured
  let (has_providers, has_active_provider) = if config_exists {
    match parse_toml_config(&config_content) {
      Ok(config) => {
        let providers = config
          .get("model_providers")
          .and_then(Value::as_object)
          .map(|p| !p.is_empty())
          .unwrap_or(false);
        let active = config
          .get("model_provider")
          .and_then(Value::as_str)
          .map(|s| !s.is_empty())
          .unwrap_or(false);
        (providers, active)
      }
      Err(_) => (false, false),
    }
  } else {
    (false, false)
  };

  let needs_setup = !codex_installed || !config_exists || !has_providers;

  Ok(json!({
    "node": {
      "installed": node_installed,
      "version": node_version,
      "major": node_major,
      "sufficient": node_major >= 18,
    },
    "npm": {
      "installed": npm_installed,
      "version": npm_version,
    },
    "codex": {
      "installed": codex_installed,
      "version": codex_binary.get("version").cloned().unwrap_or(Value::Null),
      "path": codex_binary.get("path").cloned().unwrap_or(Value::Null),
    },
    "config": {
      "exists": config_exists,
      "envExists": env_exists,
      "hasProviders": has_providers,
      "hasActiveProvider": has_active_provider,
      "configPath": global_config_path.to_string_lossy().to_string(),
      "envPath": global_env_path.to_string_lossy().to_string(),
    },
    "needsSetup": needs_setup,
    "codexHome": codex_home.to_string_lossy().to_string(),
  }))
}
use serde_json::{json, Value};
use std::cmp::Ordering;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::provider::get_string;
use crate::{
  compare_versions, default_codex_home, extract_version, home_dir, npm_command,
  parse_json_object, parse_toml_config, read_text, OPENAI_CODEX_PACKAGE,
};
