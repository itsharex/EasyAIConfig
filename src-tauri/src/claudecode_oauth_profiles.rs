// Claude Code OAuth profile manager.
//
// Unlike Codex (which stores OAuth tokens plainly in ~/.codex/auth.json so we
// had to copy files around ourselves), Claude Code has a native mechanism:
//
//   - `CLAUDE_CONFIG_DIR=/some/path` → Claude Code reads/writes all state
//     (including .claude.json and .credentials.json) under that directory.
//   - The Keychain service name is automatically namespaced per config dir
//     (`Claude Code-credentials-<8-char-sha256>`), so tokens for each profile
//     live in their own macOS Keychain entry and never collide.
//
// So our "profile" is literally a CLAUDE_CONFIG_DIR under our own home.
// Switching = telling the launcher which one to point CLAUDE_CONFIG_DIR at.
// We never read or write Keychain ourselves, never copy tokens, never touch
// the user's default ~/.claude/. That means:
//   - No plaintext tokens on disk that we manage.
//   - No risk of corrupting the user's existing login.
//   - Account switching is invisible at the protocol level (Claude Code
//     client sends no device fingerprint — verified against source).
//
// Layout:
//   ~/.codex-config-ui/claudecode-oauth-profiles/
//     profiles.json              — { version, active, lastSwitchAt, profiles: [...] }
//     <id>/                      — this directory IS CLAUDE_CONFIG_DIR for the profile
//       .claude.json             — Claude writes oauthAccount here after login
//       .credentials.json        — (Linux/Windows only; macOS uses Keychain)
//       ...                      — Claude manages the rest

use chrono::Utc;
use serde_json::{json, Map, Value};
use std::fs;
use std::path::PathBuf;
use uuid::Uuid;

use crate::provider::get_string;
use crate::{app_home, ensure_dir, parse_json_object, read_text, write_text};

const PROFILES_DIRNAME: &str = "claudecode-oauth-profiles";
const PROFILES_INDEX: &str = "profiles.json";

fn profiles_root() -> Result<PathBuf, String> {
  Ok(app_home()?.join(PROFILES_DIRNAME))
}

fn profiles_index_path() -> Result<PathBuf, String> {
  Ok(profiles_root()?.join(PROFILES_INDEX))
}

fn profile_dir(id: &str) -> Result<PathBuf, String> {
  if id.trim().is_empty() || id.contains('/') || id.contains('\\') || id.contains("..") {
    return Err("非法的 profile id".to_string());
  }
  Ok(profiles_root()?.join(id))
}

fn read_profiles_index() -> Result<Value, String> {
  let path = profiles_index_path()?;
  let text = read_text(&path)?;
  if text.trim().is_empty() {
    return Ok(json!({
      "version": 1,
      "active": "",
      "lastSwitchAt": 0,
      "profiles": [],
    }));
  }
  let parsed: Value = serde_json::from_str(&text)
    .map_err(|e| format!("claudecode profiles.json 解析失败: {}", e))?;
  Ok(parsed)
}

fn write_profiles_index(index: &Value) -> Result<(), String> {
  ensure_dir(&profiles_root()?)?;
  let path = profiles_index_path()?;
  let text = serde_json::to_string_pretty(index).map_err(|e| e.to_string())?;
  write_text(&path, &text)
}

fn get_str_obj(obj: &Map<String, Value>, key: &str) -> String {
  obj.get(key).and_then(Value::as_str).unwrap_or("").trim().to_string()
}

// Pull oauthAccount metadata out of a profile's .claude.json. Returns empty
// strings when the file is missing / not yet populated (i.e. user hasn't
// finished the login flow yet).
fn read_profile_metadata(dir: &std::path::Path) -> Value {
  let mut out = json!({
    "accountUuid": "",
    "email": "",
    "organizationName": "",
    "organizationUuid": "",
    "organizationRole": "",
    "displayName": "",
    "plan": "",
    "hasTokens": false,
  });

  let claude_json = read_text(&dir.join(".claude.json")).unwrap_or_default();
  if claude_json.trim().is_empty() {
    return out;
  }
  let parsed: Value = match serde_json::from_str(&claude_json) {
    Ok(v) => v,
    Err(_) => return out,
  };
  let account = match parsed.get("oauthAccount").and_then(Value::as_object) {
    Some(obj) => obj,
    None => return out,
  };

  let account_uuid = get_str_obj(account, "accountUuid");
  let email = get_str_obj(account, "emailAddress");
  let org_name = get_str_obj(account, "organizationName");
  let org_uuid = get_str_obj(account, "organizationUuid");
  let org_role = get_str_obj(account, "organizationRole");
  let display_name = get_str_obj(account, "displayName");
  // Subscription tier — claude.json stores this under different possible keys.
  let plan = if !get_str_obj(account, "billingType").is_empty() {
    // billingType values observed: "stripe_subscription", etc. — not the plan tier
    // itself. Fall back to subscriptionType if Claude stored one; otherwise blank.
    get_str_obj(account, "subscriptionType")
  } else {
    get_str_obj(account, "subscriptionType")
  };

  if let Some(obj) = out.as_object_mut() {
    obj.insert("accountUuid".to_string(), json!(account_uuid));
    obj.insert("email".to_string(), json!(email));
    obj.insert("organizationName".to_string(), json!(org_name));
    obj.insert("organizationUuid".to_string(), json!(org_uuid));
    obj.insert("organizationRole".to_string(), json!(org_role));
    obj.insert("displayName".to_string(), json!(display_name));
    obj.insert("plan".to_string(), json!(plan));
    obj.insert("hasTokens".to_string(), json!(!account_uuid.is_empty()));
  }
  out
}

// Public: expose the active profile's CONFIG_DIR so the launcher can inject
// CLAUDE_CONFIG_DIR. Returns None when no profile is active (i.e. default
// ~/.claude/ should be used — unchanged from previous behavior).
pub(crate) fn active_profile_config_dir() -> Option<PathBuf> {
  let index = read_profiles_index().ok()?;
  let active = index.get("active").and_then(Value::as_str).unwrap_or("");
  if active.is_empty() {
    return None;
  }
  let dir = profile_dir(active).ok()?;
  if !dir.exists() {
    return None;
  }
  Some(dir)
}

// ---- Public routes ----

// Refresh each profile's displayed metadata from its .claude.json on every
// list call — cheap enough (single small JSON parse per profile) and means
// token refreshes / org changes propagate without an explicit "refresh meta"
// button.
pub(crate) fn list_claudecode_oauth_profiles(_query: &Value) -> Result<Value, String> {
  let mut index = read_profiles_index()?;
  let active = index.get("active").and_then(Value::as_str).unwrap_or("").to_string();
  let last_switch_at = index.get("lastSwitchAt").and_then(Value::as_i64).unwrap_or(0);

  let profiles_arr = index
    .get_mut("profiles")
    .and_then(Value::as_array_mut)
    .cloned()
    .unwrap_or_default();

  let mut enriched = Vec::new();
  for p in profiles_arr {
    let id = p.get("id").and_then(Value::as_str).unwrap_or("").to_string();
    if id.is_empty() {
      continue;
    }
    let name = p.get("name").and_then(Value::as_str).unwrap_or("").to_string();
    let created_at = p.get("createdAt").and_then(Value::as_i64).unwrap_or(0);
    let updated_at = p.get("updatedAt").and_then(Value::as_i64).unwrap_or(0);
    let dir = profile_dir(&id)?;
    let meta = read_profile_metadata(&dir);
    enriched.push(json!({
      "id": id,
      "name": name,
      "configDir": dir.to_string_lossy().to_string(),
      "createdAt": created_at,
      "updatedAt": updated_at,
      "accountUuid": meta.get("accountUuid").cloned().unwrap_or(json!("")),
      "email": meta.get("email").cloned().unwrap_or(json!("")),
      "organizationName": meta.get("organizationName").cloned().unwrap_or(json!("")),
      "organizationRole": meta.get("organizationRole").cloned().unwrap_or(json!("")),
      "displayName": meta.get("displayName").cloned().unwrap_or(json!("")),
      "plan": meta.get("plan").cloned().unwrap_or(json!("")),
      "hasTokens": meta.get("hasTokens").cloned().unwrap_or(json!(false)),
    }));
  }

  Ok(json!({
    "active": active,
    "lastSwitchAt": last_switch_at,
    "profiles": enriched,
  }))
}

// Create a new profile *slot*. Doesn't run codex login — caller is expected to
// separately POST /api/claudecode/login with the same profileId so the terminal
// can launch `CLAUDE_CONFIG_DIR=<dir> claude auth login`.
pub(crate) fn create_claudecode_oauth_profile(body: &Value) -> Result<Value, String> {
  let object = parse_json_object(body);
  let requested_name = get_string(&object, "name");
  let id = format!("prof_{}", Uuid::new_v4().simple());
  let dir = profile_dir(&id)?;
  ensure_dir(&dir)?;

  let now = Utc::now().timestamp();
  let name = if requested_name.is_empty() {
    format!("Claude 账号 #{}", &id[..8.min(id.len())])
  } else {
    requested_name
  };

  let mut index = read_profiles_index()?;
  if let Some(arr) = index.get_mut("profiles").and_then(Value::as_array_mut) {
    arr.push(json!({
      "id": id,
      "name": name,
      "createdAt": now,
      "updatedAt": now,
    }));
  } else if let Some(obj) = index.as_object_mut() {
    obj.insert(
      "profiles".to_string(),
      json!([{
        "id": id,
        "name": name,
        "createdAt": now,
        "updatedAt": now,
      }]),
    );
  }
  write_profiles_index(&index)?;

  Ok(json!({
    "id": id,
    "name": name,
    "configDir": dir.to_string_lossy().to_string(),
  }))
}

// Switch the active profile — this is *only* a pointer update. No Keychain
// ops, no file copies. All future Claude launches from our app will set
// CLAUDE_CONFIG_DIR=<dir> if active is non-empty, and skip the env var if
// active is empty (user switching back to ~/.claude/ default).
pub(crate) fn switch_claudecode_oauth_profile(body: &Value) -> Result<Value, String> {
  let object = parse_json_object(body);
  let id = get_string(&object, "id"); // empty string = back to default

  let mut index = read_profiles_index()?;
  let now = Utc::now().timestamp();
  let last = index.get("lastSwitchAt").and_then(Value::as_i64).unwrap_or(0);

  // Defensive server-side throttle: 60s hard floor so buggy/malicious callers
  // can't hammer switches. UI enforces the same.
  if last > 0 && now - last < 60 && id != index.get("active").and_then(Value::as_str).unwrap_or("") {
    return Err(format!(
      "切换太频繁，请在 {} 秒后再试（防风控）",
      60 - (now - last)
    ));
  }

  if !id.is_empty() {
    let dir = profile_dir(&id)?;
    if !dir.exists() {
      return Err("目标 profile 目录不存在".to_string());
    }
  }

  if let Some(obj) = index.as_object_mut() {
    obj.insert("active".to_string(), json!(id));
    obj.insert("lastSwitchAt".to_string(), json!(now));
  }
  write_profiles_index(&index)?;

  Ok(json!({ "active": id }))
}

pub(crate) fn rename_claudecode_oauth_profile(body: &Value) -> Result<Value, String> {
  let object = parse_json_object(body);
  let id = get_string(&object, "id");
  let name = get_string(&object, "name");
  if id.is_empty() { return Err("id is required".to_string()); }
  if name.is_empty() { return Err("name is required".to_string()); }

  let mut index = read_profiles_index()?;
  let mut touched = false;
  let now = Utc::now().timestamp();
  if let Some(arr) = index.get_mut("profiles").and_then(Value::as_array_mut) {
    for p in arr.iter_mut() {
      if p.get("id").and_then(Value::as_str).unwrap_or("") == id {
        if let Some(obj) = p.as_object_mut() {
          obj.insert("name".to_string(), json!(name));
          obj.insert("updatedAt".to_string(), json!(now));
        }
        touched = true;
        break;
      }
    }
  }
  if !touched {
    return Err("未找到该 profile".to_string());
  }
  write_profiles_index(&index)?;
  Ok(json!({ "id": id, "name": name }))
}

// Delete the profile's directory. Keychain entries (macOS) are left as
// harmless orphans — reclaim is manual via Keychain Access if a user cares.
// We deliberately don't touch ~/.claude/ or the default Keychain entry.
pub(crate) fn delete_claudecode_oauth_profile(body: &Value) -> Result<Value, String> {
  let object = parse_json_object(body);
  let id = get_string(&object, "id");
  if id.is_empty() { return Err("id is required".to_string()); }

  let dir = profile_dir(&id)?;

  let mut index = read_profiles_index()?;
  let mut removed = false;
  if let Some(arr) = index.get_mut("profiles").and_then(Value::as_array_mut) {
    let before = arr.len();
    arr.retain(|p| p.get("id").and_then(Value::as_str).unwrap_or("") != id);
    removed = arr.len() != before;
  }
  if !removed {
    return Err("未找到该 profile".to_string());
  }
  if let Some(obj) = index.as_object_mut() {
    let active = obj.get("active").and_then(Value::as_str).unwrap_or("").to_string();
    if active == id {
      obj.insert("active".to_string(), json!(""));
    }
  }
  write_profiles_index(&index)?;

  if dir.exists() {
    let _ = fs::remove_dir_all(&dir);
  }

  Ok(json!({ "id": id }))
}
