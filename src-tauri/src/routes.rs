async fn dispatch(app: tauri::AppHandle, path: &str, method: &str, query: &Value, body: &Value) -> Result<Value, String> {
  match (path, method) {
    ("/api/setup/check", "GET") => check_setup_environment(query),
    ("/api/state", "GET") => load_state(query),
    ("/api/path/pick-directory", "POST") => pick_directory(app, body),
    ("/api/provider/test", "POST") => detect_provider(body).await,
    ("/api/provider/secret", "POST") => get_provider_secret(body),
    ("/api/provider/test-saved", "POST") => test_saved_provider(body).await,
    ("/api/config/save", "POST") => save_config(body),
    ("/api/config/raw-save", "POST") => save_raw_config(body),
    ("/api/config/settings-save", "POST") => save_settings(body),
    ("/api/codex/install", "POST") => codex_npm_action(&["install", "-g", OPENAI_CODEX_PACKAGE]),
    ("/api/codex/release", "GET") => get_codex_release_info(),
    ("/api/codex/reinstall", "POST") => codex_npm_action(&["install", "-g", OPENAI_CODEX_PACKAGE, "--force"]),
    ("/api/codex/update", "POST") => codex_npm_action(&["install", "-g", &format!("{}@latest", OPENAI_CODEX_PACKAGE)]),
    ("/api/codex/uninstall", "POST") => codex_npm_action(&["uninstall", "-g", OPENAI_CODEX_PACKAGE]),
    ("/api/codex/launch", "POST") => launch_codex(body),
    ("/api/backups", "GET") => list_backups(),
    ("/api/backups/restore", "POST") => restore_backup(body),
    ("/api/app/update", "GET") => get_app_update_info(app).await,
    ("/api/app/update", "POST") => install_app_update(app).await,
    _ => Err(format!("Unsupported request: {method} {path}")),
  }
}

#[tauri::command]
pub(crate) async fn backend_request(app: tauri::AppHandle, path: String, method: Option<String>, query: Option<Value>, body: Option<Value>) -> Value {
  let query_value = query.unwrap_or_else(|| json!({}));
  let body_value = body.unwrap_or_else(|| json!({}));
  match dispatch(app, &path, method.as_deref().unwrap_or("GET"), &query_value, &body_value).await {
    Ok(data) => ok(data),
    Err(error) => fail(error),
  }
}
use serde_json::{json, Value};

use crate::codex::{
  check_setup_environment, codex_npm_action, get_codex_release_info, launch_codex,
};
use crate::config::{
  get_provider_secret, list_backups, load_state, pick_directory, restore_backup, save_config,
  save_raw_config, save_settings, test_saved_provider,
};
use crate::provider::detect_provider;
use crate::updater::{get_app_update_info, install_app_update};
use crate::{fail, ok, OPENAI_CODEX_PACKAGE};
