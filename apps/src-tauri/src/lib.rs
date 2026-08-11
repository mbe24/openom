use openom_store::{sqlite::SqliteStore, Caps, DocStore, Snapshot, Update};
use serde::{Deserialize, Serialize};
use tauri::{Manager, State};

pub struct AppStore(pub Box<dyn DocStore>);

#[derive(Serialize)]
pub struct ReadResult {
    pub snapshot: Option<Snapshot>,
    pub updates: Vec<Update>,
    pub cursor: u64,
    pub caps: Caps,
}

#[derive(Deserialize)]
pub struct AppendArgs {
    pub doc: String,
    pub updates: Vec<Update>,
}

/// Die gesamte Brücke: lesen …
#[tauri::command]
fn store_read(state: State<'_, AppStore>, doc: String, since: Option<u64>) -> Result<ReadResult, String> {
    let s = &state.0;
    let snapshot = s.read_snapshot(&doc).map_err(|e| e.to_string())?;
    let (updates, cursor) = s.read_updates(&doc, since).map_err(|e| e.to_string())?;
    Ok(ReadResult { snapshot, updates, cursor, caps: s.caps() })
}

/// … und schreiben. Mehr Kommandos braucht der Prototyp nicht.
#[tauri::command]
fn store_append(state: State<'_, AppStore>, args: AppendArgs) -> Result<u64, String> {
    state.0.append(&args.doc, &args.updates).map_err(|e| e.to_string())
}

#[tauri::command]
fn store_put_snapshot(
    state: State<'_, AppStore>,
    doc: String,
    bytes: Vec<u8>,
    expected: Option<String>,
) -> Result<String, String> {
    state
        .0
        .put_snapshot(&doc, &bytes, expected.as_deref())
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn store_list(state: State<'_, AppStore>) -> Result<Vec<String>, String> {
    state.0.list().map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let store = SqliteStore::in_memory().expect("in-memory sqlite");
            app.manage(AppStore(Box::new(store)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            store_read,
            store_append,
            store_put_snapshot,
            store_list
        ])
        .run(tauri::generate_context!())
        .expect("error while running openom");
}
