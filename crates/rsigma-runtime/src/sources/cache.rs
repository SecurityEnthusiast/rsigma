//! Source resolution cache with in-memory and optional SQLite persistence.
//!
//! Stores last-known-good values so that `on_error: use_cached` can serve
//! stale data when a source fetch fails.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

/// Thread-safe cache for resolved source data.
///
/// Provides an in-memory layer with optional SQLite-backed disk persistence.
pub struct SourceCache {
    entries: Mutex<HashMap<String, serde_json::Value>>,
    db: Option<Mutex<rusqlite::Connection>>,
}

impl SourceCache {
    /// Create a new in-memory-only cache.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            db: None,
        }
    }

    /// Create a cache backed by a SQLite database at the given path.
    ///
    /// The table is created if it does not exist. Existing cached values
    /// are loaded into memory on construction.
    pub fn with_sqlite(path: &Path) -> Result<Self, String> {
        let conn = rusqlite::Connection::open(path)
            .map_err(|e| format!("failed to open source cache DB: {e}"))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS source_cache (
                source_id TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT (datetime('now'))
            )",
        )
        .map_err(|e| format!("failed to create source_cache table: {e}"))?;

        // Load existing entries into memory
        let entries = {
            let mut map = HashMap::new();
            let mut stmt = conn
                .prepare("SELECT source_id, value FROM source_cache")
                .map_err(|e| format!("failed to prepare SELECT: {e}"))?;
            let rows = stmt
                .query_map([], |row| {
                    let id: String = row.get(0)?;
                    let val: String = row.get(1)?;
                    Ok((id, val))
                })
                .map_err(|e| format!("failed to query source_cache: {e}"))?;

            for (id, val_str) in rows.flatten() {
                if let Ok(val) = serde_json::from_str(&val_str) {
                    map.insert(id, val);
                }
            }
            map
        };

        Ok(Self {
            entries: Mutex::new(entries),
            db: Some(Mutex::new(conn)),
        })
    }

    /// Store a resolved value in the cache (memory + disk if available).
    pub fn store(&self, source_id: &str, value: &serde_json::Value) {
        {
            let mut entries = self.entries.lock().unwrap();
            entries.insert(source_id.to_string(), value.clone());
        }

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let val_str = serde_json::to_string(value).unwrap_or_default();
            let _ = conn.execute(
                "INSERT OR REPLACE INTO source_cache (source_id, value, updated_at) VALUES (?1, ?2, datetime('now'))",
                rusqlite::params![source_id, val_str],
            );
        }
    }

    /// Retrieve a cached value for a source.
    pub fn get(&self, source_id: &str) -> Option<serde_json::Value> {
        let entries = self.entries.lock().unwrap();
        entries.get(source_id).cloned()
    }

    /// Remove a cached entry (memory + disk).
    pub fn invalidate(&self, source_id: &str) {
        {
            let mut entries = self.entries.lock().unwrap();
            entries.remove(source_id);
        }

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let _ = conn.execute(
                "DELETE FROM source_cache WHERE source_id = ?1",
                rusqlite::params![source_id],
            );
        }
    }

    /// Clear all cached entries (memory + disk).
    pub fn clear(&self) {
        {
            let mut entries = self.entries.lock().unwrap();
            entries.clear();
        }

        if let Some(db) = &self.db {
            let conn = db.lock().unwrap();
            let _ = conn.execute("DELETE FROM source_cache", []);
        }
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap();
        entries.len()
    }

    /// Returns true if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SourceCache {
    fn default() -> Self {
        Self::new()
    }
}
