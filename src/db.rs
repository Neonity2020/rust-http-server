//! SQLite storage.
//!
//! rusqlite is the Rust counterpart of the Node `better-sqlite3` package: one
//! synchronous connection, prepared statements, no async. Every statement is
//! therefore reached through [`AppState::db`](crate::AppState::db), which moves
//! the work onto the blocking pool.

use std::{
    fmt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use rusqlite::Connection;
use serde::Serialize;

pub type Result<T> = std::result::Result<T, rusqlite::Error>;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Item {
    pub id: i64,
    pub name: String,
}

/// Seconds since the Unix epoch, the unit every timestamp column uses.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Opening a database fails for two unrelated reasons, so the boot error keeps
/// them apart instead of flattening into one string.
#[derive(Debug)]
pub enum ConnectError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "{err}"),
            Self::Sqlite(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<std::io::Error> for ConnectError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<rusqlite::Error> for ConnectError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

pub fn open(path: &Path) -> std::result::Result<Connection, ConnectError> {
    // A bare "app.db" has an empty parent; create_dir_all("") would fail.
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    configure(&conn)?;
    Ok(conn)
}

/// Same schema and pragmas, but backed by RAM. Used by the tests.
#[cfg(test)]
pub fn open_in_memory() -> Result<Connection> {
    let conn = Connection::open_in_memory()?;
    configure(&conn)?;
    Ok(conn)
}

fn configure(conn: &Connection) -> Result<()> {
    // WAL lets readers run while a writer holds the write lock; it is a no-op
    // for in-memory databases, which report `memory` here.
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;",
    )
}

/// `COLLATE NOCASE` on `username` is what makes `Alice` and `alice` the same
/// account; the UNIQUE index is what stops the second one from being created.
const MIGRATION_1: &str = r#"
CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    password_hash TEXT    NOT NULL,
    created_at    INTEGER NOT NULL
);

-- Only the SHA-256 of the cookie token is stored, so a leaked database file
-- cannot be replayed as a set of working cookies. Deleting a user takes their
-- sessions with them.
CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY,
    token_hash TEXT    NOT NULL UNIQUE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_expires_at ON sessions (expires_at);
CREATE INDEX sessions_user_id ON sessions (user_id);

CREATE TABLE items (
    id   INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);

-- Demo rows so /api/items is not empty on a fresh database. These live inside
-- the migration, so they are inserted once ever: deleting every item does not
-- resurrect them on the next boot.
INSERT INTO items (name) SELECT 'apple';
INSERT INTO items (name) SELECT 'banana';
INSERT INTO items (name) SELECT 'cherry';
"#;

/// Applied in order, each recorded in `PRAGMA user_version`. Never edit a
/// migration that has shipped; append a new one.
const MIGRATIONS: &[&str] = &[MIGRATION_1];

pub fn migrate(conn: &Connection) -> Result<()> {
    let from: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;

    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let version = index as i64 + 1;
        if version <= from {
            continue;
        }

        // DDL in SQLite is transactional, so a failure part-way through leaves
        // the previous schema intact rather than a half-built one.
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let applied = conn
            .execute_batch(sql)
            .and_then(|()| conn.pragma_update(None, "user_version", version));
        if let Err(err) = applied {
            let _ = conn.execute_batch("ROLLBACK");
            return Err(err);
        }
        conn.execute_batch("COMMIT")?;
        tracing::info!(version, "applied database migration");
    }

    Ok(())
}

pub fn is_username_taken_error(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
    )
}

// ---------- users ----------

pub fn create_user(conn: &Connection, username: &str, password_hash: &str) -> Result<User> {
    let created_at = now();
    conn.execute(
        "INSERT INTO users (username, password_hash, created_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![username, password_hash, created_at],
    )?;
    Ok(User {
        id: conn.last_insert_rowid(),
        username: username.to_string(),
        created_at,
    })
}

/// Returns the user together with the stored hash — the hash never leaves this
/// module except to be verified.
pub fn user_with_hash(conn: &Connection, username: &str) -> Result<Option<(User, String)>> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT id, username, created_at, password_hash
           FROM users
          WHERE username = ?1",
        rusqlite::params![username],
        |row| {
            let user = User {
                id: row.get(0)?,
                username: row.get(1)?,
                created_at: row.get(2)?,
            };
            Ok((user, row.get(3)?))
        },
    )
    .optional()
}

pub fn count_users(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))
}

// ---------- sessions ----------

pub fn create_session(
    conn: &Connection,
    token_hash: &str,
    user_id: i64,
    expires_at: i64,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![token_hash, user_id, now(), expires_at],
    )?;
    Ok(conn.last_insert_rowid())
}

/// Resolves a cookie token to its owner. Expired sessions are dropped on the
/// way past so a stale cookie cannot keep a row alive forever.
pub fn user_for_session(
    conn: &Connection,
    token_hash: &str,
    now: i64,
) -> Result<Option<(User, i64)>> {
    use rusqlite::OptionalExtension as _;
    let found: Option<(User, i64)> = conn
        .query_row(
            "SELECT u.id, u.username, u.created_at, s.expires_at
               FROM sessions s
               JOIN users u ON u.id = s.user_id
              WHERE s.token_hash = ?1",
            rusqlite::params![token_hash],
            |row| {
                let user = User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    created_at: row.get(2)?,
                };
                Ok((user, row.get(3)?))
            },
        )
        .optional()?;

    match found {
        Some((user, expires_at)) if expires_at > now => Ok(Some((user, expires_at))),
        Some(_) => {
            delete_session(conn, token_hash)?;
            Ok(None)
        }
        None => Ok(None),
    }
}

pub fn delete_session(conn: &Connection, token_hash: &str) -> Result<usize> {
    conn.execute(
        "DELETE FROM sessions WHERE token_hash = ?1",
        rusqlite::params![token_hash],
    )
}

pub fn delete_expired_sessions(conn: &Connection, now: i64) -> Result<usize> {
    conn.execute(
        "DELETE FROM sessions WHERE expires_at <= ?1",
        rusqlite::params![now],
    )
}

// ---------- items ----------

pub fn list_items(conn: &Connection) -> Result<Vec<Item>> {
    let mut stmt = conn.prepare("SELECT id, name FROM items ORDER BY id")?;
    let items = stmt.query_map([], |row| {
        Ok(Item {
            id: row.get(0)?,
            name: row.get(1)?,
        })
    })?;
    items.collect()
}

pub fn item(conn: &Connection, id: i64) -> Result<Option<Item>> {
    use rusqlite::OptionalExtension as _;
    conn.query_row(
        "SELECT id, name FROM items WHERE id = ?1",
        rusqlite::params![id],
        |row| {
            Ok(Item {
                id: row.get(0)?,
                name: row.get(1)?,
            })
        },
    )
    .optional()
}

pub fn create_item(conn: &Connection, name: &str) -> Result<Item> {
    conn.execute(
        "INSERT INTO items (name) VALUES (?1)",
        rusqlite::params![name],
    )?;
    Ok(Item {
        id: conn.last_insert_rowid(),
        name: name.to_string(),
    })
}

pub fn delete_item(conn: &Connection, id: i64) -> Result<usize> {
    conn.execute("DELETE FROM items WHERE id = ?1", rusqlite::params![id])
}

pub fn count_items(conn: &Connection) -> Result<i64> {
    conn.query_row("SELECT COUNT(*) FROM items", [], |row| row.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn migrated() -> Connection {
        let conn = open_in_memory().expect("in-memory database");
        migrate(&conn).expect("migrate");
        conn
    }

    #[test]
    fn migrations_are_idempotent() {
        let conn = migrated();
        // A second boot must not re-run the inserts or re-seed the demo items.
        migrate(&conn).expect("second migrate");
        assert_eq!(count_items(&conn).unwrap(), 3);
        assert_eq!(count_users(&conn).unwrap(), 0);
    }

    #[test]
    fn seeded_items_match_the_demo_data() {
        let conn = migrated();
        let items = list_items(&conn).unwrap();
        assert_eq!(items.len(), 3);
        assert_eq!(
            items[0],
            Item {
                id: 1,
                name: "apple".to_string()
            }
        );
        assert_eq!(items[2].name, "cherry");
    }

    #[test]
    fn usernames_are_case_insensitive_but_unique() {
        let conn = migrated();
        let alice = create_user(&conn, "Alice", "$argon2id$fake").unwrap();
        assert_eq!(alice.id, 1);

        let err = create_user(&conn, "alice", "$argon2id$fake").unwrap_err();
        assert!(is_username_taken_error(&err), "got: {err}");

        // The lookup that login performs agrees with the constraint.
        assert!(user_with_hash(&conn, "ALICE").unwrap().is_some());
        assert_eq!(user_with_hash(&conn, "bob").unwrap(), None);
    }

    #[test]
    fn a_session_resolves_to_its_owner_until_it_expires() {
        let conn = migrated();
        let user = create_user(&conn, "carol", "$argon2id$fake").unwrap();
        create_session(&conn, "token-hash", user.id, now() + 60).unwrap();

        let (found, expires_at) = user_for_session(&conn, "token-hash", now())
            .unwrap()
            .unwrap();
        assert_eq!(found.username, "carol");
        assert!(expires_at > now());

        assert_eq!(user_for_session(&conn, "other-token", now()).unwrap(), None);
    }

    #[test]
    fn an_expired_session_is_rejected_and_removed() {
        let conn = migrated();
        let user = create_user(&conn, "dave", "$argon2id$fake").unwrap();
        create_session(&conn, "stale", user.id, now() - 1).unwrap();

        assert_eq!(user_for_session(&conn, "stale", now()).unwrap(), None);
        // The row is gone, not just ignored.
        assert_eq!(delete_session(&conn, "stale").unwrap(), 0);
    }

    #[test]
    fn deleting_a_user_takes_their_sessions_along() {
        let conn = migrated();
        let user = create_user(&conn, "erin", "$argon2id$fake").unwrap();
        create_session(&conn, "erin-token", user.id, now() + 60).unwrap();

        conn.execute(
            "DELETE FROM users WHERE id = ?1",
            rusqlite::params![user.id],
        )
        .unwrap();
        assert_eq!(user_for_session(&conn, "erin-token", now()).unwrap(), None);
    }

    #[test]
    fn purge_only_removes_sessions_that_are_already_dead() {
        let conn = migrated();
        let user = create_user(&conn, "frank", "$argon2id$fake").unwrap();
        create_session(&conn, "expired", user.id, now() - 1).unwrap();
        create_session(&conn, "live", user.id, now() + 600).unwrap();

        assert_eq!(delete_expired_sessions(&conn, now()).unwrap(), 1);
        assert!(user_for_session(&conn, "live", now()).unwrap().is_some());
    }

    #[test]
    fn item_crud_round_trips_and_reports_missing_rows() {
        let conn = migrated();
        let created = create_item(&conn, "date").unwrap();
        assert_eq!(item(&conn, created.id).unwrap(), Some(created.clone()));

        assert_eq!(delete_item(&conn, created.id).unwrap(), 1);
        assert_eq!(delete_item(&conn, created.id).unwrap(), 0);
        assert_eq!(item(&conn, created.id).unwrap(), None);
    }
}
