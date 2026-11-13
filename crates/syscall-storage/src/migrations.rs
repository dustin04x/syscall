use rusqlite::Connection;

use crate::error::{Result, StorageError};

/// Latest schema version. Bump only with an accompanying migration.
pub const LATEST_SCHEMA_VERSION: u32 = 5;

struct Migration {
    version: u32,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        sql: include_str!("../migrations/001_initial.sql"),
    },
    Migration {
        version: 2,
        sql: include_str!("../migrations/002_session_integrity.sql"),
    },
    Migration {
        version: 3,
        sql: include_str!("../migrations/003_event_provenance.sql"),
    },
    Migration {
        version: 4,
        sql: include_str!("../migrations/004_activity_events.sql"),
    },
    Migration {
        version: 5,
        sql: include_str!("../migrations/005_evidence_accounting.sql"),
    },
];

fn user_version(conn: &Connection) -> Result<u32> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    u32::try_from(version).map_err(|_| {
        StorageError::Data(format!(
            "PRAGMA user_version returned invalid value {version}"
        ))
    })
}

/// Apply all pending migrations to a writable connection.
pub fn migrate(conn: &mut Connection) -> Result<()> {
    let mut current = user_version(conn)?;
    if current > LATEST_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion {
            found: current,
            supported: LATEST_SCHEMA_VERSION,
        });
    }

    for migration in MIGRATIONS {
        if migration.version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.pragma_update(None, "user_version", migration.version)?;
        tx.commit()?;
        current = migration.version;
        tracing::debug!(version = migration.version, "applied database migration");
    }

    Ok(())
}

/// Verify that an existing database has a schema this build understands.
pub fn check_version(conn: &Connection) -> Result<()> {
    let current = user_version(conn)?;
    if current == 0 {
        return Err(StorageError::MissingSchema);
    }
    if current > LATEST_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchemaVersion {
            found: current,
            supported: LATEST_SCHEMA_VERSION,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_database_is_migrated_to_latest() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(user_version(&conn).unwrap(), LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn migration_is_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(user_version(&conn).unwrap(), LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn newer_schema_is_rejected() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", LATEST_SCHEMA_VERSION + 1)
            .unwrap();
        assert!(matches!(
            migrate(&mut conn),
            Err(StorageError::UnsupportedSchemaVersion { .. })
        ));
    }

    #[test]
    fn check_version_rejects_uninitialized_database() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(matches!(
            check_version(&conn),
            Err(StorageError::MissingSchema)
        ));
    }
}
