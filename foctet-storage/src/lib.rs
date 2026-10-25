//! Binary ciphertext storage for SQLite, PostgreSQL, MySQL and MariaDB.
//!
//! Databases never receive encryption keys. SQL versions are concurrency guards,
//! not trusted rollback checkpoints. Readers must independently know the expected
//! version and writer. This optional driver crate requires Rust 1.94 (SQLx 0.9);
//! core cryptography keeps its separate Rust 1.88 requirement. MySQL RSA password
//! exchange is disabled; use a validated TLS connection outside local tests.
use foctet_core::{BodyEnvelopeLimits, HandshakeSigner, PeerIdentity, StorageRecord};
use foctet_http::{AsyncReplayStore, MESSAGE_ID_LEN, ReplayCheck, ReplayStoreError};
use sqlx::{AnyPool, Row};

#[cfg(feature = "turso")]
pub mod turso;

/// Database or record validation error.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// A remote libSQL operation failed.
    #[error("remote database operation failed")]
    Remote,
    /// Database operation failed; no plaintext is included.
    #[error("database operation failed")]
    Database(#[from] sqlx::Error),
    /// Invalid version or resource budget.
    #[error("invalid storage input: {0}")]
    Invalid(&'static str),
    /// Encryption or writer verification failed.
    #[error("record cryptography failed")]
    Crypto(#[from] foctet_core::BodyEnvelopeError),
}
/// Signed opaque bytes persisted together in one atomic write.
#[derive(Clone, Debug)]
pub struct StoredRecord {
    /// Positive monotonic revision, limited to signed SQL BIGINT.
    pub version: u64,
    /// Encrypted bytes, not plaintext.
    pub ciphertext: Vec<u8>,
    /// Detached pinned-writer signature.
    pub signature: [u8; 64],
}
impl StoredRecord {
    /// Seals and signs a record on an endpoint before any database access.
    pub fn seal(
        plaintext: &[u8],
        recipient: [u8; 32],
        key_id: &[u8],
        record: StorageRecord<'_>,
        writer: &dyn HandshakeSigner,
        limits: &BodyEnvelopeLimits,
    ) -> Result<Self, StorageError> {
        revision(record.version)?;
        let (ciphertext, signature) = foctet_core::seal_signed_storage_record(
            plaintext, recipient, key_id, record, writer, limits,
        )?;
        Ok(Self {
            version: record.version,
            ciphertext,
            signature,
        })
    }
    /// Opens using independently trusted descriptor/version and writer identity.
    pub fn open(
        &self,
        secret: [u8; 32],
        expected: StorageRecord<'_>,
        writer: PeerIdentity,
        limits: &BodyEnvelopeLimits,
    ) -> Result<Vec<u8>, StorageError> {
        if self.version != expected.version {
            return Err(StorageError::Invalid("unexpected version"));
        }
        Ok(foctet_core::open_signed_storage_record(
            &self.ciphertext,
            self.signature,
            secret,
            expected,
            writer,
            limits,
        )?)
    }
}
fn revision(value: u64) -> Result<i64, StorageError> {
    if value == 0 {
        return Err(StorageError::Invalid("zero version"));
    }
    i64::try_from(value).map_err(|_| StorageError::Invalid("version exceeds SQL BIGINT"))
}
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(out, "{b:02x}").expect("string");
    }
    out
}

/// Supported SQL dialect. MariaDB uses the MySQL wire protocol.
#[derive(Clone, Copy, Debug)]
pub enum Dialect {
    /// SQLite, including local files.
    Sqlite,
    /// PostgreSQL.
    Postgres,
    /// MySQL or MariaDB.
    Mysql,
}
/// Connection pool storing only opaque encrypted records.
#[derive(Clone)]
pub struct SqlStore {
    pool: AnyPool,
    dialect: Dialect,
    max_bytes: usize,
}
impl SqlStore {
    /// Connects without creating or modifying any schema. URL TLS policy is the
    /// caller's responsibility; use verify-full/verify_identity in production.
    pub async fn connect(
        url: &str,
        dialect: Dialect,
        max_bytes: usize,
    ) -> Result<Self, StorageError> {
        let scheme = url.split(':').next().unwrap_or("");
        if !matches!(
            (dialect, scheme),
            (Dialect::Sqlite, "sqlite")
                | (Dialect::Postgres, "postgres" | "postgresql")
                | (Dialect::Mysql, "mysql")
        ) {
            return Err(StorageError::Invalid("database URL and dialect mismatch"));
        }
        sqlx::any::install_default_drivers();
        if max_bytes == 0 || max_bytes > i32::MAX as usize {
            return Err(StorageError::Invalid("record budget"));
        }
        let pool = sqlx::any::AnyPoolOptions::new()
            .max_connections(if url.contains(":memory:") { 1 } else { 8 })
            .connect(url)
            .await?;
        Ok(Self {
            pool,
            dialect,
            max_bytes,
        })
    }
    /// Applies the idempotent version-1 schema. Call explicitly during migration.
    pub async fn initialize(&self) -> Result<(), StorageError> {
        let blob = match self.dialect {
            Dialect::Postgres => "BYTEA",
            Dialect::Mysql => "LONGBLOB",
            Dialect::Sqlite => "BLOB",
        };
        let engine = if matches!(self.dialect, Dialect::Mysql) {
            " ENGINE=InnoDB"
        } else {
            ""
        };
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS foctet_records_v1 (record_key VARCHAR(64) PRIMARY KEY, version BIGINT NOT NULL, ciphertext {blob} NOT NULL, signature {blob} NOT NULL){engine}"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .execute(&self.pool)
            .await?;
        let sql = format!(
            "CREATE TABLE IF NOT EXISTS foctet_replay_v1 (message_id VARCHAR(32) PRIMARY KEY, expires BIGINT NOT NULL){engine}"
        );
        sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .execute(&self.pool)
            .await?;
        if matches!(self.dialect, Dialect::Mysql) {
            let rows = sqlx::query("SELECT ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME IN ('foctet_records_v1','foctet_replay_v1')").fetch_all(&self.pool).await?;
            if rows.len() != 2
                || rows.iter().any(|row| {
                    row.try_get::<String, _>(0)
                        .map_or(true, |engine| !engine.eq_ignore_ascii_case("InnoDB"))
                })
            {
                return Err(StorageError::Invalid("storage tables require InnoDB"));
            }
        }
        Ok(())
    }
    fn query(&self, sql: &'static str) -> String {
        if !matches!(self.dialect, Dialect::Postgres) {
            return sql.to_owned();
        }
        let mut n = 0;
        sql.chars()
            .map(|c| {
                if c == '?' {
                    n += 1;
                    format!("${n}")
                } else {
                    c.to_string()
                }
            })
            .collect()
    }
    /// Atomically inserts revision 1 or advances exactly expected + 1.
    /// Returns false on conflict without overwriting a concurrent writer.
    pub async fn compare_and_swap(
        &self,
        key: [u8; 32],
        expected: Option<u64>,
        record: &StoredRecord,
    ) -> Result<bool, StorageError> {
        let next = revision(record.version)?;
        if record.ciphertext.len() > self.max_bytes {
            return Err(StorageError::Invalid("record budget"));
        }
        if record.version
            != expected
                .unwrap_or(0)
                .checked_add(1)
                .ok_or(StorageError::Invalid("version overflow"))?
        {
            return Err(StorageError::Invalid("nonconsecutive version"));
        }
        if let Some(old) = expected {
            let sql = self.query("UPDATE foctet_records_v1 SET version=?, ciphertext=?, signature=? WHERE record_key=? AND version=?");
            let result = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(next)
                .bind(&record.ciphertext)
                .bind(record.signature.to_vec())
                .bind(hex(&key))
                .bind(revision(old)?)
                .execute(&self.pool)
                .await?;
            Ok(result.rows_affected() == 1)
        } else {
            let sql = self.query("INSERT INTO foctet_records_v1 (version,ciphertext,signature,record_key) VALUES (?,?,?,?)");
            match sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
                .bind(next)
                .bind(&record.ciphertext)
                .bind(record.signature.to_vec())
                .bind(hex(&key))
                .execute(&self.pool)
                .await
            {
                Ok(_) => Ok(true),
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
    }
    /// Reads bounded opaque bytes. Oversized server rows are not returned.
    pub async fn get(&self, key: [u8; 32]) -> Result<Option<StoredRecord>, StorageError> {
        let sql = self.query("SELECT version,ciphertext,signature FROM foctet_records_v1 WHERE record_key=? AND LENGTH(ciphertext)<=? AND LENGTH(signature)=64");
        let row = sqlx::query(sqlx::AssertSqlSafe(sql.as_str()))
            .bind(hex(&key))
            .bind(self.max_bytes as i64)
            .fetch_optional(&self.pool)
            .await?;
        row.map(|r| {
            let version: i64 = r.try_get(0)?;
            if version <= 0 {
                return Err(StorageError::Invalid("invalid stored version"));
            }
            let signature: Vec<u8> = r.try_get(2)?;
            let ciphertext: Vec<u8> = r.try_get(1)?;
            if ciphertext.len() > self.max_bytes {
                return Err(StorageError::Invalid("record budget"));
            }
            Ok(StoredRecord {
                version: version as u64,
                ciphertext,
                signature: signature
                    .try_into()
                    .map_err(|_| StorageError::Invalid("signature length"))?,
            })
        })
        .transpose()
    }
    /// Deletes expired replay markers; run periodically on the primary database.
    pub async fn prune_replay(&self, now: u64) -> Result<u64, StorageError> {
        let now = i64::try_from(now).map_err(|_| StorageError::Invalid("timestamp"))?;
        Ok(sqlx::query(sqlx::AssertSqlSafe(
            self.query("DELETE FROM foctet_replay_v1 WHERE expires<=?"),
        ))
        .bind(now)
        .execute(&self.pool)
        .await?
        .rows_affected())
    }
    /// Closes all pool connections, useful before backup/restart tests.
    pub async fn close(&self) {
        self.pool.close().await;
    }
}
impl AsyncReplayStore for SqlStore {
    async fn check_and_insert(
        &self,
        id: &[u8; MESSAGE_ID_LEN],
        expires: u64,
        now: u64,
    ) -> Result<ReplayCheck, ReplayStoreError> {
        async {
            if expires <= now {
                return Err(StorageError::Invalid("expired replay marker"));
            }
            let expires = revision(expires)?;
            let now = i64::try_from(now).map_err(|_| StorageError::Invalid("timestamp"))?;
            let mut tx = self.pool.begin().await?;
            sqlx::query(sqlx::AssertSqlSafe(self.query(
                "DELETE FROM foctet_replay_v1 WHERE message_id=? AND expires<=?",
            )))
            .bind(hex(id))
            .bind(now)
            .execute(&mut *tx)
            .await?;
            let insert = sqlx::query(sqlx::AssertSqlSafe(
                self.query("INSERT INTO foctet_replay_v1 (message_id,expires) VALUES (?,?)"),
            ))
            .bind(hex(id))
            .bind(expires)
            .execute(&mut *tx)
            .await;
            match insert {
                Ok(_) => {
                    tx.commit().await?;
                    Ok(ReplayCheck::Accepted)
                }
                Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
                    tx.rollback().await?;
                    Ok(ReplayCheck::Replay)
                }
                Err(e) => Err(StorageError::Database(e)),
            }
        }
        .await
        .map_err(|e: StorageError| ReplayStoreError::Backend(e.to_string()))
    }
}
