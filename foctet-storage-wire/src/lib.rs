//! Portable signed storage for Workers and native endpoints.
//! SQL plans contain only opaque text. The default codec has no driver/runtime
//! dependency; optional workers-rs adapters execute plans through SDK bindings.
//! A blind storage service requires no private decryption keys.
//! See `docs/worker-databases.md` for the trust boundary.
pub mod database;
#[cfg(any(test, all(feature = "workers", target_arch = "wasm32")))]
mod hrana;
#[cfg(all(feature = "workers", target_arch = "wasm32"))]
pub mod workers;

use base64::{Engine, engine::general_purpose::STANDARD};
use foctet_core::{BodyEnvelopeLimits, HandshakeSigner, PeerIdentity, StorageRecord};

/// Maximum text record size. Applications may choose a smaller budget.
/// This fits comfortably below a single MySQL protocol packet even when a
/// text-only driver hex-escapes the ASCII value. Server quotas can be smaller.
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;
/// Validation or cryptographic failure. No input or secret is included.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid or over-budget input.
    #[error("invalid storage wire value")]
    Invalid,
    /// Authentication or envelope failure.
    #[error("storage authentication failed")]
    Crypto(#[from] foctet_core::BodyEnvelopeError),
}

/// A canonical `FCT1.<padded Base64 ciphertext>.<padded Base64 signature>` value.
/// Parsing checks syntax and bounds, not authenticity. Only `open` authenticates.
#[derive(Clone, Debug)]
pub struct TextRecord(String);
impl TextRecord {
    /// Parses an untrusted ASCII record with a caller-selected transport budget.
    pub fn parse(text: &str, max_bytes: usize) -> Result<Self, Error> {
        decode(text, max_bytes)?;
        Ok(Self(text.to_owned()))
    }
    /// Seals and signs at a trusted endpoint, using explicit envelope limits.
    pub fn seal(
        plaintext: &[u8],
        recipient: [u8; 32],
        key_id: &[u8],
        record: StorageRecord<'_>,
        writer: &dyn HandshakeSigner,
        limits: &BodyEnvelopeLimits,
    ) -> Result<Self, Error> {
        revision(record.version)?;
        // Reject oversized plaintext before encryption; check the final encoded
        // envelope size below, including its variable-length header.
        if plaintext.len() > (MAX_TEXT_BYTES - 94) / 4 * 3 {
            return Err(Error::Invalid);
        }
        let (ciphertext, signature) = foctet_core::seal_signed_storage_record(
            plaintext, recipient, key_id, record, writer, limits,
        )?;
        Self::from_parts(&ciphertext, &signature)
    }
    /// Encodes signed parts. This does not verify the writer.
    pub fn from_parts(ciphertext: &[u8], signature: &[u8; 64]) -> Result<Self, Error> {
        if ciphertext.is_empty() || ciphertext.len() > (MAX_TEXT_BYTES - 94) / 4 * 3 {
            return Err(Error::Invalid);
        }
        let text = format!(
            "FCT1.{}.{}",
            STANDARD.encode(ciphertext),
            STANDARD.encode(signature)
        );
        if text.len() > MAX_TEXT_BYTES {
            return Err(Error::Invalid);
        }
        Ok(Self(text))
    }
    /// Verifies an independently pinned writer and expected descriptor, then opens.
    /// Never derive `expected.version` or `writer` solely from a database response.
    pub fn open(
        &self,
        secret: [u8; 32],
        expected: StorageRecord<'_>,
        writer: PeerIdentity,
        limits: &BodyEnvelopeLimits,
    ) -> Result<Vec<u8>, Error> {
        revision(expected.version)?;
        let (ciphertext, signature) = decode(&self.0, MAX_TEXT_BYTES)?;
        Ok(foctet_core::open_signed_storage_record(
            &ciphertext,
            signature,
            secret,
            expected,
            writer,
            limits,
        )?)
    }
    /// ASCII text safe for parameter binding to a TEXT column.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
fn decode(text: &str, max_bytes: usize) -> Result<(Vec<u8>, [u8; 64]), Error> {
    if max_bytes == 0 || max_bytes > MAX_TEXT_BYTES || text.len() > max_bytes {
        return Err(Error::Invalid);
    }
    let mut fields = text.split('.');
    if fields.next() != Some("FCT1") {
        return Err(Error::Invalid);
    }
    let ct = fields.next().ok_or(Error::Invalid)?;
    let sig = fields.next().ok_or(Error::Invalid)?;
    if fields.next().is_some() || ct.is_empty() || sig.len() != 88 {
        return Err(Error::Invalid);
    }
    let ciphertext = STANDARD.decode(ct).map_err(|_| Error::Invalid)?;
    let signature = STANDARD.decode(sig).map_err(|_| Error::Invalid)?;
    // STANDARD rejects noncanonical padding and nonzero trailing bits.
    Ok((
        ciphertext,
        signature.try_into().map_err(|_| Error::Invalid)?,
    ))
}
fn revision(value: u64) -> Result<(), Error> {
    if value == 0 || value > i64::MAX as u64 {
        Err(Error::Invalid)
    } else {
        Ok(())
    }
}
/// SQL dialect for text-only Worker drivers.
#[derive(Clone, Copy)]
pub enum Dialect {
    /// Turso / libSQL / SQLite.
    Libsql,
    /// Hyperdrive MySQL / MariaDB.
    Mysql,
}
/// Bound SQL statement. Bind every argument as a string, without interpolation.
#[derive(Debug)]
pub struct Statement {
    /// Fixed library-owned SQL.
    pub sql: &'static str,
    /// Scalar text parameters, in placeholder order.
    pub args: Vec<String>,
}
/// Stateless SQL adapter for an existing async Worker connection.
/// Execute plans once. Duplicate-key INSERT means conflict; other errors propagate.
/// UPDATE must report exactly zero (conflict) or one affected row. On timeout,
/// reconcile with a fresh read; never blindly retry or advance the trusted checkpoint.
pub struct TextStore {
    dialect: Dialect,
}
impl TextStore {
    /// Creates a plan builder; performs no connection or migration.
    pub fn new(dialect: Dialect) -> Self {
        Self { dialect }
    }
    /// Explicit migration. Existing MySQL tables MUST be checked for InnoDB by
    /// the application's migration runner; CREATE IF NOT EXISTS cannot convert them.
    pub fn schema(&self) -> &'static str {
        match self.dialect {
            Dialect::Libsql => {
                "CREATE TABLE IF NOT EXISTS foctet_text_v1 (record_key TEXT PRIMARY KEY NOT NULL, version BIGINT NOT NULL CHECK(version > 0), payload TEXT NOT NULL)"
            }
            Dialect::Mysql => {
                "CREATE TABLE IF NOT EXISTS foctet_text_v1 (record_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY, version BIGINT NOT NULL CHECK(version > 0), payload MEDIUMTEXT CHARACTER SET ascii NOT NULL) ENGINE=InnoDB"
            }
        }
    }
    /// Validates a successful statement's affected-row count. Classify only
    /// duplicate-primary-key INSERT errors as conflicts before calling this.
    pub fn write_succeeded(affected_rows: u64) -> Result<bool, Error> {
        match affected_rows {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid),
        }
    }
    /// Reads only the exact expected version. A missing row is not proof of deletion.
    /// Returned payloads remain untrusted; use TextRecord::parse and TextRecord::open.
    pub fn get(&self, key: [u8; 32], expected: u64) -> Result<Statement, Error> {
        revision(expected)?;
        Ok(Statement {
            sql: "SELECT payload FROM foctet_text_v1 WHERE record_key = ? AND version = CAST(? AS SIGNED)",
            args: vec![hex(key), expected.to_string()],
        })
    }
    /// Atomically inserts version 1 (`None`) or updates exactly `previous + 1`.
    /// Keys should be opaque stable IDs scoped to an authorized tenant by the app.
    /// This blind adapter does not authenticate the payload or authorize its writer.
    pub fn compare_and_swap(
        &self,
        key: [u8; 32],
        previous: Option<u64>,
        value: &TextRecord,
    ) -> Result<Statement, Error> {
        match previous {
            None => Ok(Statement {
                sql: match self.dialect {
                    Dialect::Libsql => {
                        "INSERT INTO foctet_text_v1 (record_key, version, payload) VALUES (?, 1, ?) ON CONFLICT(record_key) DO NOTHING"
                    }
                    Dialect::Mysql => {
                        "INSERT INTO foctet_text_v1 (record_key, version, payload) VALUES (?, 1, ?)"
                    }
                },
                args: vec![hex(key), value.0.clone()],
            }),
            Some(old) => {
                revision(old)?;
                revision(old.checked_add(1).ok_or(Error::Invalid)?)?;
                Ok(Statement {
                    sql: "UPDATE foctet_text_v1 SET payload = ?, version = version + 1 WHERE record_key = ? AND version = CAST(? AS SIGNED)",
                    args: vec![value.0.clone(), hex(key), old.to_string()],
                })
            }
        }
    }
}
fn hex(key: [u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in key {
        write!(s, "{b:02x}").expect("string write");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use foctet_core::IdentityKeyPair;
    use x25519_dalek::{PublicKey, StaticSecret};
    #[test]
    fn signed_text_requires_trusted_writer_identity_and_revision() {
        let secret = [23; 32];
        let public = PublicKey::from(&StaticSecret::from(secret)).to_bytes();
        let writer = IdentityKeyPair::from_secret_key_bytes([42; 32]);
        let attacker = IdentityKeyPair::from_secret_key_bytes([43; 32]);
        let pin = PeerIdentity::new(writer.public_key());
        let limits = BodyEnvelopeLimits::default();
        let expected = StorageRecord::new(b"tenant/keys", b"root", 2);
        let record =
            TextRecord::seal(b"root key", public, b"kid", expected, &writer, &limits).unwrap();
        let parsed = TextRecord::parse(record.as_str(), MAX_TEXT_BYTES).unwrap();
        assert_eq!(
            parsed.open(secret, expected, pin, &limits).unwrap(),
            b"root key"
        );
        for descriptor in [
            StorageRecord::new(b"tenant/keys", b"root", 3),
            StorageRecord::new(b"other/keys", b"root", 2),
            StorageRecord::new(b"tenant/keys", b"other", 2),
        ] {
            assert!(parsed.open(secret, descriptor, pin, &limits).is_err());
        }
        let replacement = TextRecord::seal(
            b"attacker root",
            public,
            b"kid",
            expected,
            &attacker,
            &limits,
        )
        .unwrap();
        assert!(replacement.open(secret, expected, pin, &limits).is_err());
        assert!(parsed.open([24; 32], expected, pin, &limits).is_err());
        let (mut ciphertext, signature) = decode(parsed.as_str(), MAX_TEXT_BYTES).unwrap();
        ciphertext[0] ^= 1;
        assert!(
            TextRecord::from_parts(&ciphertext, &signature)
                .unwrap()
                .open(secret, expected, pin, &limits)
                .is_err()
        );
    }
    #[test]
    fn frozen_signed_text_vector_opens() {
        let vector: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/storage-text-v1.json")).unwrap();
        let writer: [u8; 32] = serde_json::from_value(vector["writer"].clone()).unwrap();
        for version in 1..=2 {
            let record = TextRecord::parse(
                vector["records"][version - 1].as_str().unwrap(),
                MAX_TEXT_BYTES,
            )
            .unwrap();
            assert_eq!(
                record
                    .open(
                        [23; 32],
                        StorageRecord::new(b"test", b"item", version as u64),
                        PeerIdentity::new(writer),
                        &BodyEnvelopeLimits::default()
                    )
                    .unwrap(),
                b"worker database secret"
            );
        }
    }
    #[test]
    fn strict_format_and_allocation_budgets() {
        let record = TextRecord::from_parts(&[0, 255, 128], &[0; 64]).unwrap();
        assert!(record.as_str().starts_with("FCT1.AP+A."));
        for bad in [
            record.as_str().replace("FCT1", "FCT0"),
            format!("{}.", record.as_str()),
            record.as_str().trim_end_matches('=').to_owned(),
            record.as_str().replace("AP+A", "AP-A"),
            record.as_str().replace("AP+A", "AB=="),
            format!(" {}", record.as_str()),
        ] {
            assert!(TextRecord::parse(&bad, MAX_TEXT_BYTES).is_err(), "{bad}");
        }
        assert!(TextRecord::parse(record.as_str(), record.as_str().len() - 1).is_err());
        assert!(TextRecord::parse(record.as_str(), MAX_TEXT_BYTES + 1).is_err());
        assert!(TextRecord::from_parts(&vec![0; MAX_TEXT_BYTES], &[0; 64]).is_err());
        assert!(TextRecord::from_parts(&[], &[0; 64]).is_err());
    }
    #[test]
    fn sql_plans_use_only_scalar_text_and_checked_bigints() {
        assert!(!TextStore::write_succeeded(0).unwrap());
        assert!(TextStore::write_succeeded(1).unwrap());
        assert!(TextStore::write_succeeded(2).is_err());
        let text = TextRecord::from_parts(&[255], &[0; 64]).unwrap();
        for dialect in [Dialect::Libsql, Dialect::Mysql] {
            let store = TextStore::new(dialect);
            assert!(store.get([0; 32], 0).is_err());
            assert!(store.get([0; 32], i64::MAX as u64 + 1).is_err());
            assert!(
                store
                    .compare_and_swap([0; 32], Some(i64::MAX as u64), &text)
                    .is_err()
            );
            assert!(store.compare_and_swap([0; 32], Some(0), &text).is_err());
            let plan = store
                .compare_and_swap([255; 32], Some(9007199254740993), &text)
                .unwrap();
            assert_eq!(plan.args[2], "9007199254740993");
            assert_eq!(plan.args[1], "ff".repeat(32));
            assert!(!plan.sql.contains(text.as_str()));
            assert_eq!(
                store
                    .compare_and_swap([0; 32], None, &text)
                    .unwrap()
                    .args
                    .len(),
                2
            );
        }
    }
}
