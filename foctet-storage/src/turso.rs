//! Turso/libSQL Hrana HTTP v2 adapter with bounded responses and modern TLS.
//! All SQL is static and parameterized. Each write is one atomic statement.
//! This deliberately avoids legacy libSQL client TLS dependencies.
use crate::{StorageError, StoredRecord, hex, revision};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
};
use foctet_http::{AsyncReplayStore, MESSAGE_ID_LEN, ReplayCheck, ReplayStoreError};
use serde_json::{Value, json};
fn text(v: String) -> Value {
    json!({"type":"text","value":v})
}
fn integer(v: i64) -> Value {
    json!({"type":"integer","value":v.to_string()})
}
fn blob(v: &[u8]) -> Value {
    json!({"type":"blob","base64":STANDARD.encode(v)})
}

// Validate protocol shapes independently of SQL predicates. A proxy or server
// can return malformed or oversized rows despite the requested WHERE clause.
fn parse_pipeline(mut value: Value) -> Result<Value, StorageError> {
    let results = value
        .get_mut("results")
        .and_then(Value::as_array_mut)
        .ok_or(StorageError::Remote)?;
    if results.len() != 2
        || results[0]["type"] != "ok"
        || results[0]["response"]["type"] != "execute"
        || results[1]["type"] != "ok"
        || results[1]["response"]["type"] != "close"
        || !results[0]["response"]["result"].is_object()
    {
        return Err(StorageError::Remote);
    }
    Ok(results[0]["response"]["result"].take())
}

fn decode_blob(value: &Value, max: usize) -> Result<Vec<u8>, StorageError> {
    if value["type"] != "blob" {
        return Err(StorageError::Remote);
    }
    let encoded = value["base64"].as_str().ok_or(StorageError::Remote)?;
    if encoded.len() > max.div_ceil(3) * 4 {
        return Err(StorageError::Invalid("record budget"));
    }
    let bytes = STANDARD
        .decode(encoded)
        .or_else(|_| STANDARD_NO_PAD.decode(encoded))
        .map_err(|_| StorageError::Remote)?;
    if bytes.len() > max {
        return Err(StorageError::Invalid("record budget"));
    }
    Ok(bytes)
}

fn decode_record(result: Value, max: usize) -> Result<Option<StoredRecord>, StorageError> {
    let rows = result["rows"].as_array().ok_or(StorageError::Remote)?;
    if rows.is_empty() {
        return Ok(None);
    }
    if rows.len() != 1 {
        return Err(StorageError::Remote);
    }
    let row = rows[0].as_array().ok_or(StorageError::Remote)?;
    if row.len() != 3 || row[0]["type"] != "integer" {
        return Err(StorageError::Remote);
    }
    let version = row[0]["value"]
        .as_str()
        .ok_or(StorageError::Remote)?
        .parse::<u64>()
        .map_err(|_| StorageError::Remote)?;
    revision(version)?;
    Ok(Some(StoredRecord {
        version,
        ciphertext: decode_blob(&row[1], max)?,
        signature: decode_blob(&row[2], 64)?
            .try_into()
            .map_err(|_| StorageError::Invalid("signature length"))?,
    }))
}

/// Remote Hrana client. Bearer tokens are never formatted and redirects are disabled.
pub struct TursoStore {
    client: reqwest::Client,
    endpoint: reqwest::Url,
    token: zeroize::Zeroizing<String>,
    max_bytes: usize,
}
impl TursoStore {
    /// Connects without modifying schema. HTTPS is mandatory except loopback tests.
    pub async fn connect(
        url: String,
        token: String,
        max_bytes: usize,
    ) -> Result<Self, StorageError> {
        let token = zeroize::Zeroizing::new(token);
        if max_bytes == 0 || max_bytes > 64 * 1024 * 1024 {
            return Err(StorageError::Invalid("record budget"));
        }
        let url = if let Some(host) = url.strip_prefix("libsql://") {
            format!("https://{host}")
        } else {
            url
        };
        let base = reqwest::Url::parse(&url).map_err(|_| StorageError::Invalid("Turso URL"))?;
        let local = matches!(base.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
        if !(base.scheme() == "https" || (base.scheme() == "http" && local))
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
        {
            return Err(StorageError::Invalid(
                "Turso requires HTTPS without URL credentials",
            ));
        }
        let endpoint = base
            .join("/v2/pipeline")
            .map_err(|_| StorageError::Invalid("Turso URL"))?;
        let roots =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| StorageError::Remote)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| StorageError::Remote)?;
        Ok(Self {
            client,
            endpoint,
            token,
            max_bytes,
        })
    }
    async fn execute(&self, sql: &'static str, args: Vec<Value>) -> Result<Value, StorageError> {
        let mut response=self.client.post(self.endpoint.clone()).bearer_auth(self.token.as_str()).json(&json!({"requests":[{"type":"execute","stmt":{"sql":sql,"args":args,"want_rows":true}},{"type":"close"}]})).send().await.map_err(|_|StorageError::Remote)?.error_for_status().map_err(|_|StorageError::Remote)?;
        let budget = self.max_bytes * 2 + 16 * 1024;
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| StorageError::Remote)? {
            if chunk.len() > budget.saturating_sub(bytes.len()) {
                return Err(StorageError::Invalid("Turso response budget"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| StorageError::Remote)?;
        parse_pipeline(value)
    }
    /// Initializes the versioned opaque-record and replay tables.
    pub async fn initialize(&self) -> Result<(), StorageError> {
        self.execute("CREATE TABLE IF NOT EXISTS foctet_records_v1 (record_key TEXT PRIMARY KEY,version INTEGER NOT NULL,ciphertext BLOB NOT NULL,signature BLOB NOT NULL)",vec![]).await?;
        self.execute("CREATE TABLE IF NOT EXISTS foctet_replay_v1 (message_id TEXT PRIMARY KEY,expires INTEGER NOT NULL)",vec![]).await?;
        Ok(())
    }
    /// Atomically advances expected + 1, returning false on a write conflict.
    pub async fn compare_and_swap(
        &self,
        key: [u8; 32],
        expected: Option<u64>,
        record: &StoredRecord,
    ) -> Result<bool, StorageError> {
        let version = revision(record.version)?;
        if record.ciphertext.len() > self.max_bytes
            || record.version
                != expected
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(StorageError::Invalid("version overflow"))?
        {
            return Err(StorageError::Invalid("record budget or version"));
        }
        let mut args = vec![
            integer(version),
            blob(&record.ciphertext),
            blob(&record.signature),
            text(hex(&key)),
        ];
        let sql = if let Some(old) = expected {
            args.push(integer(revision(old)?));
            "UPDATE foctet_records_v1 SET version=?,ciphertext=?,signature=? WHERE record_key=? AND version=?"
        } else {
            "INSERT INTO foctet_records_v1 (version,ciphertext,signature,record_key) VALUES (?,?,?,?) ON CONFLICT(record_key) DO NOTHING"
        };
        match self.execute(sql, args).await?["affected_row_count"].as_u64() {
            Some(0) => Ok(false),
            Some(1) => Ok(true),
            _ => Err(StorageError::Remote),
        }
    }
    /// Reads bounded opaque bytes. Verify the trusted version and writer locally.
    pub async fn get(&self, key: [u8; 32]) -> Result<Option<StoredRecord>, StorageError> {
        let result=self.execute("SELECT version,ciphertext,signature FROM foctet_records_v1 WHERE record_key=? AND length(ciphertext)<=? AND length(signature)=64",vec![text(hex(&key)),integer(self.max_bytes as i64)]).await?;
        decode_record(result, self.max_bytes)
    }
    /// Deletes expired replay markers on the primary server.
    pub async fn prune_replay(&self, now: u64) -> Result<u64, StorageError> {
        let now = i64::try_from(now).map_err(|_| StorageError::Invalid("timestamp"))?;
        self.execute(
            "DELETE FROM foctet_replay_v1 WHERE expires<=?",
            vec![integer(now)],
        )
        .await?["affected_row_count"]
            .as_u64()
            .ok_or(StorageError::Remote)
    }
}
impl AsyncReplayStore for TursoStore {
    async fn check_and_insert(
        &self,
        id: &[u8; MESSAGE_ID_LEN],
        expires: u64,
        now: u64,
    ) -> Result<ReplayCheck, ReplayStoreError> {
        if expires <= now || expires > i64::MAX as u64 {
            return Err(ReplayStoreError::Backend("invalid deadline".into()));
        }
        let result=self.execute("INSERT INTO foctet_replay_v1 (message_id,expires) VALUES (?,?) ON CONFLICT(message_id) DO UPDATE SET expires=excluded.expires WHERE foctet_replay_v1.expires<=?",vec![text(hex(id)),integer(expires as i64),integer(now as i64)]).await.map_err(|_|ReplayStoreError::Backend("Turso replay failed".into()))?;
        match result["affected_row_count"].as_u64() {
            Some(1) => Ok(ReplayCheck::Accepted),
            Some(0) => Ok(ReplayCheck::Replay),
            _ => Err(ReplayStoreError::Backend("invalid Turso result".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(bytes: &[u8]) -> Value {
        json!({"rows":[[integer(1),blob(bytes),blob(&[7;64])]]})
    }
    #[test]
    fn rejects_malformed_rows_and_server_ignored_limits() {
        let valid = row(&[0, 255, 1]);
        assert_eq!(
            decode_record(valid.clone(), 3).unwrap().unwrap().ciphertext,
            [0, 255, 1]
        );
        // Same base64 encoded length: checking only encoded size is insufficient.
        assert!(decode_record(valid.clone(), 2).is_err());
        let mut wrong_type = valid.clone();
        wrong_type["rows"][0][1]["type"] = json!("text");
        let mut extra = valid.clone();
        extra["rows"]
            .as_array_mut()
            .unwrap()
            .push(valid["rows"][0].clone());
        let mut short = valid.clone();
        short["rows"][0].as_array_mut().unwrap().pop();
        let mut bad_signature = valid.clone();
        bad_signature["rows"][0][2] = blob(&[0; 65]);
        let mut bad_version = valid.clone();
        bad_version["rows"][0][0] = integer(0);
        for invalid in [
            wrong_type,
            extra,
            short,
            bad_signature,
            bad_version,
            json!({"rows":[null]}),
            json!({}),
        ] {
            assert!(decode_record(invalid, 3).is_err());
        }
        let mut unpadded = valid;
        unpadded["rows"][0][2]["base64"] = json!(STANDARD_NO_PAD.encode([7; 64]));
        assert!(decode_record(unpadded, 3).is_ok());
    }
    #[test]
    fn validates_execute_and_close_pipeline_results() {
        let valid = json!({"results":[
            {"type":"ok","response":{"type":"execute","result":{"rows":[]}}},
            {"type":"ok","response":{"type":"close"}}
        ]});
        assert!(parse_pipeline(valid.clone()).is_ok());
        let mut no_close = valid.clone();
        no_close["results"].as_array_mut().unwrap().pop();
        let mut wrong_type = valid.clone();
        wrong_type["results"][0]["response"]["type"] = json!("close");
        let mut close_error = valid;
        close_error["results"][1]["type"] = json!("error");
        for invalid in [
            no_close,
            wrong_type,
            close_error,
            json!({"results":null}),
            json!([]),
            json!("invalid"),
            json!(true),
            json!(null),
        ] {
            assert!(parse_pipeline(invalid).is_err());
        }
    }
    #[tokio::test]
    async fn rejects_insecure_and_credential_bearing_urls() {
        for url in [
            "http://example.com",
            "https://user:password@example.com",
            "https://example.com?token=secret",
            "file:///tmp/test",
        ] {
            assert!(
                TursoStore::connect(url.into(), String::new(), 1024)
                    .await
                    .is_err()
            );
        }
    }
}
