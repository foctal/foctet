/** Blind, text-only storage. No recipient secrets or writer keys enter a driver. */
export const MAX_TEXT_BYTES = 1024 * 1024;
const MAX_REVISION = 9223372036854775807n;
function revision(value) {
  if (typeof value !== 'bigint' || value < 1n || value > MAX_REVISION)
    throw new Error('Expected a positive signed BIGINT revision');
  return value.toString();
}
function key(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value))
    throw new Error('Expected a lowercase 32-byte hex storage key');
  return value;
}
function base64(bytes) {
  let result = '';
  for (let offset = 0; offset < bytes.length; offset += 8192)
    result += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
  return btoa(result);
}
function decode(text) {
  if (text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text))
    throw new Error('Invalid Base64');
  const bytes = Uint8Array.from(atob(text), c => c.charCodeAt(0));
  if (base64(bytes) !== text) throw new Error('Noncanonical Base64');
  return bytes;
}
/** Parse only; this is not writer verification. Apply request limits before buffering. */
export function decodeRecord(text, maxBytes = MAX_TEXT_BYTES) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_TEXT_BYTES ||
      typeof text !== 'string' || text.length > maxBytes) throw new Error('Record budget exceeded');
  const parts = text.split('.');
  if (parts.length !== 3 || parts[0] !== 'FCT1' || !parts[1] || parts[2].length !== 88)
    throw new Error('Invalid signed text record');
  const ciphertext = decode(parts[1]), signature = decode(parts[2]);
  if (signature.length !== 64) throw new Error('Invalid signature size');
  return {ciphertext, signature};
}
/** Encode the ciphertext/signature returned by foctet-wasm SignedObject. */
export function encodeRecord(ciphertext, signature) {
  if (!(ciphertext instanceof Uint8Array) || !(signature instanceof Uint8Array) ||
      signature.length !== 64 || ciphertext.length === 0 ||
      ciphertext.length > Math.floor((MAX_TEXT_BYTES - 94) / 4) * 3)
    throw new Error('Invalid signed record size');
  return `FCT1.${base64(ciphertext)}.${base64(signature)}`;
}
/** Verify and decrypt on an endpoint with an independently trusted descriptor/pin. */
export function openRecord(wasm, text, secret, namespace, recordId, expectedVersion, writer) {
  revision(expectedVersion);
  const {ciphertext, signature} = decodeRecord(text);
  return wasm.openSignedStorageRecord(ciphertext, signature, secret, namespace, recordId, expectedVersion, writer);
}
const GET = 'SELECT payload FROM foctet_text_v1 WHERE record_key = ? AND version = CAST(? AS SIGNED)';
const INSERT = 'INSERT INTO foctet_text_v1 (record_key, version, payload) VALUES (?, 1, ?)';
const UPDATE = 'UPDATE foctet_text_v1 SET payload = ?, version = version + 1 WHERE record_key = ? AND version = CAST(? AS SIGNED)';
const LIBSQL_SCHEMA = 'CREATE TABLE IF NOT EXISTS foctet_text_v1 (record_key TEXT PRIMARY KEY NOT NULL, version BIGINT NOT NULL CHECK(version > 0), payload TEXT NOT NULL)';
const MYSQL_SCHEMA = 'CREATE TABLE IF NOT EXISTS foctet_text_v1 (record_key VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY, version BIGINT NOT NULL CHECK(version > 0), payload MEDIUMTEXT CHARACTER SET ascii NOT NULL) ENGINE=InnoDB';
class Store {
  constructor(execute, duplicate, schema, maxBytes) {
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_TEXT_BYTES)
      throw new Error('Invalid record budget');
    this.execute = execute; this.duplicate = duplicate; this.schema = schema; this.maxBytes = maxBytes;
  }
  /** Explicit migration only. Never called during construction or reads. */
  async initialize() { await this.execute(this.schema, []); }
  /** Return untrusted text for the independently expected version, or null. */
  async get(storageKey, expectedVersion) {
    const result = await this.execute(GET, [key(storageKey), revision(expectedVersion)]);
    if (!Array.isArray(result.rows) || result.rows.length > 1) throw new Error('Invalid database rows');
    if (!result.rows.length) return null;
    const text = result.rows[0].payload;
    decodeRecord(text, this.maxBytes);
    return text;
  }
  /** null inserts version 1; otherwise advances exactly one revision. No retries. */
  async compareAndSwap(storageKey, previousVersion, text) {
    key(storageKey); decodeRecord(text, this.maxBytes);
    let sql = this.schema === LIBSQL_SCHEMA ? INSERT + " ON CONFLICT(record_key) DO NOTHING" : INSERT;
    let args = [storageKey, text];
    if (previousVersion !== null) {
      revision(previousVersion); revision(previousVersion + 1n);
      sql = UPDATE; args = [text, storageKey, previousVersion.toString()];
    }
    let result;
    try { result = await this.execute(sql, args); }
    catch (error) {
      if (previousVersion === null && this.duplicate(error)) return false;
      throw error;
    }
    if (result.affected !== 0 && result.affected !== 1) throw new Error('Invalid affected row count');
    return result.affected === 1;
  }
}
/** Pass a request-scoped @libsql/client/web client, using the primary URL. */
export function tursoStore(client, {maxBytes = MAX_TEXT_BYTES} = {}) {
  return new Store(async (sql, args) => {
    const result = await client.execute({sql, args});
    return {rows: result.rows, affected: result.rowsAffected};
  }, error => error?.code === 'SQLITE_CONSTRAINT_PRIMARYKEY', LIBSQL_SCHEMA, maxBytes);
}
/** Pass a mysql2/promise connection configured for Hyperdrive with disableEval.
 * Connection lifetime, TLS, timeouts and cache-disabled routing belong to the app.
 */
export function hyperdriveStore(connection, {maxBytes = MAX_TEXT_BYTES} = {}) {
  const execute = async (sql, args) => {
    const [result] = await connection.execute(sql, args);
    return {rows: Array.isArray(result) ? result : [], affected: result.affectedRows};
  };
  const store = new Store(execute, error => error?.errno === 1062 && error?.sqlState === '23000', MYSQL_SCHEMA, maxBytes);
  store.initialize = async () => {
    await execute(MYSQL_SCHEMA, []);
    const result = await execute("SELECT ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'foctet_text_v1'", []);
    if (result.rows.length !== 1 || result.rows[0].engine?.toUpperCase() !== 'INNODB')
      throw new Error('Foctet requires an InnoDB table');
  };
  return store;
}
