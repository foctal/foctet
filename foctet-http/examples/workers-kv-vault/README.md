# Zero-knowledge KV vault (blind storage Worker)

A Cloudflare Workers + KV backend that stores end-to-end-encrypted vault items
**without holding any key**. The Worker only moves opaque `application/foctet`
blobs in and out of KV; all sealing and opening happens on the client with
[`foctet_core::storage`](../../../foctet-core/src/storage.rs).

Routes:

- `PUT /vault/:id` — store the request body under `id`
- `GET /vault/:id` — return the stored bytes (404 if absent)
- `DELETE /vault/:id` — remove the record

## Local dev

```bash
cd foctet-http/examples/workers-kv-vault
npm i -D wrangler@latest
npx wrangler dev
```

Run the Rust client against the local Worker in another terminal (from the repo
root):

```bash
cargo run -p foctet-http --example workers_kv_vault_client
```

Expected:

```
stored <N> ciphertext bytes to http://127.0.0.1:8787/vault/login-github
opened: github password: correct horse battery staple
substitution correctly rejected (wrong record id fails to open)
rollback correctly rejected (stale version fails to open)
```

The client seals a vault item, uploads the blob, fetches it back and opens it,
then proves that the same blob does **not** open under a different record id
(substitution) or a newer expected version (rollback).

## Deploy

```bash
# Create a KV namespace and paste the id into wrangler.toml (kv_namespaces.id).
npx wrangler kv namespace create VAULT_KV
export CLOUDFLARE_API_TOKEN=...
npx wrangler deploy

VAULT_URL=https://<name>.<account>.workers.dev \
  cargo run -p foctet-http --example workers_kv_vault_client
```

## What this proves

- **Zero knowledge:** the Worker has no foctet or crypto dependency (see
  `Cargo.toml`) and never sees a key, so a compromised Worker or KV store yields
  only opaque ciphertext.
- **Substitution / rollback resistance:** each value binds its namespace / id /
  version into the AEAD, so a backend cannot answer a query for one record with
  another record's ciphertext, or serve a stale version, without the client's
  open failing.

Notes:

- Demo keys are hardcoded and not production-safe; a real client derives the
  account key from the user's master password and never uploads it.
- Transport is plain HTTP because the payload is already end-to-end encrypted;
  keep HTTPS in production and add your normal Worker auth/authorization.
- See the [zero-knowledge storage guide](../../../docs/zero-knowledge-workers-storage.md).
