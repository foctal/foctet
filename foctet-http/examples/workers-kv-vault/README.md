# Blind KV storage example

A Cloudflare Worker stores opaque `application/foctet` records in KV. The Rust
client encrypts and decrypts with
[`foctet_core::storage`](../../../foctet-core/src/storage.rs); the Worker holds
no decryption keys.

- `PUT /vault/:id` stores a request body.
- `GET /vault/:id` returns the stored bytes, or 404.
- `DELETE /vault/:id` removes a record.

## Run locally

```bash
cd foctet-http/examples/workers-kv-vault
npm ci
npx wrangler dev
```

In another terminal, from the repository root:

```bash
cargo run -p foctet-http --example workers_kv_vault_client
```

The client stores and opens a record, then checks that opening it with a
different record ID or expected version fails.

## Limitations

This example has fixed client keys and unauthenticated storage routes. Use it
locally. Before adapting it for deployment, add authorization, request limits,
HTTPS, and application-managed keys.

Record context binds the namespace, ID, and version. The reader must keep its
expected version independently trusted to detect rollback. This example uses
unsigned records: anyone with the recipient public key can create a fresh valid
ciphertext. Use signed storage records and a trusted writer pin when the backend
must not be able to replace data.

Encryption does not prevent deletion or denial of service. See the
[blind storage guide](../../../docs/zero-knowledge-workers-storage.md) for
application requirements.
