# Blind KV storage example

A Cloudflare Worker stores signed TEXT records in KV. The Rust
client creates a recipient key and a writer identity for each run. It verifies
the returned record with its local writer pin and expected object revision.

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
newer expected version fails.

## Limitations

The example has unauthenticated storage routes and a 1 MiB record limit. Run
it locally. Deployments need authorization, HTTPS, durable endpoint keys, and
trusted revision checkpoints stored outside KV. The example's ephemeral keys
can only open records within the same run.

Encryption does not prevent deletion or denial of service. See the
[blind storage guide](../../../docs/zero-knowledge-workers-storage.md) for
application requirements.
