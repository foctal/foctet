# Cloudflare Workers example (`workers-rs`)

Local dev with a project-local Wrangler install:

```bash
cd foctet-http/examples/workers-echo
npm i -D wrangler@latest
npx wrangler dev
```

Run the Rust client against the local worker in another terminal:

```bash
cargo run -p foctet-http --example workers_echo_client
```

Target a deployed Worker with `WORKERS_URL`:

```bash
WORKERS_URL=https://<name>.<account>.workers.dev/foctet \
  cargo run -p foctet-http --example workers_echo_client
```

## Key rotation demo

The Worker's opener holds a keyring of two server key generations — `v2`
(current) and `v1` (retiring) — so it accepts requests sealed to either during
an overlap window. Pick which key the client seals to with `SERVER_KEY_VERSION`:

| `SERVER_KEY_VERSION` | Sealed to | Expected result |
| --- | --- | --- |
| `v2` (default) | current key | `200`, then replay `409` |
| `v1` | retiring key (still in keyring) | `200`, then replay `409` |
| `retired` | key the Worker does not hold | `401`, then replay `401` |

```bash
SERVER_KEY_VERSION=v1 cargo run -p foctet-http --example workers_echo_client
SERVER_KEY_VERSION=retired cargo run -p foctet-http --example workers_echo_client
```

`v1` and `v2` both returning `200` demonstrates overlap acceptance; `retired`
returning `401` (not `500`, and never `409` on retry) demonstrates clean failure
handling — a request sealed to a retired key fails authentication before the
replay store is consulted. See the [key-rotation guide](../../../docs/key-rotation.md)
for the production rotation procedure.

Notes:

- Demo keys are hardcoded and are not production-safe.
- Requests bind method, path, query, freshness, and message ID. Responses bind
  status and the initiating request message ID.
- Replay decisions use a per-message Durable Object. Cloudflare KV is not a
  substitute because it cannot perform the required atomic check-and-insert.
- In production, combine this with HTTPS and your normal Worker authentication / authorization checks.
- The example shows only body-complete encryption/decryption flow.
