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

Notes:

- Demo keys are hardcoded and are not production-safe.
- The example protects request and response bodies only; method, path, and headers remain outer HTTP metadata.
- In production, combine this with HTTPS and your normal Worker authentication / authorization checks.
- The example shows only body-complete encryption/decryption flow.
