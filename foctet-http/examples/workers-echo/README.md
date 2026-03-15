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
- The examples show only body-complete encryption/decryption flow.
