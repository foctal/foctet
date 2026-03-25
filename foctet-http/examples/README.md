# HTTP examples

For a full cross-crate map of examples, see `docs/examples.md`.

Run the server:

```bash
cargo run -p foctet-http --example axum_body_echo_server --features axum
```

Run the client in another terminal:

```bash
cargo run -p foctet-http --example axum_body_echo_client --features axum
```

Notes:

- Demo keys are hardcoded and are not production-safe.
- The examples use the recommended high-level `HttpSealer` / `HttpOpener` path.
- `application/foctet` v0 encrypts and authenticates the body bytes only, not request metadata.
- HTTP method, URL, status code, and most headers remain visible to the outer HTTP stack.
- For production use, pair body envelopes with an authenticated outer transport such as HTTPS, WebTransport, or an authenticated Foctet transport channel.
- The examples show one-shot body-complete encryption/decryption flow, not streaming transport sessions.
