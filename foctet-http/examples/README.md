# HTTP examples

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
- `application/foctet` v1 authenticates the encrypted body only, not request metadata.
- The examples show only body-complete encryption/decryption flow.
