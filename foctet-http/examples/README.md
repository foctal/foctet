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

The client also has turn-key negative tests (each asserts the expected rejection
and exits non-zero otherwise):

- `--replay` — re-sends the identical sealed request; the second is rejected with
  **409** (single-use message id).
- `--wrong-path` — POSTs a request sealed for `/foctet` to `/foctet-elsewhere`;
  rejected with **401** (the path is bound into the AEAD).
- `--expired` — seals with an already-elapsed expiry; rejected with **401**.

See `tests.md` (§4) for the full runbook.

Notes:

- Demo keys are hardcoded and are not production-safe.
- The examples use the recommended high-level `HttpSealer` / `HttpOpener` path.
- `application/foctet` v0 encrypts and authenticates the body bytes only, not request metadata.
- HTTP method, URL, status code, and most headers remain visible to the outer HTTP stack.
- For production use, pair body envelopes with an authenticated outer transport such as HTTPS, WebTransport, or an authenticated Foctet transport channel.
- The examples show one-shot body-complete encryption/decryption flow, not streaming transport sessions.
