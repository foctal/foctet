# HTTP / Workers Recipient-Key Rotation

This guide covers rotating the **recipient key** that senders seal `foctet-http`
body envelopes to — the server key for request protection, or the client key for
response protection. It applies equally to the axum and Cloudflare Workers
adapters, which both build on `HttpOpener`.

Rotation of a live Foctet **session** key (`foctet-transport`) is a separate
mechanism (the DH ratchet / rekey control frames) and is not covered here.

## Model

A body envelope is sealed to one recipient public key and carries a sender-chosen
`key_id` (kid) identifying which recipient key was used. The kid is authenticated
(bound into the AEAD), so it cannot be altered in transit.

The recipient opens with an ordered **keyring** of secret keys
(`HttpOpenOptions`). Opening tries each key in order and succeeds on the first
that authenticates. This lets a recipient accept both the current and a previous
key during an overlap window:

```rust
// Accept the current key (v2) and the retiring key (v1).
let opener = HttpOpener::new(
    HttpOpenOptions::new(server_secret_v2).with_recipient_key(server_secret_v1),
);
```

Trial decryption is safe:

- Every keyring entry is one of the recipient's own secret keys, and each attempt
  is against context-bound, authenticated ciphertext, so a non-matching key
  simply fails to open — there is no decryption oracle.
- Authentication runs **before** the replay store is consulted, so a failing key
  attempt never consumes a replay slot. A request sealed to a key the recipient
  no longer holds is rejected identically on every retry.

Place the key that serves the most traffic first to minimize wasted attempts.

## Rotation procedure

1. **Generate** a new recipient keypair and assign it a fresh kid
   (for example `server-v2`). Store the secret with `wrangler secret put`
   (Workers) or your secret manager — never hardcode it.
2. **Add** the new secret to the recipient keyring alongside the current one and
   deploy. The recipient now accepts both keys. Nothing sender-side has changed
   yet, so all traffic still opens.
3. **Publish** the new public key + kid to senders and begin the overlap window.
   Senders migrate from the old kid to the new one at their own pace.
4. **Wait** at least the length of the longest sender-side key cache or protected
   context TTL (`DEFAULT_CONTEXT_TTL_SECS` by default). Retiring the old key
   before every in-flight sender has migrated causes spurious `401`s.
5. **Retire** the old key: remove it from the keyring and redeploy. Requests
   still sealed to the old key now fail authentication and are answered `401`.
6. **Destroy** the retired secret once you are confident no rollback is needed.

**Rollback:** if the new key is bad, keep the old key in the keyring and tell
senders to revert to the old kid. Because the recipient still holds both, no
redeploy is required to accept old-kid traffic again.

## Failure handling

With `WorkersError::status_code()` (Workers) and `AxumError::into_response`
(axum), failures map to status codes without leaking error detail:

| Condition | Status | Cause |
| --- | --- | --- |
| Sealed to a key not in the keyring (retired/unknown) | `401` | `OpenFailed` |
| Tampered body or bound header | `401` | `OpenFailed` |
| Expired protected context | `401` | `ContextExpired` |
| Replayed request | `409` | `Replayed` |
| Malformed context headers | `400` | `MissingContext` / `InvalidContext` |
| Replay-store backend error | `500` | `ReplayStore` |

Only genuine server-side faults return `500`; a client sealing to a retired key
is a `401`, not a server error.

## Monitoring

- Track the `401` rate during and after an overlap window. A rising `401` rate
  after retiring a key means senders had not finished migrating — roll the old
  key back into the keyring.
- On Workers, watch live traffic with `npx wrangler tail` while rolling out each
  step.
- Keep the overlap window open until the `401` rate at the *old* kid drops to
  zero before retiring.

## Verifying rotation

The `foctet-http` test suite covers the rotation logic
(`cargo test -p foctet-http`):

- `key_rotation_overlap_accepts_current_and_previous_key`
- `key_rotation_rejects_key_after_it_is_retired`
- `key_rotation_trial_decryption_does_not_consume_replay_slot`

The `workers-echo` example drives the same scenarios against a real Worker; see
its [README](../foctet-http/examples/workers-echo/README.md) for the
`SERVER_KEY_VERSION` matrix (`v1` / `v2` accepted, `retired` → `401`).
