# Security and platform boundaries

## What a breach exposes

| Compromised material | Confidentiality consequence |
| --- | --- |
| Ciphertext-only database, object store, relay, or backup | No plaintext recovery under the cryptographic assumptions, provided endpoint secrets and decryption services remain outside the breach |
| Recipient private key plus captured bodies, records, or archives | Previously stored ciphertext for that recipient can be decrypted; these formats do not provide recipient-compromise forward secrecy |
| Current session state | Current and retained previous traffic keys are exposed; erased generations are not recoverable from the root chain alone |
| Writer signing key | Forged writes and new identity impersonation become possible; the signing key alone does not decrypt recipient envelopes |
| Browser scripts, endpoint process, or sufficient recovery shares | Treat accessible plaintext and keys as compromised |

Place endpoint keys, recovery shares, and trusted version checkpoints in separate
trust domains from ciphertext. A cloud secret in the same compromised account
is not an independent boundary. A Worker that decrypts is an endpoint; a Worker
that only forwards sealed bytes can remain outside the plaintext boundary.

## Trust boundaries

Use pinned identities for sessions. A valid signature from a key supplied by an
attacker proves key possession, not an authorized identity. Default sessions
reject self-signed peers without a configured trust anchor. Applications
must provision pins, authenticate updates, and handle revocation.

Public-key body and archive encryption protects confidentiality, but anyone who
knows the recipient public key can encrypt a replacement. Protected HTTP context
prevents moving existing ciphertext to a different request; it does not identify
the author of a newly created ciphertext. HTTP authentication and authorization
remain mandatory. Use `sign_ciphertext` / `verify_ciphertext` to authenticate the
exact encrypted bytes and a canonical purpose-specific context with a pinned
writer. Verify before decryption. Signing a split manifest covers its part hashes.
A signature does not make a replay fresh and does not authorize an operation.

For records, prefer `seal_signed_storage_record` / `open_signed_storage_record`.
Persist the detached signature with the ciphertext, but keep the trusted writer
pin and expected version outside the untrusted store's rollback domain. The
unsigned storage API remains available for callers that authenticate writes
through another trusted mechanism. Signatures expose linkable writer evidence.

Any service that decrypts is an endpoint within the trust boundary. To hide
content from a storage or relay service, encrypt and decrypt at trusted endpoints
and forward/store ciphertext only. TLS termination,
server-side disk encryption, and cloud-managed keys do not create this boundary.
Code served by a malicious host can steal browser keys before encryption; client
code integrity and endpoint security remain application responsibilities.

## Integration guides

See [transport requirements](transport-matrix.md),
[storage integration](storage-integration.md), and
[deployment patterns](recommended-deployments.md) for API selection.
Split files provide segmentation; only the separate threshold API provides
k-of-n key recovery. Threshold recovery uses bounded in-memory archives, while
FOCTETFS supports large single-recipient streaming files.

## Operational requirements

Replay authorities must be shared, atomic, durable, and fail closed. Preserve
entries through the inclusive freshness window (`expiry + skew + 1` seconds).
Use the same skew policy across instances and a trustworthy nondecreasing clock;
increasing skew while old entries have expired can reopen a replay interval.
Apply upload deadlines: a stream reader's time argument is a snapshot, not a
continuously updated clock. Bound request lifetime and aggregate bytes externally.
Streaming readers consume the ID after the first chunk authenticates, before
releasing that chunk. Discard a reader after any error and require `finish()`.
Never commit side effects from provisional chunks before finalization.

Signed storage prevents a server from inventing a record but cannot stop it from
withholding, deleting, or returning an old signed version when the reader has
lost its trusted checkpoint. Use compare-and-swap writes and trusted checkpoint
backup/recovery. Keep tenant and object identifiers unambiguous and do not place
plaintext content in indexes, logs, traces, object names, or queue attributes.

MySQL/MariaDB `BLOB` sizes differ from `LONGBLOB`; select the actual column type
for the configured ciphertext budget. PostgreSQL `bytea` and SQLite/Turso binary
values are byte containers, not cryptographic integration. Parameterize SQL and
keep encryption outside the database. Replicated reads are not replay authorities.

See [testing](testing.md) for reproducible validation and
[CHANGELOG.md](../CHANGELOG.md) for API changes and upgrade notes.
