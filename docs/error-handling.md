# Error handling and terminal-state policy

This document defines the required caller action for every public Foctet error
surface. It is part of the protocol safety contract: an error is not a license
to retry the same ciphertext, plaintext, control message, or session on an
arbitrary connection.

## Rules

- A **recoverable** result was rejected before the stateful endpoint accepted
  an ambiguous protocol transition. Correct the input, drain backpressure, or
  wait for admission before attempting another operation on that endpoint.
- A **terminal** result requires discarding the endpoint and its `Session`, if
  any. Establish a fresh authenticated session. Do not retry the protected
  bytes on the same session.
- A **request rejection** applies to HTTP's stateless request/response
  protection. Reject the current protected payload. A new request requires a
  fresh message ID and must follow application idempotency policy.
- A **retryable HTTP failure** means cryptographic acceptance did not complete;
  retry is still subject to application idempotency and the replay-store
  contract.

Foctet intentionally exposes no frame-local recovery class on stateful
endpoints. A malformed, unauthenticated, replayed, or out-of-state frame can
otherwise conceal a diverged peer state, so it is terminal.

## Core protocol

`CoreError::disposition()` is the executable classification.

| Errors | Disposition | Required action |
| --- | --- | --- |
| `FrameTooLarge`, `TlvTooLarge`, `OutboundBufferLimitExceeded`, `RekeyInProgress`, `HandshakeRateLimited` | Recoverable | Correct input, drain queued output, resume/cancel the prepared rekey, or wait before retrying. |
| All other `CoreError` variants, including parser/header errors, AEAD/HKDF/DH failures, replay errors, invalid control or session state, key/sequence exhaustion, I/O/EOF, and handshake authentication/timeout failures | Terminal | Discard the endpoint/session and establish a new authenticated session. |

Stateless helpers may return `CoreError` without retaining a session. Their
callers still must not use a failed result as authenticated input.

## HTTP and framework adapters

`HttpError::disposition()` is the executable classification. `AxumError` and
`WorkersError` forward the HTTP classification and classify runtime/body-read
errors as request rejection.

| Errors | Disposition | Required action |
| --- | --- | --- |
| `HttpError::ReplayStore` | Retryable | Retry only using a new protected request when application idempotency permits. |
| Every other `HttpError`; `AxumError::BodyRead`; `WorkersError::Worker` | Reject | Reject the protected request/response. Do not retry its payload in place. |

Do not return detailed cryptographic or replay errors to an untrusted HTTP
peer. Use the adapter's documented generic status mapping and log only
secret-free diagnostics.

## Transport channels

`TransportChannelError`, `MessageChannelError`, `DatagramChannelError`, and
feature-gated `QuinnDatagramError` expose `disposition()`. Underlying transport
errors, including `QuinnDatagramTransportError`, are terminal because delivery
and peer state cannot be proven after an error.

| Errors | Disposition | Required action |
| --- | --- | --- |
| Wrapped recoverable `CoreError` | Recoverable | Correct input or relieve backpressure, then retry on the same live endpoint. |
| Wrapped terminal `CoreError` or any underlying transport/backend error | Terminal | Close/discard the endpoint and establish a fresh authenticated channel. |

For datagram endpoints, loss and reordering are normal only when represented by
missing or reordered datagrams. An error from `send_datagram` or
`recv_datagram` is not a loss signal and is terminal.

## Ambiguous output and rekey

After a partial write, write error, or flush error, `SyncIo` and
`FoctetFramed` (including `FoctetStream`) are terminal. Automatic-rekey control
output also terminates its paired `Session` on failure, zeroizing live traffic
keys. Native transport builders own the connection while handshaking and
discard both the connection and uncommitted session after a partial write,
write-zero, flush failure, peer close, timeout, or cancellation. They never
return a half-completed handshake connection for retry.

`SecureChannel::rekey_now`, `AsyncSecureChannel::rekey_now`, and the native
transport-channel `rekey_now` methods perform the same prepare/send/commit
transaction. `SecureDatagramChannel::send_rekey` and `recv_rekey` require a
`SecureMessageChannel` as their reliable encrypted control path. Any control
backend failure closes the control channel, datagram channel, and session.
If an async `rekey_now` future is cancelled while flush is pending, the channel
retains the exact prepared control and returns `RekeyInProgress` from ordinary
send/receive operations. Calling `rekey_now` again resumes that same
transaction; extracting the channel parts instead closes them.

WASM callers may use `cancelPreparedRekey()` only after proving that the
transport accepted no bytes. After a partial write, failed flush, or otherwise
ambiguous result they must call `terminate()` and discard the transport.

Delivery-sensitive applications must use authenticated message IDs and
idempotent application operations; Foctet cannot determine whether an
ambiguously failed encrypted send or handshake control reached the peer.
