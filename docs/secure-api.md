# Session authentication

Authenticated session constructors accept `ProductionSessionAuth`. It can only be constructed
with one of these authentication roots:

- a local Ed25519 identity plus a pinned peer identity; or
- a non-empty `ChannelBinding` derived from an authenticated outer channel.

`Session::new_production_initiator`,
`Session::new_production_responder`, and the
`establish_production_*` Tokio/Futures builders require this type.
`SessionAuthConfig::unauthenticated_for_testing` cannot be converted into it.

Unauthenticated transport convenience functions are compiled only with the
`foctet-transport/dangerous-unauthenticated` feature. Stateless full-request
HTTP helpers are compiled only with
`foctet-http/dangerous-stateless-http`. Neither feature is enabled by default.
Raw body-envelope helpers remain available under explicit body-oriented names
because their replayable building-block semantics are part of their contract.

Tokio and Futures handshake builders propagate random-source errors. Code that
constructs sessions directly can use `Session::try_new_initiator_with_auth`
and `Session::try_new_responder_with_auth` with
`ProductionSessionAuth::into_session_auth()`. Use `IdentityKeyPair::try_generate`
for fallible identity generation. The infallible Rust constructors panic if
the platform cannot supply secure randomness.

## Nonce-domain ownership

`TrafficKeys` directional key fields are private and the type cannot be built
from raw key bytes. Byte-stream, message, and datagram channels each claim their shape once
from an active `Session`; a second endpoint of the same shape fails with
`CoreError::EndpointAlreadyClaimed`. This prevents two endpoints from starting
the same sequence at zero. Each shape has its own frame profile and nonce domain.

For the low-level byte-stream constructors, `SyncIo::new` and
`FoctetFramed::new` return a terminal endpoint if another stream already
claimed the session's keys or the directions conflict with the session role. Prefer the session-backed channel constructors
for an immediate construction error. Dropping a channel does not release
its claim. Independently derived raw keys require caller-managed ownership.

Live message, datagram, framed, and stream endpoints do not implement `Clone`.
Sharing a channel requires synchronizing access to the same endpoint (for example,
with a mutex), not copying its sequence counters or replay windows. To create an
independent channel, establish a fresh authenticated session with fresh keys.

The advanced
`dangerously_from_shared_keys_without_nonce_ownership` constructors exist for
vector generation and integrations with an externally proven nonce-ownership
scheme. Their caller must guarantee exclusive ownership of every outbound nonce
domain and preserve sequence state for the lifetime of the traffic key.
