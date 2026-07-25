# Secure Production API

Production handshakes use `ProductionSessionAuth`. It can only be constructed
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

## Nonce-domain ownership

`TrafficKeys` directional key fields are private and the type cannot be built
from raw key bytes. Message and datagram channels claim a single-use endpoint
lease from an active `Session`; a second endpoint of the same shape fails with
`CoreError::EndpointAlreadyClaimed`. This prevents two endpoints from starting
the same `(direction, key_id, stream_id)` sequence at zero.

The advanced
`dangerously_from_shared_keys_without_nonce_ownership` constructors exist for
vector generation and integrations with an externally proven nonce-ownership
scheme. Their caller must guarantee exclusive ownership of every outbound nonce
domain and preserve sequence state for the lifetime of the traffic key.

Compile-fail rustdoc tests verify that raw traffic-key literals are inaccessible
and that an unauthenticated test configuration cannot satisfy a production
constructor.
