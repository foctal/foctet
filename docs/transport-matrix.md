# Transport security matrix

All production sessions require pinned peer identity or an explicitly
authenticated outer-channel binding. Any terminal Foctet or backend error
closes the affected channel; retry requires a new authenticated session.

| Adapter | Shape | Delivery contract | Size bound | Control and close contract | Deployment duties |
| --- | --- | --- | --- | --- | --- |
| Tokio/futures byte stream | Reliable ordered bytes | Exact ordered stream | `FrameCodecConfig::max_frame_len` | Handshake and rekey share a reliable ordered channel; EOF, ambiguous write, parse, authentication, or sequence failure is terminal | Apply handshake timeout, rate, and concurrency admission limits |
| QUIC/WebTransport bidirectional stream | Reliable ordered bytes | Exact ordered stream per transport stream | Foctet frame limit plus the implementation's stream flow control | One authenticated handshake/control stream per session; reset, stop, or connection close is terminal | Authenticate the QUIC/TLS peer or use pinned Foctet identity |
| Raw or browser WebSocket message | Reliable ordered messages | One binary WebSocket message per Foctet message; text is rejected | `MessageConfig::max_message_size`, clamped when the backend reports a lower limit | Rekey uses the same reliable ordered message channel; close or ambiguous send is terminal | Bound any application queue; one Foctet session per raw WebSocket |
| Multiplexed WebSocket / muxtls | Reliable ordered bytes per mux stream | Independent ordered byte streams; mux owns fairness | Foctet frame limit and mux limits | Each mux stream carries one Foctet channel; session control must not use a lossy path | Configure bounded stream and connection queues |
| QUIC/WebTransport datagram | Unreliable unordered datagrams | Loss and reorder allowed; duplicates rejected by replay windows | `DatagramConfig::max_datagram_size`, clamped to live backend maximum | Handshake and every rekey require a separate reliable ordered encrypted control channel; connection failure or rekey divergence is terminal | Rely on transport address validation and anti-amplification; reduce the configured size after path-MTU reduction |
| Raw connected UDP | Unreliable unordered datagrams | Loss and reorder allowed; connected socket filters other source addresses | Default `DEFAULT_MAX_DATAGRAM_SIZE`, configurable downward | No control channel is provided; use a separate authenticated reliable ordered channel for handshake/rekey | `new` rejects unconnected sockets. Server/listener handoff must use `new_unvalidated_peer`, which enforces a 3x budget until explicit validation |

## Datagram rules

- A datagram contains exactly one Foctet datagram frame. Fragmentation and
  reassembly are outside the adapter and should be avoided.
- Oversized plaintext is rejected before encryption. A backend-reported smaller
  maximum clamps the Foctet configuration.
- Loss does not advance receiver state. Reordering within the replay window is
  accepted once; duplicates and packets outside the window are rejected.
- Rekey controls never travel on the datagram path. Sender commit, reliable
  control delivery, and key adoption form one fail-closed transaction.
- Applications must stop sending when path MTU shrinks until configuration is
  reduced or the transport reports a usable maximum.

## Server admission

Before expensive handshake work, apply both `HandshakeRateLimiter` and
`HandshakeConcurrencyLimiter`. Raw UDP listeners must validate a source address
before lifting amplification limits. A received datagram alone increases the
pre-validation response budget only by the configured factor; it does not
authenticate the peer.
