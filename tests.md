# Foctet — Real-Environment Test Runbook

A **step-by-step** guide for testing Foctet against real runtimes, real sockets,
and real deployment targets — the things the in-process `cargo test` suite cannot
cover. Follow the sections in order; each step has the exact commands, the
expected output, and what it proves.

- Companion docs: `TODO.md` (feature roadmap), `SECURITY.md` (posture), `README.md`.
- **Legend:** `[x]` verified on this machine while writing the runbook ·
  `[ ]` needs your environment (second host / cloud / service) · `[~]` partially
  verified.
- **"Two hosts"** below can be two terminals on one machine (real sockets, real
  TLS — only NAT/MTU differ) **or** two real machines: every command takes an
  `--addr`, so swap `127.0.0.1` for the server's LAN/Tailscale IP to go
  cross-host. Keep the TLS server name `localhost` (the dev cert's SAN) unless
  you regenerate the cert.

---

## 0. TL;DR — the fastest full pass

```bash
# from the repo root
cargo test --workspace --all-features --locked         # 1. in-process suite (175 tests)
cd devcert && ./generate.sh && cd ..                   # 2. dev TLS cert
# 3. transports (each: server in terminal A, client in terminal B) — see §3
# 4. HTTP echo + replay — see §4
# 5. WASM in a real browser — see §6
cargo +nightly fuzz run control_message -- -max_total_time=60   # 6. fuzz smoke — see §8
```

---

## 1. What is already automated (don't re-test by hand)

CI (`.github/workflows/rust.yml`) + local already cover:

- `cargo test --workspace --all-features --locked` — **175 tests**: the
  cross-shape conformance suite (`foctet-transport/tests/conformance.rs`),
  in-memory transport roundtrips, protocol negative tests, vectors, the raw-UDP
  real-socket tests (`udp::tests::*`, incl. anti-amplification).
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
  `cargo fmt --all -- --check`, MSRV 1.88 check, `cargo deny check`, RustSec audit.
- Three `wasm32-unknown-unknown` **build** checks (compile only, not runtime).
- `node foctet-wasm/tests/node_interop.cjs` — WASM SDK runtime in Node.

The gap this runbook closes: **compile checks and one-process loopbacks are not
real runtimes/networks.** Everything below runs real processes, sockets, and engines.

---

## 2. One-time setup

```bash
# Toolchains
rustup target add wasm32-unknown-unknown
rustup toolchain install nightly      # for cargo-fuzz
cargo install cargo-fuzz              # fuzzing
cargo install wasm-pack              # WASM SDK builds
# Node 20+ and npm are needed for the WASM and Workers harnesses.

# Dev TLS certificate for the QUIC / WebSocket / muxtls / WebTransport examples.
# Produces devcert/localhost.crt and devcert/localhost.key (SANs: localhost,
# 127.0.0.1, ::1). Valid 10 days — re-run to refresh.
cd devcert && ./generate.sh && cd ..      # generate.ps1 on Windows
```

For cross-host runs, copy `devcert/localhost.crt` to the client host (the client
trusts it) and copy both files to the server host. The client validates SNI
`localhost`, which the cert covers regardless of the IP you dial — so no cert
regeneration is needed just to change hosts.

---

## 3. Transport adapters (TODO §3)

Each transport example now has a `--role`:

- `--role loopback` (default) — both peers in one process, ephemeral port. Quick
  smoke test; this is what `cargo run -p foctet-transport --example <x>` does
  with no args.
- `--role server` — bind `--addr`, serve until Ctrl+C.
- `--role client` — connect to `--addr`.

The examples open `STREAM_COUNT = 2` Foctet streams, run the authenticated
handshake per stream, assert `peer_authenticated()`, and echo each payload back.
Client and server derive their pinned identities from fixed seeds, so the two
processes agree without any key exchange step.

### 3.1 QUIC streams (`quinn`) — VERIFIED two-process

Build once:
```bash
cargo build -p foctet-transport --example quinn_split --features "transport-quinn runtime-tokio"
BIN=target/debug/examples/quinn_split
```

**Terminal A (server):**
```bash
$BIN --role server --addr 127.0.0.1:4433 \
  --tls-cert devcert/localhost.crt --tls-key devcert/localhost.key
```
Expected:
```
quinn server listening on 127.0.0.1:4433 (Ctrl+C to stop)
```

**Terminal B (client):**
```bash
$BIN --role client --addr 127.0.0.1:4433 --tls-cert devcert/localhost.crt
```
Expected (exit 0):
```
quinn client connecting to 127.0.0.1:4433
client stream 0 got: quinn stream 0 reply to: hello from quinn stream 0
client stream 1 got: quinn stream 1 reply to: hello from quinn stream 1
quinn client finished
```
Server prints `accepted connection from …` / `served …`. **Proves:** real QUIC
handshake, Foctet authenticated handshake, `peer_authenticated()` true,
bidirectional encrypted streams across two processes.

- [x] **Negative test — wrong pinned identity is rejected:**
  ```bash
  $BIN --role client --addr 127.0.0.1:4433 --tls-cert devcert/localhost.crt --wrong-identity
  ```
  Client exits **non-zero** with a `ConnectionLost` error; the server logs
  `error serving …: peer identity mismatch`. Proves identity pinning fails closed.
- [ ] **Cross-host:** run the server on host A bound to `0.0.0.0:4433`; on host B
  run the client with `--addr <hostA-ip>:4433` (cert copied over). Same output.
- [ ] **Network impairment:** between the two, apply loss/latency
  (`tc qdisc add dev <if> root netem loss 5% delay 50ms` on Linux, or `dnctl`
  /`pfctl` on macOS) and confirm QUIC recovers and frames still authenticate.
- [x] **Long-lived / rekey:** see §7 (turn-key via `--messages` / `--rekey-frames`).

### 3.2 WebSocket (`websock-mux`, `wss://`) — VERIFIED two-process

```bash
cargo build -p foctet-transport --example websock_split --features "transport-websock-mux runtime-tokio"
BIN=target/debug/examples/websock_split
```
**Terminal A:**
```bash
$BIN --role server --addr 127.0.0.1:4443 \
  --tls-cert devcert/localhost.crt --tls-key devcert/localhost.key
# -> websock server listening on wss://127.0.0.1:4443 (Ctrl+C to stop)
```
**Terminal B:**
```bash
$BIN --role client --addr 127.0.0.1:4443 --tls-cert devcert/localhost.crt
```
Expected:
```
client stream 0 got: websock-mux stream 0 reply to: hello from websock stream 0
client stream 1 got: websock-mux stream 1 reply to: hello from websock stream 1
websock client finished
```
- [x] **Negative test:** add `--wrong-identity` → client errors, server logs
  `error serving session: peer identity mismatch`.
- [ ] Cross-host: as in §3.1 (the client dials `wss://<addr>`; keep the cert's
  `127.0.0.1`/`localhost` SAN in mind — for a hostname/IP not in the SAN,
  regenerate the cert with that SAN in `devcert/openssl.conf`).

### 3.3 Browser WebSocket (Rust/wasm, no JS glue) — needs a runner

`WebsockMessageTransport` is generic over `websock::WebSocketConnection` and
compiles for `wasm32` under `transport-websock` (browser `websock-wasm` backend).
CI build-checks it; a real browser run is covered below.
- [x] Build check: `cargo check -p foctet-transport --no-default-features --features transport-websock --target wasm32-unknown-unknown`.
- [x] **Real browser run** — the browser drives the WASM `FoctetSession` as the
  handshake *initiator* over a real `WebSocket` against the native
  `websock_message_server` responder (raw-message shape, the counterpart the
  browser SDK produces). Both speak one Foctet frame per binary WS message.

  Terminal A — native responder:
  ```bash
  cargo run -p foctet-transport --example websock_message_server \
    --features "runtime-tokio transport-websock" -- --role server --addr 127.0.0.1:4460
  ```
  Terminal B — serve the wasm page (rebuilds `pkg-web`):
  ```bash
  cd foctet-wasm && npm run browser   # serves http://localhost:8011/...
  ```
  Open `http://localhost:8011/examples/browser/websocket.html`. Expected on the
  page: **3 passed, 0 failed** (WebSocket connect + authenticated handshake, then
  two messages echoed). The server logs `handshake complete; peer authenticated`
  and `echoed … byte(s)`. *(Verified in a real browser: authenticated
  browser-initiator ↔ native-responder handshake + sealed message echo.)*

  A native `--role client` / `--role loopback` drives the same wire format
  without a browser (`… --role loopback`), useful for a quick smoke test.

### 3.4 muxtls — loopback smoke only

The muxtls example pre-establishes its Foctet sessions in-process (mutual TLS is
the peer authenticator), so it ships as a one-process smoke test:
- [x] `cargo run -p foctet-transport --example muxtls_split --features "transport-muxtls runtime-tokio"`
  → prints `muxtls multi-stream foctet E2EE example finished` (exit 0).
- [ ] A two-process muxtls example (running the Foctet handshake over the muxtls
  stream) is future work — see the note in `foctet-transport/examples/README.md`.

### 3.5 WebTransport (`webtrans`) — loopback smoke + browser is the real target

- [x] Loopback: `cargo run -p foctet-transport --example webtrans_split --features "transport-webtrans runtime-tokio"`.
- [x] **Browser client against a native server** — `webtrans_datagram_split`
  (`--role server`) is the native responder; the WASM `FoctetSession`
  (datagram mode) is the browser initiator. The authenticated handshake runs
  over a reliable bidi stream (the byte-framed Foctet handshake), then the sealed
  application data flows as WebTransport **datagrams** (one Foctet datagram frame
  each — the shape `sealDatagram`/`openDatagram` produce).

  First refresh the dev cert (ECDSA P-256, ≤14-day validity — required for
  `serverCertificateHashes`): `cd devcert && ./generate.sh && cd ..`.

  Terminal A — native responder with the dev cert:
  ```bash
  cargo run -p foctet-transport --example webtrans_datagram_split \
    --features "runtime-tokio transport-webtrans" -- --role server \
    --addr 127.0.0.1:4470 --tls-cert devcert/localhost.crt --tls-key devcert/localhost.key
  ```
  Terminal B — serve the wasm page (rebuilds `pkg-web`):
  ```bash
  cd foctet-wasm && npm run browser   # serves http://localhost:8011/...
  ```
  Open `http://localhost:8011/examples/browser/webtransport.html`, paste the
  contents of `devcert/localhost.hex` into the cert-hash field, and press **Run
  test**. Expected: **3 passed, 0 failed** (WebTransport connect + authenticated
  handshake over a stream, then two datagrams echoed). The server logs
  `handshake complete; peer authenticated` and `echoed … byte(s)`. *(Verified in
  a real browser: authenticated browser-initiator ↔ native-responder handshake
  over a WebTransport stream + sealed datagram echo.)*

  A native `--role client` / `--role loopback` drives the same wire format
  (handshake over a stream, data over datagrams) without a browser — a quick
  smoke test for the protocol. The streams-only `webtrans_split` remains the
  loopback smoke test for the stream path.

### 3.6 Raw UDP datagram + anti-amplification (TODO §3.5)

The raw-UDP adapter is covered by **real-socket** unit tests (local sockets, two
endpoints):
- [x] `cargo test -p foctet-transport --features runtime-tokio udp::` runs
  `roundtrip_over_real_udp_sockets` and `anti_amplification_caps_sends_until_validated`
  (a spoofable peer is capped at `factor × received` until `mark_peer_validated()`).
- [x] **Two-process driver** — `udp_datagram_split` runs the authenticated Foctet
  handshake over a reliable TCP control channel, then builds
  `SecureDatagramChannel::from_active_session` over a *connected*
  `UdpDatagramTransport` on each side and exchanges datagrams. The server enables
  `with_anti_amplification(3)`, so it refuses an unsolicited send until the first
  client datagram validates the address, then calls `mark_peer_validated()`.
  ```bash
  cargo build -p foctet-transport --example udp_datagram_split --features runtime-tokio
  BIN=target/debug/examples/udp_datagram_split
  ```
  **Terminal A (server):**
  ```bash
  $BIN --role server --control-addr 127.0.0.1:4455 --udp-addr 127.0.0.1:4456
  ```
  **Terminal B (client):**
  ```bash
  $BIN --role client --control-addr 127.0.0.1:4455 --datagrams 3
  ```
  Server logs (proves the amplifier is capped until validation):
  ```
  anti-amplification: refused to send before validation (WouldBlock) — ok
  received first client datagram — marked peer validated, cap lifted
  server echoed 3 datagram(s)
  ```
  Client prints each `client datagram N got: udp echo N reply to: ...` (exit 0).
- [ ] **Cross-host** UDP (real path/MTU/NAT): run the same two processes on two
  hosts — swap `--control-addr`/`--udp-addr` for the server's routable addresses.
  Confirm datagrams still authenticate through real NAT/MTU.

---

## 4. HTTP — axum (TODO §1.2, §4) — VERIFIED two-process

The axum examples use the production-recommended protected-context path
(`seal_request_with_context` / `open_request_with_context`).

```bash
cargo build -p foctet-http --examples --features axum
```
**Terminal A (server, binds 127.0.0.1:3000):**
```bash
target/debug/examples/axum_body_echo_server
# -> axum demo server listening on http://127.0.0.1:3000/foctet
```
**Terminal B (client):**
```bash
target/debug/examples/axum_body_echo_client
```
Expected:
```
status: 200 OK
answers our request id: true
plaintext body: HELLO AXUM
```
**Proves:** body sealed/opened over a real HTTP stack with the method/path/
message-id/timestamp bound into the AEAD; the response answers the request id.

- [x] **Negative test — replay rejected (HTTP 409):**
  ```bash
  target/debug/examples/axum_body_echo_client --replay
  ```
  Sends the **identical** sealed request twice. Expected tail:
  ```
  replay status: 409 Conflict
  replay correctly rejected with 409 Conflict
  ```
  (exits non-zero if the replay was *not* rejected). Proves the `ReplayStore`
  enforces single use over the wire.
- [x] **Route substitution / expiry:** both are turn-key negative tests.
  ```bash
  target/debug/examples/axum_body_echo_client --wrong-path   # sealed for /foctet, POSTed to /foctet-elsewhere
  target/debug/examples/axum_body_echo_client --expired      # sealed with an already-elapsed expiry
  ```
  Each expects (and asserts, exiting non-zero otherwise):
  ```
  wrong-path correctly rejected with 401 Unauthorized
  expired correctly rejected with 401 Unauthorized
  ```
  Proves the path (`OpenFailed` → 401) and the expiry (`ContextExpired` → 401)
  are bound into the AEAD / enforced. The server exposes a second route
  (`/foctet-elsewhere`) wired to the same handler purely so the path-mismatch
  reaches the opener rather than 404-ing at the router.
- [ ] **Streaming upload:** drive `foctet_http::axum::open_request_stream` with a
  chunked body; confirm per-chunk decryption and that a truncated body yields
  `StreamIncomplete` (HTTP 400). (Covered in-process by
  `foctet-http` tests; a real chunked-upload client is still to add.)

### 4.2 Durable replay store (Redis) — multi-instance

- [ ] Start Redis: `docker run --rm -p 6379:6379 redis`.
- [ ] Run **two** server instances on different ports, both pointed at the same
  Redis via `RedisReplayStore` (the in-tree example uses `InMemoryReplayStore`;
  swap it for `RedisReplayStore` behind the `redis` feature, or write a small
  variant). Send a request to instance A, then replay the captured bytes to
  instance B → still **409**. Proves replay defense is cross-instance.
  (`RedisReplayStore` is compile-checked today; this is its first live run.)

---

## 5. Cloudflare Workers (TODO §1.2, §4)

`foctet-http/examples/workers-echo` is a full `workers-rs` project using
`WorkersOpener` + `DurableObjectReplayStore`.

- [ ] **Local `wrangler dev`:**
  ```bash
  cd foctet-http/examples/workers-echo
  npm i -D wrangler@latest
  npx wrangler dev
  # second terminal, from the repo root:
  cargo run -p foctet-http --example workers_echo_client
  ```
  Confirm a body roundtrip; re-send the same request and confirm **409** (the
  Durable Object enforces single use).
- [ ] **Deployed** (`npx wrangler deploy`): repeat against the edge; then verify
  the DO **alarm** expires the replay entry at TTL (replay accepted only after
  expiry, rejected before).
- [ ] Key rotation + failure handling; write the operational guide (TODO §4).

---

## 6. WASM / TypeScript SDK in a browser (TODO §5)

### 6.1 Node — VERIFIED (keep in CI)
- [x] `npm --prefix foctet-wasm test` — body envelope + Rust→JS interop in Node.

### 6.2 Real browser — VERIFIED
- [x] Serve the harness (dependency-free Node static server; no Python, no
  editor config):
  ```bash
  cd foctet-wasm
  ./examples/browser/serve.sh        # Unix/macOS  (serve.ps1 on Windows; npm run browser also works)
  # open http://localhost:8011/examples/browser/index.html
  ```
  Expected on the page: **5 passed, 0 failed** — `version()`, body-envelope
  roundtrip, context binding (match opens / mismatch fails), Rust→JS wire
  compatibility (`tests/interop_vector.json`), and a full in-page
  `FoctetSession` handshake + `sealMessage`/`openMessage` roundtrip. The result
  is also at `window.__FOCTET_RESULT__ = { passed, failed }`.
  *(This is what surfaced the `Instant::now()` wasm bug — see §10.)*

### 6.3 Headless CI + publish
- [x] Headless browser tests in CI. `foctet-wasm/tests/browser.rs` runs 4
  `wasm-bindgen-test` tests in a real headless Chrome: body-envelope
  roundtrip, context binding, full authenticated `FoctetSession` handshake +
  messages + replay rejection, and a datagram-mode roundtrip. Locally:
  ```bash
  wasm-pack test --headless --chrome foctet-wasm
  ```
  **Gotcha:** wasm-pack auto-downloads the *latest* chromedriver, which can be
  one major version ahead of your installed Chrome and fails with
  `Error: http status: 404`. Fix: download the matching driver from
  [Chrome for Testing](https://googlechromelabs.github.io/chrome-for-testing/)
  and set `CHROMEDRIVER=/path/to/chromedriver`. — *verified: 4/4 pass in
  headless Chrome 149.* In CI the `wasm-browser-test` job uses the runner's
  version-matched preinstalled Chrome + chromedriver.
- [ ] `npm publish` the SDK; replace `interop/minimal_decoder.ts` with it.

---

## 7. Rekey / DH ratchet over a live session (TODO §2.3)

In-process tests + `test-vectors/rekey-v0.json` cover the key schedule. Over a
live connection:
- [x] Cross several rekeys over a live session. `quinn_split` takes
  `--rekey-frames <N>` (overrides `RekeyThresholds::max_frames`) and
  `--messages <M>` (request/reply round-trips per stream), and installs a
  `SessionObserver` that prints each rekey so the rotation is *observable*, not
  merely inferred from delivery:
  ```bash
  cargo build -p foctet-transport --example quinn_split --features "transport-quinn runtime-tokio"
  target/debug/examples/quinn_split --role loopback --messages 6 --rekey-frames 2
  ```
  Expected: every message round-trips (exit 0) and the log shows the *alternating*
  ratchet — each side initiates in turn and the peer applies the matching id:
  ```
  [client stream 0] rekey initiated 0->1
  [server stream 0] rekey applied   0->1
  [server stream 0] rekey initiated 1->2
  [client stream 0] rekey applied   1->2
  ...
  ```
  The same flags work two-process (`--role server` / `--role client`, §3.1).
- [ ] Confirm an old-key frame delivered reordered across a rekey still decrypts
  (retained previous keys).
- [ ] One-directional traffic surfaces the documented alternation stall — rekey
  from both ends periodically.
- [ ] **External cryptographic review** before claiming PCS (TODO §2.3 gate).

---

## 8. Fuzzing with a real budget (TODO §6)

Five targets exist (`fuzz/fuzz_targets/`); `cargo-fuzz` + nightly are installed.
- [x] Smoke (60s each, no crash expected):
  ```bash
  cargo +nightly fuzz run control_message  -- -max_total_time=60
  cargo +nightly fuzz run handshake        -- -max_total_time=60
  cargo +nightly fuzz run body_envelope    -- -max_total_time=60
  cargo +nightly fuzz run stream_body      -- -max_total_time=60
  cargo +nightly fuzz run datagram_message -- -max_total_time=60
  ```
- [x] Seeded corpus + fuzz-in-CI. Committed seeds under `fuzz/seeds/<target>/`
  (valid frames/envelopes/archives/control messages generated by
  `cargo run -p foctet --example gen_fuzz_seeds`, sealed with the targets'
  fixed keys). `.github/workflows/fuzz.yml` runs all seven targets weekly and
  on `workflow_dispatch` (default 300 s/target, budget overridable) and
  uploads crash artifacts.
- [ ] One-off deep run (≥30 min/target) on a beefy machine:
  ```bash
  cp fuzz/seeds/<target>/* fuzz/corpus/<target>/
  cargo +nightly fuzz run <target> -- -max_total_time=1800
  ```

---

## 9. Cross-implementation interop (TODO §6/§7)

- [ ] Decode Foctet envelopes/frames with an **independent** decoder (not the Rust
  workspace) — extend `interop/` beyond the header-only `minimal_decoder.ts`, or
  consume the published WASM SDK from a separate project.
- [ ] Have that implementation verify the canonical `test-vectors/` suite.

---

## 10. Bug found while writing this runbook (why real-env testing matters)

Running the WASM `FoctetSession` handshake in Node/browser (not just the native
test) immediately aborted with `RuntimeError: unreachable` inside
`Instant::now()`: `wasm32-unknown-unknown` has no monotonic clock, so the
age-based rekey timestamp panicked at session creation — a runtime-only failure
the green native suite never hit.

**Fix:** `foctet-core/src/session.rs` now uses an internal `MonoInstant`
(native = `std::time::Instant`; `wasm32` = age-threshold disabled, frame/byte
thresholds still apply). Documented in `SECURITY.md`, recorded in `CHANGELOG.md`,
re-verified in §6.2. **Lesson:** green-in-workspace ≠ works-in-the-field — every
step here that finds something gets a fix + a doc/CHANGELOG note + a harness check.

---

## 11. Sign-off checklist (maps to TODO §8 release gates)

"Production-ready" / "v1" wording is allowed only when these are all `[x]`:

- [x] QUIC and WebSocket adapters pass a real two-process run incl. the
      identity-mismatch negative test (§3.1, §3.2). — *verified on one host;
      cross-host pending.*
- [~] WebTransport: browser-initiator ↔ native-responder handshake + datagram
      echo verified in a real browser (§3.5, `webtrans_datagram_split`); muxtls
      two-process run (§3.4) still pending.
- [~] Raw-UDP two-process datagram driver + anti-amplification verified locally
      (§3.6, `udp_datagram_split`); cross-host against a spoofed source pending.
- [x] axum protected-context roundtrip + replay-rejection (409) over real HTTP (§4).
- [ ] axum + Redis multi-instance replay defense (§4.2).
- [ ] Workers under `wrangler dev` **and** deployed, incl. DO TTL expiry (§5).
- [x] WASM SDK verified in a real browser (§6.2) **and** under headless Chrome
      in CI (§6.3); npm publish pending.
- [~] DH ratchet over a live long-lived session verified with observable rekeys
      (§7, `quinn_split --rekey-frames`); independent crypto review still pending.
- [x] Fuzzing seeded + wired into CI (§8); one-off deep run (≥30 min/target)
      still worth doing before v1.
- [ ] Cross-implementation interop + independent vector verification (§9).
- [ ] Operational guides (Workers, deployment, key management, incident response).
