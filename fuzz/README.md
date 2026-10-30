# Fuzzing

This directory contains `cargo-fuzz` targets for parsers and AEAD-open paths
that consume attacker-controlled bytes.

## Prerequisites

Install `cargo-fuzz` once (requires a nightly toolchain):

```bash
cargo install cargo-fuzz --locked
```

## Targets

- `storage_formats`: authenticated recovery-share parser and signed streaming files
- `frame_parser`: `foctet_core::Frame::from_bytes` (stream frame header/wire)
- `archive_parser`: single- and split-archive decryption entry points
- `control_message`: control-plane (`ControlMessage`) decoder
- `handshake`: handshake/rekey state machine — any decodable control message is
  fed to a fresh responder and initiator
- `body_envelope`: one-shot body-envelope parse + key-unwrap + AEAD open
- `stream_body`: streaming-body header parser + incremental `StreamFrameDecoder`
- `datagram_message`: datagram and message frame open paths (header + AEAD +
  replay handling)
- `rekey_transaction`: prepare/cancel/commit, ambiguous delivery, duplicate
  controls, and ratchet turn ordering
- `http_context`: protected request context, bound-header, and AAD encoding
- `workers_replay_adapter`: the hostile carrier-header boundary shared by the
  Workers adapter (Durable Object storage remains covered by Wrangler E2E)
- `archive_encoder`: deterministic single and split archive encoders across
  chunk and part boundaries

## Seeds

`seeds/<target>/` holds committed seed inputs — *valid* wire blobs (frames,
envelopes, archives, control messages) sealed with the same fixed keys the
targets hard-code, so the fuzzer starts from deep parser states. Regenerate
with:

```bash
cargo run -p foctet --example gen_fuzz_seeds
```

Sealing uses random ephemerals, so regenerated seeds differ byte-for-byte;
they only need to be valid, not reproducible.

The working corpus (`corpus/`, git-ignored) grows locally; retain it between runs.
`cargo fuzz` uses libFuzzer with AddressSanitizer on supported native targets.

Report security-sensitive crashes privately through [SECURITY.md](../SECURITY.md),
including the crashing input and reproduction command. After a fix, add a
regression case to the corpus.

## Run locally

```bash
# From the workspace root; copy seeds into the working corpus first.
mkdir -p fuzz/corpus/frame_parser
cp fuzz/seeds/frame_parser/* fuzz/corpus/frame_parser/
cargo +nightly fuzz run frame_parser -- -max_total_time=300
```

The `storage_formats` target also parses bounded canonical Worker TEXT records;
`signed-text-v1` is a public synthetic syntax seed, not an authenticated record.
Copy seeds to a temporary corpus directory before fuzzing to keep generated cases
out of the committed seed set.
