# Fuzzing

This directory contains `cargo-fuzz` targets for hardening every parser and
AEAD-open path that consumes attacker-controlled bytes.

## Prerequisites

Install `cargo-fuzz` once (requires a nightly toolchain):

```bash
cargo install cargo-fuzz --locked
```

## Targets

- `frame_parser`: `foctet_core::Frame::from_bytes` (stream frame header/wire)
- `archive_parser`: single- and split-archive decryption entry points
- `control_message`: control-plane (`ControlMessage`) decoder
- `handshake`: handshake/rekey state machine — any decodable control message is
  fed to a fresh responder and initiator
- `body_envelope`: one-shot body-envelope parse + key-unwrap + AEAD open
- `stream_body`: streaming-body header parser + incremental `StreamFrameDecoder`
- `datagram_message`: datagram and message frame open paths (header + AEAD +
  replay handling)

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

The working corpus (`corpus/`, git-ignored) grows locally

## Run locally

```bash
# From the workspace root; copy seeds into the working corpus first.
mkdir -p fuzz/corpus/frame_parser
cp fuzz/seeds/frame_parser/* fuzz/corpus/frame_parser/
cargo +nightly fuzz run frame_parser -- -max_total_time=300
```
