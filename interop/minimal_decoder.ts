#!/usr/bin/env node

// Minimal non-Rust Foctet frame decoder reference (Draft v0).
// This script parses the fixed-width plaintext header and ciphertext length.

const FRAME_HEADER_LEN = 22;

type DecodedFrame = {
  header: {
    magic_hex: string;
    version: number;
    flags: number;
    profile_id: number;
    key_id: number;
    stream_id: number;
    seq: string;
    ct_len: number;
  };
  ciphertext_hex: string;
};

function parseHex(input: string): Buffer {
  const clean = input.trim().toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("input must be an even-length hex string");
  }
  return Buffer.from(clean, "hex");
}

function decodeFrame(buf: Buffer): DecodedFrame {
  if (buf.length < FRAME_HEADER_LEN) {
    throw new Error(`buffer too short: ${buf.length}`);
  }

  const magic = [buf[0], buf[1]];
  const version = buf[2];
  const flags = buf[3];
  const profileId = buf[4];
  const keyId = buf[5];
  const streamId = buf.readUInt32BE(6);
  const seq = buf.readBigUInt64BE(10);
  const ctLen = buf.readUInt32BE(18);

  const ciphertext = buf.subarray(FRAME_HEADER_LEN);
  if (ciphertext.length !== ctLen) {
    throw new Error(
      `ciphertext length mismatch: expected ${ctLen}, got ${ciphertext.length}`,
    );
  }

  return {
    header: {
      magic_hex: Buffer.from(magic).toString("hex"),
      version,
      flags,
      profile_id: profileId,
      key_id: keyId,
      stream_id: streamId,
      seq: seq.toString(),
      ct_len: ctLen,
    },
    ciphertext_hex: ciphertext.toString("hex"),
  };
}

function main(): void {
  const input = process.argv[2];
  if (!input) {
    console.error("Usage: node interop/minimal_decoder.ts <frame_hex>");
    process.exit(2);
  }

  try {
    const decoded = decodeFrame(parseHex(input));
    console.log(JSON.stringify(decoded, null, 2));
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`decode error: ${message}`);
    process.exit(1);
  }
}

main();
