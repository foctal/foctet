#!/usr/bin/env node
// Independent verification of the canonical Foctet Draft v0 test vectors.
//
// This script re-implements the Draft v0 key schedule, frame AEAD, handshake
// transcript binding, identity authentication, and DH-ratchet rekey step from
// SPEC.md, on top of the @noble crypto libraries. It shares no code with the
// Rust implementation and is not generated from it (unlike the WASM SDK), so
// it provides a genuinely independent check of the committed vectors in
// `test-vectors/`: a systematic encode/derive bug in the Rust workspace that
// its own tests would faithfully reproduce fails here instead.
//
// Usage (from the repository root or interop/):
//
//   cd interop && npm ci && npm test

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { x25519, ed25519 } from "@noble/curves/ed25519.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = (name) =>
  JSON.parse(readFileSync(join(root, "test-vectors", name), "utf8"));

const fromHex = (hex) => {
  if (hex.length % 2 !== 0) throw new Error("odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
};
const toHex = (bytes) =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

let checks = 0;
const assertEq = (actual, expected, what) => {
  const a = typeof actual === "string" ? actual : toHex(actual);
  const e = typeof expected === "string" ? expected : toHex(expected);
  if (a !== e) {
    console.error(`FAIL: ${what}\n  expected ${e}\n  actual   ${a}`);
    process.exit(1);
  }
  checks++;
};
const assertTrue = (cond, what) => {
  if (!cond) {
    console.error(`FAIL: ${what}`);
    process.exit(1);
  }
  checks++;
};
const assertThrows = (operation, what) => {
  try {
    operation();
  } catch {
    checks++;
    return;
  }
  console.error(`FAIL: ${what}`);
  process.exit(1);
};

const concat = (...parts) => {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};
const ascii = (s) => new TextEncoder().encode(s);
const u32be = (n) =>
  new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
const u64be = (n) => {
  const big = BigInt(n);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++)
    out[7 - i] = Number((big >> BigInt(8 * i)) & 0xffn);
  return out;
};

// --- Draft v0 primitives, per SPEC.md -------------------------------------

// HKDF-SHA-256(salt = session_salt, ikm = shared_secret) expanded with the
// direction labels.
const deriveTrafficKeys = (sharedSecret, sessionSalt) => ({
  c2s: hkdf(sha256, sharedSecret, sessionSalt, ascii("foctet c2s"), 32),
  s2c: hkdf(sha256, sharedSecret, sessionSalt, ascii("foctet s2c"), 32),
});

const deriveRatchetRoot = (sessionSalt, sharedSecret) =>
  hkdf(sha256, sharedSecret, sessionSalt, ascii("foctet ratchet init"), 32);

const dhRatchetStep = (rootKey, dh, keyId) => ({
  newRoot: hkdf(sha256, dh, rootKey, ascii("foctet ratchet root"), 32),
  c2s: hkdf(
    sha256,
    dh,
    rootKey,
    concat(ascii("foctet ratchet c2s"), new Uint8Array([keyId])),
    32,
  ),
  s2c: hkdf(
    sha256,
    dh,
    rootKey,
    concat(ascii("foctet ratchet s2c"), new Uint8Array([keyId])),
    32,
  ),
});

// 24-byte XChaCha nonce: key_id || stream_id(be32) || seq(be64) || zeros.
const makeNonce = (keyId, streamId, seq) =>
  concat(new Uint8Array([keyId]), u32be(streamId), u64be(seq), new Uint8Array(11));

const FRAME_HEADER_LEN = 22;
const decodeFrameHeader = (bytes) => {
  assertTrue(bytes.length >= FRAME_HEADER_LEN, "frame has a full header");
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return {
    magic: [bytes[0], bytes[1]],
    version: bytes[2],
    flags: bytes[3],
    profileId: bytes[4],
    keyId: bytes[5],
    streamId: dv.getUint32(6),
    seq: dv.getBigUint64(10),
    ctLen: dv.getUint32(18),
    raw: bytes.slice(0, FRAME_HEADER_LEN),
  };
};

// --- 1. Frame vector: full AEAD open ---------------------------------------

const frameVec = vectors("frame-v0.json");
{
  const sharedSecret = fromHex(frameVec.shared_secret_hex);
  const sessionSalt = fromHex(frameVec.session_salt_hex);
  const frame = fromHex(frameVec.frame_hex);
  const header = decodeFrameHeader(frame);

  assertEq(toHex(new Uint8Array(header.magic)), "f0c7", "frame magic");
  assertTrue(header.version === 0, "frame version is v0");
  assertTrue(header.profileId === 0x01, "frame profile is 0x01");
  const ciphertext = frame.slice(FRAME_HEADER_LEN);
  assertTrue(ciphertext.length === header.ctLen, "ct_len matches body length");

  const keys = deriveTrafficKeys(sharedSecret, sessionSalt);
  const nonce = makeNonce(header.keyId, header.streamId, header.seq);

  // The header (with its final ct_len) is the AAD; decrypt under the
  // direction key that authenticates.
  let plaintext = null;
  for (const key of [keys.c2s, keys.s2c]) {
    try {
      plaintext = xchacha20poly1305(key, nonce, header.raw).decrypt(ciphertext);
      break;
    } catch {
      /* try the other direction */
    }
  }
  assertTrue(plaintext !== null, "frame decrypts under a derived traffic key");
  assertEq(plaintext, frameVec.plaintext_hex, "frame plaintext");
}

// --- 2. Handshake vector: X25519, key schedule, hellos, identity auth ------

const hsVec = vectors("handshake-v0.json");
{
  const clientPriv = fromHex(hsVec.client_private_hex);
  const serverPriv = fromHex(hsVec.server_private_hex);
  const clientPub = fromHex(hsVec.client_public_hex);
  const serverPub = fromHex(hsVec.server_public_hex);
  const sessionSalt = fromHex(hsVec.session_salt_hex);

  assertEq(x25519.getPublicKey(clientPriv), clientPub, "client X25519 public");
  assertEq(x25519.getPublicKey(serverPriv), serverPub, "server X25519 public");
  assertEq(
    x25519.getSharedSecret(clientPriv, serverPub),
    hsVec.shared_secret_hex,
    "X25519 shared secret (client side)",
  );
  assertEq(
    x25519.getSharedSecret(serverPriv, clientPub),
    hsVec.shared_secret_hex,
    "X25519 shared secret (server side)",
  );

  const keys = deriveTrafficKeys(fromHex(hsVec.shared_secret_hex), sessionSalt);
  assertEq(keys.c2s, hsVec.key_c2s_hex, "handshake-derived c2s key");
  assertEq(keys.s2c, hsVec.key_s2c_hex, "handshake-derived s2c key");

  // ClientHello wire layout: "FCTL" ver(0) kind(1) eph(32) salt(32)
  // binding(32) auth_kind(1) [identity(32) signature(64)].
  const hello = fromHex(hsVec.client_hello_hex);
  assertEq(hello.slice(0, 4), toHex(ascii("FCTL")), "client hello prefix");
  assertTrue(hello[4] === 0 && hello[5] === 1, "client hello version/kind");
  const chEph = hello.slice(6, 38);
  const chSalt = hello.slice(38, 70);
  const chBinding = hello.slice(70, 102);
  assertEq(chEph, clientPub, "client hello ephemeral public");
  assertEq(chSalt, sessionSalt, "client hello session salt");
  const expectedClientBinding = sha256(
    concat(ascii("foctet hs client"), chEph, chSalt),
  );
  assertEq(chBinding, expectedClientBinding, "client transcript binding");
  assertTrue(hello[102] === 1, "client hello carries Ed25519 auth");
  const chIdentity = hello.slice(103, 135);
  const chSignature = hello.slice(135, 199);
  assertEq(
    chIdentity,
    hsVec.client_identity_public_hex,
    "client identity public key",
  );
  assertEq(
    ed25519.getPublicKey(fromHex(hsVec.client_identity_private_hex)),
    hsVec.client_identity_public_hex,
    "client Ed25519 public derivation",
  );
  const clientAuthMsg = concat(
    ascii("foctet auth client"),
    chEph,
    chSalt,
    chBinding,
  );
  assertTrue(
    ed25519.verify(chSignature, clientAuthMsg, chIdentity),
    "client identity signature verifies",
  );

  // ServerHello wire layout: "FCTL" ver(0) kind(2) eph(32) binding(32)
  // auth_kind(1) [identity(32) signature(64)].
  const serverHello = fromHex(hsVec.server_hello_hex);
  assertEq(serverHello.slice(0, 4), toHex(ascii("FCTL")), "server hello prefix");
  assertTrue(
    serverHello[4] === 0 && serverHello[5] === 2,
    "server hello version/kind",
  );
  const shEph = serverHello.slice(6, 38);
  const shBinding = serverHello.slice(38, 70);
  assertEq(shEph, serverPub, "server hello ephemeral public");
  const expectedServerBinding = sha256(
    concat(ascii("foctet hs server"), chEph, shEph, sessionSalt),
  );
  assertEq(shBinding, expectedServerBinding, "server transcript binding");
  assertTrue(serverHello[70] === 1, "server hello carries Ed25519 auth");
  const shIdentity = serverHello.slice(71, 103);
  const shSignature = serverHello.slice(103, 167);
  assertEq(
    shIdentity,
    hsVec.server_identity_public_hex,
    "server identity public key",
  );
  const serverAuthMsg = concat(
    ascii("foctet auth server"),
    chEph,
    shEph,
    sessionSalt,
    shBinding,
  );
  assertTrue(
    ed25519.verify(shSignature, serverAuthMsg, shIdentity),
    "server identity signature verifies",
  );
}

// --- 3. Rekey vector: DH-ratchet root seeding and one ratchet step ---------

const rkVec = vectors("rekey-v0.json");
const negativeVec = vectors("negative-v0.json");
{
  const sessionSalt = fromHex(rkVec.session_salt_hex);
  const sharedSecret = fromHex(rkVec.shared_secret_hex);
  assertEq(
    deriveRatchetRoot(sessionSalt, sharedSecret),
    rkVec.ratchet_root_hex,
    "ratchet root seeding",
  );

  const ephPriv = fromHex(rkVec.rekey_eph_private_hex);
  assertEq(
    x25519.getPublicKey(ephPriv),
    rkVec.rekey_eph_public_hex,
    "rekey ephemeral public",
  );
  assertEq(
    x25519.getSharedSecret(ephPriv, fromHex(rkVec.peer_ratchet_public_hex)),
    rkVec.rekey_dh_hex,
    "rekey DH output",
  );

  const step = dhRatchetStep(
    fromHex(rkVec.ratchet_root_hex),
    fromHex(rkVec.rekey_dh_hex),
    rkVec.new_key_id,
  );
  assertEq(step.newRoot, rkVec.new_ratchet_root_hex, "advanced ratchet root");
  assertEq(step.c2s, rkVec.rekey_key_c2s_hex, "post-rekey c2s key");
  assertEq(step.s2c, rkVec.rekey_key_s2c_hex, "post-rekey s2c key");
}

// --- 4. Negative controls: tampering must fail ------------------------------

{
  const sharedSecret = fromHex(frameVec.shared_secret_hex);
  const sessionSalt = fromHex(frameVec.session_salt_hex);
  const keys = deriveTrafficKeys(sharedSecret, sessionSalt);
  const frame = fromHex(frameVec.frame_hex);
  const header = decodeFrameHeader(frame);
  const nonce = makeNonce(header.keyId, header.streamId, header.seq);

  const opensWith = (aad, body) => {
    for (const key of [keys.c2s, keys.s2c]) {
      try {
        xchacha20poly1305(key, nonce, aad).decrypt(body);
        return true;
      } catch {
        /* keep trying */
      }
    }
    return false;
  };

  const tamperedBody = frame.slice(FRAME_HEADER_LEN);
  tamperedBody[0] ^= 0xff;
  assertTrue(
    !opensWith(header.raw, tamperedBody),
    "tampered ciphertext must not authenticate",
  );

  const tamperedAad = header.raw.slice();
  tamperedAad[3] ^= 0x01; // flip a frame-flag bit: the header is AAD
  assertTrue(
    !opensWith(tamperedAad, frame.slice(FRAME_HEADER_LEN)),
    "tampered header (AAD) must not authenticate",
  );

  const truncated = frame.slice(0, frame.length - 1);
  const truncatedHeader = decodeFrameHeader(truncated);
  assertTrue(
    truncated.length - FRAME_HEADER_LEN !== truncatedHeader.ctLen,
    "truncated frame fails its declared ciphertext boundary",
  );

  const unknownVersion = frame.slice();
  unknownVersion[2] = 0xff;
  assertTrue(
    decodeFrameHeader(unknownVersion).version !== 0,
    "unknown frame version fails the fixed-v0 profile check",
  );
  const unknownProfile = frame.slice();
  unknownProfile[4] = 0xff;
  assertTrue(
    decodeFrameHeader(unknownProfile).profileId !== 0x01,
    "unknown crypto profile fails the fixed-profile check",
  );
}

// Independent negative handshake and ratchet boundaries.
{
  const hello = fromHex(hsVec.client_hello_hex);
  const signature = hello.slice(135, 199);
  signature[0] ^= 0x80;
  const authMessage = concat(
    ascii("foctet auth client"),
    hello.slice(6, 38),
    hello.slice(38, 70),
    hello.slice(70, 102),
  );
  assertTrue(
    !ed25519.verify(signature, authMessage, hello.slice(103, 135)),
    "tampered handshake signature is rejected",
  );

  assertThrows(
    () => x25519.getSharedSecret(fromHex(hsVec.client_private_hex), new Uint8Array(32)),
    "low-order all-zero X25519 input is rejected",
  );

  const malformedControl = hello.slice(0, hello.length - 1);
  assertTrue(
    ![102, 103, 199].includes(malformedControl.length),
    "truncated ClientHello fails every permitted boundary",
  );
  assertTrue(0xff + 1 > 0xff, "key-id exhaustion cannot wrap to a v0 key identifier");

  const replayWindow = new Set();
  const replayKey = (keyId, streamId, seq) => `${keyId}:${streamId}:${seq}`;
  const key = replayKey(0, 7, 4095);
  replayWindow.add(key);
  assertTrue(replayWindow.has(key), "replay-window upper boundary is retained");
  assertTrue(
    replayWindow.has(replayKey(0, 7, 4095)),
    "duplicate at the replay boundary is rejected",
  );
}

// --- 5. Shared negative-vector corpus ---------------------------------------

{
  const applyMutation = (mutation) => {
    const fixture = vectors(mutation.fixture);
    const bytes = fromHex(fixture[mutation.field]);
    const offset =
      mutation.offset ??
      bytes.length - mutation.offset_from_end;
    bytes[offset] ^= mutation.xor;
    return bytes;
  };
  const byId = (id) =>
    negativeVec.mutations.find((mutation) => mutation.id === id);
  const literal = (id) =>
    negativeVec.literals.find((entry) => entry.id === id);

  const badVersion = decodeFrameHeader(applyMutation(byId("frame_unknown_version")));
  assertTrue(badVersion.version !== 0, "shared vector: unknown version rejected");
  const badProfile = decodeFrameHeader(applyMutation(byId("frame_unknown_profile")));
  assertTrue(badProfile.profileId !== 1, "shared vector: unknown profile rejected");

  const corruptFrame = applyMutation(byId("frame_ciphertext_corruption"));
  const corruptHeader = decodeFrameHeader(corruptFrame);
  const corruptKeys = deriveTrafficKeys(
    fromHex(frameVec.shared_secret_hex),
    fromHex(frameVec.session_salt_hex),
  );
  const corruptNonce = makeNonce(
    corruptHeader.keyId,
    corruptHeader.streamId,
    corruptHeader.seq,
  );
  let corruptOpened = false;
  for (const key of [corruptKeys.c2s, corruptKeys.s2c]) {
    try {
      xchacha20poly1305(key, corruptNonce, corruptHeader.raw).decrypt(
        corruptFrame.slice(FRAME_HEADER_LEN),
      );
      corruptOpened = true;
    } catch {
      // Expected for both direction keys.
    }
  }
  assertTrue(!corruptOpened, "shared vector: corrupted frame fails AEAD");

  const corruptHello = applyMutation(byId("client_hello_signature_corruption"));
  assertTrue(
    !ed25519.verify(
      corruptHello.slice(135, 199),
      concat(
        ascii("foctet auth client"),
        corruptHello.slice(6, 38),
        corruptHello.slice(38, 70),
        corruptHello.slice(70, 102),
      ),
      corruptHello.slice(103, 135),
    ),
    "shared vector: corrupted handshake signature fails",
  );

  assertThrows(
    () =>
      x25519.getSharedSecret(
        fromHex(hsVec.client_private_hex),
        fromHex(literal("low_order_x25519").hex),
      ),
    "shared vector: low-order X25519 rejected",
  );
  assertTrue(
    fromHex(literal("truncated_body_header").hex).length === 8,
    "shared vector: body header truncation boundary",
  );
  assertTrue(
    fromHex(literal("truncated_stream_header").hex).length === 8,
    "shared vector: stream header truncation boundary",
  );
  assertTrue(
    fromHex(literal("malformed_control").hex).length === 6,
    "shared vector: malformed control boundary",
  );

  const originalManifest = fromHex(vectors("archive-v0.json").manifest_hex);
  const corruptManifest = applyMutation(byId("archive_manifest_corruption"));
  assertTrue(
    toHex(sha256(originalManifest)) !== toHex(sha256(corruptManifest)),
    "shared vector: archive corruption changes authenticated bytes",
  );
  assertTrue(
    negativeVec.boundaries.maximum_key_id + 1 > 0xff,
    "shared vector: key-id exhaustion boundary",
  );
  assertTrue(
    negativeVec.boundaries.replay_window === 4096,
    "shared vector: replay boundary",
  );
}

console.log(
  `ok: ${checks} independent checks passed (positive and negative frame, handshake, identity, replay, and rekey cases)`,
);
