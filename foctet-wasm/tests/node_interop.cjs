// Node.js interop test for the Foctet WASM SDK.
//
// Build the package first:
//   wasm-pack build --target nodejs --out-dir pkg-node
// Then run:
//   node foctet-wasm/tests/node_interop.cjs
//
// Verifies:
//   1. JS seal -> JS open roundtrip (the WASM API works end to end in Node).
//   2. JS opens a Rust-produced envelope (Rust -> JS wire compatibility).
//   3. Context binding: matching context opens; wrong/absent context fails.

const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");

const wasm = require("../pkg-node/foctet_wasm.js");

const enc = new TextEncoder();
const dec = new TextDecoder();

function fromHex(hex) {
  return Uint8Array.from(Buffer.from(hex, "hex"));
}

let passed = 0;
function check(name, fn) {
  fn();
  passed += 1;
  console.log(`  ok - ${name}`);
}

console.log(`foctet-wasm version ${wasm.version()}`);

check("js seal -> js open roundtrip", () => {
  const kp = new wasm.KeyPair();
  const plaintext = enc.encode("hello from node");
  const envelope = wasm.sealBody(plaintext, kp.publicKey, enc.encode("node-kid"));
  const opened = wasm.openBody(envelope, kp.secretKey);
  assert.strictEqual(dec.decode(opened), "hello from node");
});

check("wrong recipient cannot open", () => {
  const kp = new wasm.KeyPair();
  const other = new wasm.KeyPair();
  const envelope = wasm.sealBody(enc.encode("secret"), kp.publicKey, enc.encode("kid"));
  assert.throws(() => wasm.openBody(envelope, other.secretKey));
});

check("context binding roundtrip and mismatch", () => {
  const kp = new wasm.KeyPair();
  const ctx = enc.encode("foctet-http-ctx-v1|POST|/pay");
  const plaintext = enc.encode("charge");
  const envelope = wasm.sealBodyWithContext(plaintext, kp.publicKey, enc.encode("kid"), ctx);

  const opened = wasm.openBodyWithContext(envelope, kp.secretKey, ctx);
  assert.strictEqual(dec.decode(opened), "charge");

  assert.throws(() => wasm.openBodyWithContext(envelope, kp.secretKey, enc.encode("other")));
  assert.throws(() => wasm.openBody(envelope, kp.secretKey));
});

check("fromSecretKey recovers the public key", () => {
  const kp = new wasm.KeyPair();
  const rebuilt = wasm.KeyPair.fromSecretKey(kp.secretKey);
  assert.deepStrictEqual(Array.from(rebuilt.publicKey), Array.from(kp.publicKey));
});

check("opens Rust-produced envelopes (Rust -> JS wire compat)", () => {
  const fixturePath = path.join(__dirname, "interop_vector.json");
  const v = JSON.parse(fs.readFileSync(fixturePath, "utf8"));
  const secret = fromHex(v.secret);

  const opened = wasm.openBody(fromHex(v.envelope), secret);
  assert.strictEqual(dec.decode(opened), v.plaintext);

  const openedCtx = wasm.openBodyWithContext(
    fromHex(v.context_envelope),
    secret,
    enc.encode(v.context),
  );
  assert.strictEqual(dec.decode(openedCtx), v.plaintext);
});

console.log(`\nAll ${passed} interop checks passed.`);
