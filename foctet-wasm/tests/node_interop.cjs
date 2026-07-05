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

check("HTTP request protected context roundtrip and mismatch", () => {
  const kp = new wasm.KeyPair();
  const now = 1_700_000_000n;
  const carrier = wasm.HttpContextCarrier.generate(now, 300n);
  carrier.setIdempotencyKey("idem-node");

  const ctx = new wasm.HttpRequestContext(
    "POST",
    "https://api.example.test/pay?currency=USD",
    carrier,
  );
  ctx.setHeader("x-tenant-id", "tenant-a");
  ctx.bindHeader("x-tenant-id");

  const plaintext = enc.encode("charge over protected HTTP context");
  const envelope = ctx.sealBody(plaintext, kp.publicKey, enc.encode("http-kid"));
  const opened = ctx.openBody(envelope, kp.secretKey, now, 30n);
  assert.strictEqual(dec.decode(opened), "charge over protected HTTP context");
  assert.strictEqual(carrier.messageIdHeaderValue.length, 32);
  assert.strictEqual(carrier.timestampHeaderValue, now.toString());
  assert.strictEqual(carrier.expiryHeaderValue, (now + 300n).toString());

  const parsed = wasm.HttpContextCarrier.fromHeaderValues(
    carrier.messageIdHeaderValue,
    carrier.timestampHeaderValue,
    carrier.expiryHeaderValue,
    carrier.idempotencyKey,
    undefined,
  );
  assert.deepStrictEqual(Array.from(parsed.messageId), Array.from(carrier.messageId));
  assert.strictEqual(parsed.timestampSecs, carrier.timestampSecs);
  assert.strictEqual(parsed.expirySecs, carrier.expirySecs);

  const wrongRoute = new wasm.HttpRequestContext(
    "POST",
    "https://api.example.test/refund?currency=USD",
    carrier,
  );
  wrongRoute.setHeader("x-tenant-id", "tenant-a");
  wrongRoute.bindHeader("x-tenant-id");
  assert.throws(() => wrongRoute.openBody(envelope, kp.secretKey, now, 30n));
});

check("HTTP response protected context answers a request id", () => {
  const kp = new wasm.KeyPair();
  const now = 1_700_000_500n;
  const requestCarrier = wasm.HttpContextCarrier.generate(now, 300n);
  const responseCarrier = wasm.HttpContextCarrier.generate(now, 300n);
  responseCarrier.setRequestMessageId(requestCarrier.messageId);

  const ctx = new wasm.HttpResponseContext(201, responseCarrier);
  const envelope = ctx.sealBody(enc.encode("created"), kp.publicKey, enc.encode("http-kid"));
  const opened = ctx.openBody(envelope, kp.secretKey, now, 30n);
  assert.strictEqual(dec.decode(opened), "created");
  assert.strictEqual(responseCarrier.requestMessageIdHeaderValue, requestCarrier.messageIdHeaderValue);

  const wrongStatus = new wasm.HttpResponseContext(200, responseCarrier);
  assert.throws(() => wrongStatus.openBody(envelope, kp.secretKey, now, 30n));
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
