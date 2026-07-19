import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { chromium } from "playwright-core";

const browserDir = resolve(import.meta.dirname);
const repoDir = resolve(browserDir, "../../..");
const wasmDir = resolve(browserDir, "../..");
const children = [];

function start(command, args, cwd) {
  const child = spawn(command, args, { cwd, stdio: "inherit" });
  children.push(child);
  return child;
}

function run(command, args, cwd) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, { cwd, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited with ${code}`));
    });
  });
}

async function waitForHttp(url) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) return;
    } catch {
      // The process is still starting.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
  }
  throw new Error(`timed out waiting for ${url}`);
}

try {
  await run("bash", ["devcert/generate.sh"], repoDir);
  await run(
    "wasm-pack",
    ["build", "--target", "web", "--out-dir", "pkg-web"],
    wasmDir,
  );
  await run(
    "cargo",
    [
      "build",
      "-p",
      "foctet-transport",
      "--example",
      "webtrans_datagram_split",
      "--features",
      "runtime-tokio transport-webtrans",
    ],
    repoDir,
  );
  start(
    resolve(repoDir, "target/debug/examples/webtrans_datagram_split"),
    [
      "--role",
      "server",
      "--addr",
      "127.0.0.1:4470",
      "--tls-cert",
      "devcert/localhost.crt",
      "--tls-key",
      "devcert/localhost.key",
      "--drop-first-reply",
      "--reorder-reply-pairs",
    ],
    repoDir,
  );
  start("node", ["examples/browser/serve.mjs", "8011"], wasmDir);
  await waitForHttp("http://127.0.0.1:8011/examples/browser/webtransport.html");
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 1_000));

  const executablePath =
    process.env.CHROME_PATH ??
    process.env.CHROME_BIN ??
    "/usr/bin/google-chrome";
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    args: ["--enable-quic", "--origin-to-force-quic-on=127.0.0.1:4470"],
  });
  const page = await browser.newPage();
  page.on("console", (message) => console.log(`[browser] ${message.text()}`));
  await page.goto("http://127.0.0.1:8011/examples/browser/webtransport.html");
  const hash = (await readFile(resolve(repoDir, "devcert/localhost.hex"), "utf8")).trim();
  await page.locator("#hash").fill(hash);

  for (let run = 0; run < 2; run += 1) {
    await page.locator("#run").click();
    await page.waitForFunction(
      () => window.__FOCTET_RESULT__ !== undefined,
      null,
      { timeout: 30_000 },
    );
    const result = await page.evaluate(() => window.__FOCTET_RESULT__);
    if (result.failed !== 0) {
      const details = await page.locator("#results").innerText();
      throw new Error(
        `browser run ${run} failed: ${JSON.stringify(result)}\n${details}`,
      );
    }
    // Clear the previous machine-readable result so the second run proves a
    // fresh WebTransport connection and authenticated session.
    await page.evaluate(() => {
      window.__FOCTET_RESULT__ = undefined;
    });
    if (run === 0) {
      await page.evaluate(async (hashHex) => {
        const hash = new Uint8Array(32);
        for (let index = 0; index < 32; index += 1) {
          hash[index] = Number.parseInt(hashHex.slice(index * 2, index * 2 + 2), 16);
        }
        const cancelled = new WebTransport("https://127.0.0.1:4470/", {
          serverCertificateHashes: [{ algorithm: "sha-256", value: hash }],
        });
        await cancelled.ready;
        cancelled.close({ closeCode: 0, reason: "cancellation test" });
        await cancelled.closed;
      }, hash);
    }
  }
  await browser.close();
} finally {
  for (const child of children.reverse()) {
    if (child.exitCode === null) child.kill("SIGTERM");
  }
}
