import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const exampleDir = resolve(import.meta.dirname, "..");
const repoDir = resolve(exampleDir, "../../..");
const stateDir = await mkdtemp(resolve(tmpdir(), "foctet-wrangler-"));
const workerUrl = "http://127.0.0.1:8787";
let worker;

function run(command, args, env = {}) {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(command, args, {
      cwd: repoDir,
      env: { ...process.env, ...env },
      stdio: "inherit",
    });
    child.on("error", reject);
    child.on("exit", (code) => {
      if (code === 0) resolvePromise();
      else reject(new Error(`${command} exited with ${code}`));
    });
  });
}

async function startWorker() {
  worker = spawn(
    "npx",
    ["wrangler", "dev", "--port", "8787", "--persist-to", stateDir],
    { cwd: exampleDir, stdio: "inherit" },
  );
  for (let attempt = 0; attempt < 120; attempt += 1) {
    if (worker.exitCode !== null) throw new Error("wrangler exited before becoming ready");
    try {
      await fetch(`${workerUrl}/health`);
      return;
    } catch {
      await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
    }
  }
  throw new Error("wrangler did not become ready");
}

async function stopWorker() {
  if (!worker || worker.exitCode !== null) return;
  worker.kill("SIGTERM");
  await new Promise((resolvePromise) => worker.once("exit", resolvePromise));
}

const client = (path, env) =>
  run("cargo", ["run", "-p", "foctet-http", "--example", "workers_echo_client"], {
    WORKERS_URL: `${workerUrl}${path}`,
    ...env,
  });

try {
  await startWorker();

  // One atomic Durable Object transaction must win a cross-invocation race.
  await client("/foctet", {
    FIXED_MESSAGE_ID_BYTE: "a5",
    RACE_REQUESTS: "32",
  });

  // Durable replay state must survive a real local Worker runtime restart.
  await stopWorker();
  await startWorker();
  await client("/foctet", {
    FIXED_MESSAGE_ID_BYTE: "a5",
    EXPECTED_STATUS: "409",
  });

  // The DO alarm removes the marker at protected-context expiry.
  await client("/foctet", {
    FIXED_MESSAGE_ID_BYTE: "b6",
    CONTEXT_TTL_SECS: "1",
    EXPECTED_STATUS: "200",
  });
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 3000));
  await client("/foctet", {
    FIXED_MESSAGE_ID_BYTE: "b6",
    CONTEXT_TTL_SECS: "1",
    EXPECTED_STATUS: "200",
  });

  // Backend failures are fail-closed and mapped to an empty 500 response.
  await client("/__foctet-test/backend-error", {
    FIXED_MESSAGE_ID_BYTE: "c7",
    EXPECTED_STATUS: "500",
  });
} finally {
  await stopWorker();
  await rm(stateDir, { recursive: true, force: true });
}
