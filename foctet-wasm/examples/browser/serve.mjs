// Minimal dependency-free static server for the foctet-wasm browser harness.
//
// Serves the `foctet-wasm` crate directory so the harness at
// `examples/browser/index.html` can reach `../../pkg-web` and `../../tests`.
// Node is already required to build the SDK, so this avoids a Python dependency.
//
// Usage:
//   node examples/browser/serve.mjs [port]
// then open the printed URL. Set FOCTET_OPEN=1 to launch the default browser.

import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const port = Number(process.argv[2] ?? process.env.PORT ?? 8011);
// examples/browser/serve.mjs -> crate root is two levels up.
const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const harnessPath = "/examples/browser/index.html";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".wasm": "application/wasm",
  ".css": "text/css; charset=utf-8",
  ".map": "application/json; charset=utf-8",
  ".ts": "text/plain; charset=utf-8",
};

const server = createServer(async (req, res) => {
  try {
    const urlPath = decodeURIComponent((req.url ?? "/").split("?")[0]);
    const rel = normalize(urlPath).replace(/^(\.\.[/\\])+/, "");
    let filePath = join(root, rel);
    // Block path traversal outside the served root.
    if (filePath !== root && !filePath.startsWith(root + sep)) {
      res.writeHead(403).end("Forbidden");
      return;
    }
    if (urlPath === "/" || urlPath.endsWith("/")) {
      filePath = join(root, harnessPath);
    }
    const body = await readFile(filePath);
    res.writeHead(200, {
      "content-type": MIME[extname(filePath)] ?? "application/octet-stream",
      "cache-control": "no-store",
    });
    res.end(body);
  } catch {
    res.writeHead(404).end("Not Found");
  }
});

server.listen(port, () => {
  const url = `http://localhost:${port}${harnessPath}`;
  console.log(`foctet-wasm browser harness: ${url}`);
  console.log(`serving ${root}`);
  console.log("Ctrl+C to stop.");
  if (process.env.FOCTET_OPEN === "1") {
    const opener =
      process.platform === "darwin"
        ? "open"
        : process.platform === "win32"
          ? "cmd"
          : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
    spawn(opener, args, { stdio: "ignore", detached: true }).unref();
  }
});
