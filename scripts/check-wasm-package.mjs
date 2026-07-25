import { access, readFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const root = new URL("../foctet-wasm/", import.meta.url).pathname;
const developmentManifest = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
for (const directory of ["pkg", "pkg-node", "pkg-web"]) {
  const packageRoot = join(root, directory);
  const manifest = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
  if (manifest.name !== "@foctet/foctet-wasm") {
    throw new Error(`${directory} has unexpected package name ${manifest.name}`);
  }
  if (manifest.version !== developmentManifest.version) {
    throw new Error(`${directory} version does not match the release harness`);
  }
  if (!manifest.types) throw new Error(`${directory} package has no TypeScript declaration entry`);
  await access(join(packageRoot, "LICENSE"));
  await access(join(packageRoot, manifest.types));
  const declarations = await readFile(join(packageRoot, manifest.types), "utf8");
  for (const required of ["FoctetSession", "KeyPair", "sealBody", "openBody"]) {
    if (!declarations.includes(required)) {
      throw new Error(`${directory} declarations omit ${required}`);
    }
  }
}

const nodePackage = await import(pathToFileURL(join(root, "pkg-node", "foctet_wasm.js")));
for (const required of ["FoctetSession", "KeyPair", "sealBody", "openBody"]) {
  if (!(required in nodePackage)) throw new Error(`Node package omits ${required}`);
}
