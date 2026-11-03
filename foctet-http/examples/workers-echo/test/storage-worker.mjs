// Blind-storage integration fixture. Local tests only: application authentication
// and per-tenant authorization must precede these operations in a deployment.
const MAX_BYTES = 1024 * 1024;
async function boundedBody(request) {
  const reader = request.body?.getReader();
  if (!reader) return new Uint8Array();
  const chunks = []; let length = 0;
  while (true) {
    const {done,value} = await reader.read(); if (done) break;
    length += value.length;
    if (length > MAX_BYTES) { await reader.cancel(); throw new Error("limit"); }
    chunks.push(value);
  }
  const out = new Uint8Array(length); let offset = 0;
  for (const chunk of chunks) { out.set(chunk,offset); offset += chunk.length; }
  return out;
}
export class BlobObject {
  constructor(state) { this.state = state; }
  async fetch(request) {
    if (request.method === "PUT") {
      await this.state.storage.put("blob", await boundedBody(request));
      return new Response(null, {status:204});
    }
    const bytes = await this.state.storage.get("blob");
    return new Response(bytes ?? null, {status: bytes ? 200 : 404});
  }
}
export default {
  async fetch(request, env) {
    const [backend,key] = new URL(request.url).pathname.slice(1).split("/");
    if (!key || !/^[a-z0-9-]{1,64}$/.test(key)) return new Response(null,{status:400});
    if (backend === "do") return env.OBJECTS.get(env.OBJECTS.idFromName(key)).fetch(request);
    if (request.method === "PUT") {
      let bytes; try { bytes = await boundedBody(request); } catch { return new Response(null,{status:413}); }
      if (backend === "kv") await env.KV.put(key, bytes);
      else if (backend === "r2") await env.R2.put(key,bytes);
      else if (backend === "d1") {
        const expected = Number(request.headers.get("x-expected-version") ?? 0);
        if (!Number.isSafeInteger(expected) || expected < 0) return new Response(null,{status:400});
        const result = expected === 0
          ? await env.DB.prepare("INSERT INTO records(id,version,blob) VALUES (?,1,?) ON CONFLICT(id) DO NOTHING").bind(key,bytes).run()
          : await env.DB.prepare("UPDATE records SET version=version+1,blob=? WHERE id=? AND version=?").bind(bytes,key,expected).run();
        if (result.meta.changes !== 1) return new Response(null,{status:409});
      } else if (backend === "queue") {
        await env.QUEUE.send({key, bytes:Array.from(bytes)});
      } else if (backend === "cache") {
        await caches.default.put(request.url,new Response(bytes,{headers:{"cache-control":"public,max-age=60"}}));
      } else return new Response(null,{status:404});
      return new Response(null,{status:204});
    }
    let bytes;
    if (backend === "kv" || backend === "queue") bytes = await env.KV.get(backend === "queue" ? `queue/${key}` : key,"arrayBuffer");
    else if (backend === "r2") { const item = await env.R2.get(key); bytes = item ? await item.arrayBuffer() : null; }
    else if (backend === "d1") { const row = await env.DB.prepare("SELECT blob FROM records WHERE id=?").bind(key).first(); bytes = row ? new Uint8Array(row.blob) : null; }
    else if (backend === "cache") return (await caches.default.match(request.url)) ?? new Response(null,{status:404});
    return new Response(bytes ?? null,{status:bytes ? 200 : 404});
  },
  async queue(batch,env) {
    for (const message of batch.messages) {
      // Duplicate deliveries overwrite identical opaque bytes, without decrypting.
      await env.KV.put(`queue/${message.body.key}`,new Uint8Array(message.body.bytes)); message.ack();
    }
  },
};
