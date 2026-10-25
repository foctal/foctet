import fixture from "./storage-worker.mjs";
import {Miniflare,convertV4MiniflareOptions} from "miniflare";
import assert from "node:assert/strict";
import {readFile,mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {resolve} from "node:path";
const root = resolve(import.meta.dirname,"../../../..");
const vector = JSON.parse(await readFile(resolve(root,"test-vectors/archive-v0.json"),"utf8"));
const bytes = Buffer.from(vector.archive_hex ?? vector.single_archive_hex,"hex");
const state = await mkdtemp(resolve(tmpdir(),"foctet-blind-storage-"));
const options = { modules:true, scriptPath:resolve(import.meta.dirname,"storage-worker.mjs"), compatibilityDate:"2026-03-08", kvNamespaces:["KV"], r2Buckets:["R2"], d1Databases:["DB"], durableObjects:{OBJECTS:{className:"BlobObject",useSQLite:true}}, queueProducers:{QUEUE:"blobs"}, queueConsumers:{blobs:{maxBatchTimeout:0}}, defaultPersistRoot:state };
let mf;
try {
  mf = new Miniflare({...convertV4MiniflareOptions(options),resourcePersistencePath:state,isolatedResourcePersistencePath:state});
  const db = await mf.getD1Database("DB");
  await db.exec("CREATE TABLE records(id TEXT PRIMARY KEY,version INTEGER NOT NULL,blob BLOB NOT NULL)");
  for (const backend of ["kv","r2","d1","do","queue","cache"]) {
    const url=`https://fixture.test/${backend}/record`;
    assert.equal((await mf.dispatchFetch(url,{method:"PUT",body:bytes})).status,204,backend);
    let response;
    for (let i=0;i<50;i++) {
      response=await mf.dispatchFetch(url);if(response.status===200)break;
      await new Promise(r=>setTimeout(r,100));
    }
    assert.equal(response.status,200,backend);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()),bytes,backend);
  }
  // Exercise the same duplicate message twice against the real KV binding.
  let acknowledgements=0;
  const duplicate={body:{key:"duplicate",bytes:Array.from(bytes)},ack(){acknowledgements++;}};
  const kv=await mf.getKVNamespace("KV");
  await fixture.queue({messages:[duplicate,duplicate]},{KV:kv});
  assert.equal(acknowledgements,2);
  assert.deepEqual(Buffer.from(await kv.get("queue/duplicate","arrayBuffer")),bytes);
  assert.equal((await mf.dispatchFetch("https://fixture.test/cache/other-object")).status,404);
  assert.equal((await mf.dispatchFetch("https://other-tenant.test/cache/record")).status,404);
  const races=await Promise.all(Array.from({length:16},()=>mf.dispatchFetch("https://fixture.test/d1/record",{method:"PUT",headers:{"x-expected-version":"1"},body:bytes})));
  assert.equal(races.filter(r=>r.status===204).length,1);
  assert.equal(races.filter(r=>r.status===409).length,15);
  assert.equal((await mf.dispatchFetch("https://fixture.test/r2/too-large",{method:"PUT",body:new Uint8Array(1024*1024+1)})).status,413);
  await mf.dispose();mf=new Miniflare({...convertV4MiniflareOptions(options),resourcePersistencePath:state,isolatedResourcePersistencePath:state});
  for(const backend of ["kv","r2","d1","do"]) {
    const response=await mf.dispatchFetch(`https://fixture.test/${backend}/record`);
    assert.equal(response.status,200,backend);assert.deepEqual(Buffer.from(await response.arrayBuffer()),bytes);
  }
  console.log("ok: KV/R2/D1/DO/Queues/Cache opaque-byte roundtrips, D1 CAS race, size limit, and persisted restart");
} finally { if(mf)await mf.dispose();await rm(state,{recursive:true,force:true}); }
