// Disposable loopback services only. No production credentials or deployments.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {mkdtemp, rm, readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {createRequire} from 'node:module';
import {build} from 'esbuild';
import {Miniflare, convertV4MiniflareOptions} from 'miniflare';
import {createConnection} from 'mysql2/promise';
import {encodeRecord, decodeRecord, openRecord} from '../index.mjs';
const root = resolve(import.meta.dirname, '../../..');
const run = (command, args, options = {}) => execFileSync(command, args, {cwd:root, encoding:'utf8', ...options}).trim();
const temp = await mkdtemp(resolve(tmpdir(), 'foctet-worker-databases-'));
const containers = [];
let mf;
try {
  const fixture = JSON.parse(run('cargo', ['run','--locked','-q','-p','foctet-storage-wire','--example','worker_fixture']));
  run('cargo', ['build','--locked','-p','foctet-wasm','--target','wasm32-unknown-unknown']);
  run('wasm-bindgen', ['--target','nodejs','--out-dir',temp, resolve(root,'target/wasm32-unknown-unknown/debug/foctet_wasm.wasm')]);
  const wasm = createRequire(import.meta.url)(resolve(temp, 'foctet_wasm.js'));
  const recipient = Uint8Array.from(fixture.secret), writer = Uint8Array.from(fixture.writer);
  const ns = new TextEncoder().encode('test'), id = new TextEncoder().encode('item');
  const open = (text, version) => openRecord(wasm, text, recipient, ns, id, version, writer);
  assert.equal(new TextDecoder().decode(open(fixture.records[0], 1n)), 'worker database secret');
  assert.equal(new TextDecoder().decode(wasm.openSignedTextStorageRecord(fixture.records[0],recipient,ns,id,1n,writer)), 'worker database secret');
  const frozen = JSON.parse(await readFile(resolve(root, 'test-vectors/storage-text-v1.json'),'utf8'));
  assert.equal(new TextDecoder().decode(open(frozen.records[0],1n)), 'worker database secret');
  const parts = decodeRecord(fixture.records[0]);
  assert.equal(encodeRecord(parts.ciphertext, parts.signature), fixture.records[0]);
  const writerPair = wasm.IdentityKeyPair.fromSecretKey(new Uint8Array(32).fill(42));
  const recipientPair = wasm.KeyPair.fromSecretKey(recipient);
  const signed = wasm.sealSignedStorageRecord(new TextEncoder().encode('js endpoint'), recipientPair.publicKey, new TextEncoder().encode("kid"),ns,id,1n,writerPair);
  assert.deepEqual(open(signed.toStorageText(),1n), new TextEncoder().encode('js endpoint'));
  signed.free(); writerPair.free(); recipientPair.free();
  const start = (kind, image, port, options, command=[]) => {
    const name = `foctet-worker-${kind}-${process.pid}`;
    run('docker',['run','-d','--name',name,'-p',`127.0.0.1::${port}`,...options,image,...command]); containers.push(name);
    return {name, port:Number(run('docker',['port',name,String(port)]).split(':').at(-1))};
  };
  const maria = start('maria','mariadb:12.3.3',3306,['-e','MARIADB_ROOT_PASSWORD=disposable','-e','MARIADB_DATABASE=foctet_test'],['--default-storage-engine=MyISAM']);
  const turso = start('libsql','ghcr.io/tursodatabase/libsql-server@sha256:6dd3eb276d9d3604e4a48ac4a999a2e267814732d57d7e94c04ba71482333a67',8080,['--platform','linux/amd64','-e','SQLD_NODE=primary']);
  for (const service of [maria,turso]) {
    let ready = false;
    for (let i=0;i<120;i++) {
      try {
        if (service === maria) run('docker',['exec',maria.name,'healthcheck.sh','--connect','--innodb_initialized'], {stdio:'pipe'});
        else if (!(await fetch(`http://127.0.0.1:${turso.port}/health`)).ok) throw new Error('not ready');
        ready=true;break;
      } catch { await new Promise(r=>setTimeout(r,1000)); }
    }
    assert.ok(ready,'database readiness');
  }
  const bundle = await build({entryPoints:[resolve(import.meta.dirname,'database-worker.mjs')],bundle:true,write:false,format:'esm',platform:'node',external:['node:*','cloudflare:*'],plugins:[{name:'worker-process',setup(build){build.onResolve({filter:/^process$/},()=>({path:'process',namespace:'worker-process'}));build.onLoad({filter:/.*/,namespace:'worker-process'},()=>({contents:'module.exports = globalThis.process;',loader:'js'}));}}],banner:{js:'import { createRequire } from "node:module"; const require = createRequire("file:///worker.mjs");'}});
  const options = {modules:true, script:bundle.outputFiles[0].text, compatibilityDate:'2026-10-19', compatibilityFlags:['nodejs_compat'], bindings:{TURSO_URL:`http://127.0.0.1:${turso.port}`}, hyperdrives:{HYPERDRIVE:`mysql://root:disposable@127.0.0.1:${maria.port}/foctet_test`}};
  const startWorker = () => new Miniflare(convertV4MiniflareOptions(options));
  mf = startWorker();
  const request = async data => {
    const response = await mf.dispatchFetch('http://fixture.test/',{method:'POST',body:JSON.stringify(data)});
    const body = await response.text(); assert.equal(response.status,200,body);return JSON.parse(body);
  };
  for (const backend of ['turso','maria']) {
    await request({backend,action:'init'});
    const key='00'.repeat(32);
    const inserts = await Promise.all(Array.from({length:8},()=>request({backend,action:'cas',key,version:null,text:fixture.records[0]})));
    assert.equal(inserts.filter(Boolean).length,1,`${backend} insert race`);
    assert.equal(await request({backend,action:'get',key,version:'1'}),fixture.records[0]);
    const updates = await Promise.all(Array.from({length:16},()=>request({backend,action:'cas',key,version:'1',text:fixture.records[1]})));
    assert.equal(updates.filter(Boolean).length,1,`${backend} CAS race`);
    assert.equal(await request({backend,action:'get',key,version:'1'}),null);
    const returned = await request({backend,action:'get',key,version:'2'});
    assert.equal(new TextDecoder().decode(open(returned,2n)),'worker database secret');
    assert.throws(()=>open(returned,1n));
    const forged = decodeRecord(returned);forged.signature[0]^=1;
    assert.throws(()=>open(encodeRecord(forged.ciphertext,forged.signature),2n));
    await mf.dispose();mf=startWorker();
    assert.equal(await request({backend,action:'get',key,version:'2'}),returned);
    console.log(`PASS ${backend}: Worker driver, insert/CAS races, signed Rust/WASM text, restart, stale/tampered rejection`);
  }
  // Execute the exact portable Rust statement via a scalar-only driver bridge.
  const connection=await createConnection({host:'127.0.0.1',port:maria.port,user:'root',password:'disposable',database:'foctet_test'});
  try {
    const [result]=await connection.execute(fixture.sql,fixture.args);
    assert.equal(result.affectedRows,0,'Rust CAS plan rejects stale revision');
    await connection.execute('UPDATE foctet_text_v1 SET version = 9007199254740993 WHERE record_key = ?', ['00'.repeat(32)]);
    assert.equal(await request({backend:'maria',action:'get',key:'00'.repeat(32),version:'9007199254740993'}),fixture.records[1]);
    // The database revision cannot turn an old signed record into a fresh one.
    assert.throws(()=>open(fixture.records[1],9007199254740993n));
  } finally { await connection.end(); }
  console.log('PASS portable Rust SQL plan and BIGINT precision beyond Number.MAX_SAFE_INTEGER');
} finally {
  try { if(mf)await mf.dispose(); }
  finally { for(const name of containers)run('docker',['rm','-f',name]); await rm(temp,{recursive:true,force:true}); }
}
