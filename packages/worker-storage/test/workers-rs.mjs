// Actual workers-rs runtime regression fixture, using only disposable services.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {readFile,mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {resolve} from 'node:path';
import {createServer} from 'node:http';
import {Miniflare,convertV4MiniflareOptions} from 'miniflare';
const root=resolve(import.meta.dirname,'../../..');
const project=resolve(root,'foctet-storage-wire/examples/workers');
const run=(cmd,args,options={})=>execFileSync(cmd,args,{cwd:root,encoding:'utf8',...options}).trim();
const state=await mkdtemp(resolve(tmpdir(),'foctet-workers-rs-'));
const containers=[];
let mf,mode='malformed',requests=0;
const mock=createServer((req,res)=>{
  requests++;
  req.resume();
  if(mode==='slow')return;
  if(mode==='redirect'){res.writeHead(302,{location:'/unexpected'});res.end();return;}
  res.writeHead(200,{'content-type':'application/json'});
  if(mode==='slow-body'){res.write('{');return;}
  if(mode==='oversized'){res.end('x'.repeat(32*1024));return;}
  res.end('{"results":[]}');
});
await new Promise(r=>mock.listen(0,'127.0.0.1',r));
try {
  run('cargo',['check','--locked','--manifest-path',resolve(project,'Cargo.toml'),'--target','wasm32-unknown-unknown']);
  run('worker-build',['--dev','--features','sdk-http'],{cwd:project});
  const vector=JSON.parse(await readFile(resolve(root,'test-vectors/storage-text-v1.json'),'utf8'));
  const start=(kind,image,port,options)=>{
    const name=`foctet-workers-rs-${kind}-${process.pid}`;
    run('docker',['run','-d','--name',name,'-p',`127.0.0.1::${port}`,...options,image]);containers.push(name);
    return {name,port:Number(run('docker',['port',name,String(port)]).split(':').at(-1))};
  };
  const libsql=start('libsql','ghcr.io/tursodatabase/libsql-server@sha256:6dd3eb276d9d3604e4a48ac4a999a2e267814732d57d7e94c04ba71482333a67',8080,['--platform','linux/amd64','-e','SQLD_NODE=primary']);
  const maria=start('maria','mariadb:12.3.3',3306,['-e','MARIADB_ROOT_PASSWORD=disposable','-e','MARIADB_DATABASE=foctet_test']);
  for(const service of [libsql,maria]) {
    let ready=false;
    for(let i=0;i<120;i++) {
      try {
        if(service===maria)run('docker',['exec',maria.name,'healthcheck.sh','--connect','--innodb_initialized'],{stdio:'pipe'});
        else if(!(await fetch(`http://127.0.0.1:${libsql.port}/health`)).ok)throw Error('not ready');
        ready=true;break;
      }catch{await new Promise(r=>setTimeout(r,1000));}
    }
    assert.ok(ready,'database readiness');
  }
  const modulesRoot=resolve(project,'build');
  const options={modulesRoot,modules:[
    {type:'ESModule',path:resolve(modulesRoot,'index.js'),contents:await readFile(resolve(modulesRoot,'index.js'),'utf8')},
    {type:'CompiledWasm',path:resolve(modulesRoot,'index_bg.wasm'),contents:await readFile(resolve(modulesRoot,'index_bg.wasm'))},
  ],compatibilityDate:'2026-10-19',compatibilityFlags:['nodejs_compat'],
    d1Databases:['DB'],kvNamespaces:['KV'],r2Buckets:['BUCKET'],
    hyperdrives:{DB_SOCKET:`mysql://root:disposable@127.0.0.1:${maria.port}/foctet_test`},
    bindings:{LIBSQL_URL:`http://127.0.0.1:${libsql.port}`,LIBSQL_BAD_URL:`http://127.0.0.1:${mock.address().port}`},
  };
  const startWorker=()=>new Miniflare({...convertV4MiniflareOptions(options),resourcePersistencePath:state,isolatedResourcePersistencePath:state});
  mf=startWorker();
  const raw=(data,path='/')=>mf.dispatchFetch(`http://fixture.test${path}`,{method:'POST',body:JSON.stringify(data)});
  const request=async(data,path)=>{
    const response=await raw(data,path);const body=await response.text();assert.equal(response.status,200,body);return JSON.parse(body);
  };
  for(const backend of ['d1','libsql']) {
    await request({backend,action:'init'});
    const inserts=await Promise.all(Array.from({length:8},()=>request({backend,action:'cas',version:null,text:vector.records[0]})));
    assert.equal(inserts.filter(Boolean).length,1,`${backend} insert race`);
    assert.equal(await request({backend,action:'get',version:'1'}),vector.records[0]);
    const writes=await Promise.all(Array.from({length:16},()=>request({backend,action:'cas',version:'1',text:vector.records[1]})));
    assert.equal(writes.filter(Boolean).length,1,`${backend} update race`);
    assert.equal(await request({backend,action:'get',version:'1'}),null);
    const text=await request({backend,action:'get',version:'2'});
    assert.equal(await (await raw({text,version:'2'},'/verify')).text(),'worker database secret');
    assert.equal((await raw({text,version:'1'},'/verify')).status,401);
    const tampered=text.slice(0,-4)+(text.at(-4)==='A'?'B':'A')+text.slice(-3);
    assert.equal((await raw({text:tampered,version:'2'},'/verify')).status,401);
    await mf.dispose();mf=startWorker();
    assert.equal(await request({backend,action:'get',version:'2'}),text);
    console.log(`PASS workers-rs ${backend}: concurrent CAS, signed records, tamper/stale rejection, restart`);
  }
  assert.equal(await (await mf.dispatchFetch('http://fixture.test/websocket')).json(),true);
  console.log('PASS workers-rs and WebSocket transport: pinned handshake, encrypted bidirectional messages, text rejection');
  for(const backend of ['kv','r2'])assert.equal(await request({backend,text:vector.records[0]}),vector.records[0]);
  assert.equal(await (await mf.dispatchFetch('http://fixture.test/hyperdrive-socket')).json(),true);
  const rejected=await mf.dispatchFetch('http://fixture.test/body-limit',{method:'POST',headers:{'content-type':'application/foctet'},body:'x'.repeat(100)});
  assert.equal(rejected.status,413);
  for(const url of ['http://example.com','https://user:password@example.com','https://example.com/?secret=x','https://example.com/#fragment','https://example.com/path'])
    assert.equal(await request({url},'/config'),false);
  assert.equal(await request({url:'https://example.com',token:'x\r\nother:y'},'/config'),false);
  assert.equal(await request({url:'libsql://example.com'},'/config'),true);
  for(mode of ['malformed','oversized','redirect','slow','slow-body']) {
    const before=requests;
    const started=performance.now();
    assert.notEqual((await raw({backend:'libsql',fault:true,action:'get',version:'2'})).status,200,mode);
    if(mode.startsWith('slow')) {
      const elapsed=performance.now()-started;
      assert.ok(elapsed>=2000 && elapsed<10000,`${mode}: deadline enforced (${elapsed} ms)`);
    }
    assert.equal(requests-before,1,`${mode}: no redirect or retry`);
  }
  console.log('PASS workers-rs 0.8.7 http feature, KV/R2, Hyperdrive socket, bounded HTTP, libSQL configuration/response/redirect/timeout failures');
} finally {
  try {if(mf)await mf.dispose();}
  finally {
    mock.closeAllConnections();await new Promise(r=>mock.close(r));
    for(const name of containers)run('docker',['rm','-f',name]);
    await rm(state,{recursive:true,force:true});
  }
}
