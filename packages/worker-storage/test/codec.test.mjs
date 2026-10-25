import {test} from 'node:test';
import assert from 'node:assert/strict';
import {encodeRecord, decodeRecord, tursoStore, hyperdriveStore, MAX_TEXT_BYTES} from '../index.mjs';
const text = encodeRecord(new Uint8Array([0,255,128]), new Uint8Array(64));
test('canonical binary-safe ASCII with bounded strict decoding', () => {
  assert.equal(text.slice(0,10), 'FCT1.AP+A.');
  assert.deepEqual(decodeRecord(text).ciphertext, new Uint8Array([0,255,128]));
  for (const bad of [text+'.', ' '+text, text.replace('FCT1','FCT0'), text.replace('AP+A','AB=='), text.replace('AP+A','AP-A'), text.slice(0,-1)])
    assert.throws(() => decodeRecord(bad));
  assert.throws(() => decodeRecord(text, text.length-1));
  assert.throws(() => decodeRecord(text, MAX_TEXT_BYTES+1));
  assert.throws(() => encodeRecord(new Uint8Array(MAX_TEXT_BYTES), new Uint8Array(64)));
});
test('strict revision, key, result and error handling; no automatic retries', async () => {
  let calls = 0;
  const store = tursoStore({execute: async () => { calls++; return {rows: [], rowsAffected: 1}; }});
  const key = '00'.repeat(32);
  for (const version of [1, '1', 0n, -1n, 9223372036854775808n]) await assert.rejects(store.get(key, version));
  await assert.rejects(store.get("' OR 1=1", 1n));
  assert.equal(calls, 0);
  assert.equal(await store.compareAndSwap(key, null, text), true);
  await assert.rejects(store.compareAndSwap(key, 9223372036854775807n, text));
  assert.equal(calls, 1);
  for (const rows of [[{payload:'broken'}], [{payload:text},{payload:text}], null])
    await assert.rejects(tursoStore({execute: async () => ({rows})}).get(key, 1n));
  await assert.rejects(tursoStore({execute: async () => ({rowsAffected:2})}).compareAndSwap(key, 1n, text));
  let attempts = 0;
  await assert.rejects(tursoStore({execute: async () => { attempts++; throw new Error('timeout'); }}).compareAndSwap(key, 1n, text));
  assert.equal(attempts, 1);
  const duplicate = tursoStore({execute: async () => { throw {code:'SQLITE_CONSTRAINT_PRIMARYKEY'}; }});
  assert.equal(await duplicate.compareAndSwap(key, null, text), false);
  await assert.rejects(duplicate.compareAndSwap(key, 1n, text));
});
test('Hyperdrive migration rejects nontransactional existing tables', async () => {
  const connection = {execute: async sql => sql.startsWith('SELECT') ? [[{engine:'MyISAM'}], []] : [{affectedRows:0},[]]};
  await assert.rejects(hyperdriveStore(connection).initialize(), /InnoDB/);
});
test('maximum valid text budget and full 64-bit revision binding', async () => {
  const bytes = new Uint8Array(Math.floor((MAX_TEXT_BYTES - 94) / 4) * 3).fill(255);
  const largest = encodeRecord(bytes,new Uint8Array(64));
  assert.ok(largest.length <= MAX_TEXT_BYTES);
  assert.deepEqual(decodeRecord(largest).ciphertext, bytes);
  assert.throws(()=>encodeRecord(new Uint8Array(bytes.length+1),new Uint8Array(64)));
  let statement;
  const store = tursoStore({execute: async value => {statement=value; return {rows:[], rowsAffected:1};}});
  await store.compareAndSwap('01'.repeat(32),9007199254740993n,text);
  assert.equal(statement.args[2],'9007199254740993');
  assert.ok(statement.args.every(value=>typeof value==='string'));
});
test('database failures cannot downgrade to conflict or valid reads', async () => {
  const key='00'.repeat(32);
  for(const error of [{code:'SQLITE_CONSTRAINT'}, {errno:1062,sqlState:'08000'}, new Error('network')]) {
    await assert.rejects(tursoStore({execute:async()=>{throw error;}}).compareAndSwap(key,null,text));
    await assert.rejects(hyperdriveStore({execute:async()=>{throw error;}}).compareAndSwap(key,null,text));
  }
  const maria=hyperdriveStore({execute:async()=>{throw {errno:1062,sqlState:'23000'};}});
  assert.equal(await maria.compareAndSwap(key,null,text),false);
  await assert.rejects(maria.compareAndSwap(key,1n,text));
});
