import {createClient} from '@libsql/client/web';
import {createConnection} from 'mysql2/promise';
import {tursoStore, hyperdriveStore, encodeRecord, openRecord, type WasmStorage} from '@foctet/worker-storage';
// Compile-time integration only; this function is not executed.
async function connectionTypes(wasm: WasmStorage) {
  const client = createClient({url:'https://example.invalid'});
  const turso = tursoStore(client);
  const connection = await createConnection({host:'localhost',disableEval:true});
  const maria = hyperdriveStore(connection);
  const text = encodeRecord(new Uint8Array([1]), new Uint8Array(64));
  await turso.compareAndSwap('00'.repeat(32), null, text);
  await maria.get('00'.repeat(32), 1n);
  // @ts-expect-error Number revisions lose precision and are rejected.
  await turso.get('00'.repeat(32), 1);
  openRecord(wasm,text,new Uint8Array(32),new Uint8Array(),new Uint8Array(),1n,new Uint8Array(32));
  client.close(); await connection.end();
}
void connectionTypes;
