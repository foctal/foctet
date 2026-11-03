// Local integration fixture only: intentionally no application authorization.
import {createClient} from '@libsql/client/web';
import {createConnection} from 'mysql2/promise';
import {tursoStore, hyperdriveStore} from '../index.mjs';
export default {
  async fetch(request, env) {
    const data = await request.json();
    let close, store;
    if (data.backend === 'turso') {
      const client = createClient({url: env.TURSO_URL});
      close = () => client.close(); store = tursoStore(client);
    } else {
      const connection = await createConnection({
        host: env.HYPERDRIVE.host, port: env.HYPERDRIVE.port,
        user: env.HYPERDRIVE.user, password: env.HYPERDRIVE.password,
        database: env.HYPERDRIVE.database, disableEval: true,
      });
      close = () => connection.end(); store = hyperdriveStore(connection);
    }
    try {
      let result;
      if (data.action === 'init') { await store.initialize(); result = true; }
      else if (data.action === 'get') result = await store.get(data.key, BigInt(data.version));
      else result = await store.compareAndSwap(data.key, data.version === null ? null : BigInt(data.version), data.text);
      return Response.json(result);
    } finally { await close(); }
  }
};
