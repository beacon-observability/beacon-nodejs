import http from 'node:http';

export function configure(app, pool, cache, endpoint) {
  const agent = new http.Agent({ keepAlive: true });
  const downstream = id =>
    new Promise((resolve, reject) => {
      const request = http.get(
        endpoint + '/?id=' + id,
        { agent, timeout: 4000 },
        response => {
          let body = '';
          response.setEncoding('utf8');
          response.on('data', chunk => (body += chunk));
          response.on('end', () =>
            response.statusCode === 200
              ? resolve(body)
              : reject(new Error('downstream error'))
          );
        }
      );
      request.on('error', reject);
      request.on('timeout', () => request.destroy(new Error('timeout')));
    });
  app.get('/:kind', async (request, response, next) => {
    try {
      const id = Number(request.query.id);
      if (!Number.isInteger(id) || id < 1 || id > 10000) {
        response.statusCode = 400;
        response.end('invalid id');
        return;
      }
      const kind = request.params.kind;
      if (kind === 'db' || kind === 'waterfall') {
        const rows = await pool.query('SELECT $1::int AS id', [id]);
        if (rows.rows[0].id !== id) throw new Error('database value changed');
      }
      if (kind === 'cache' || kind === 'waterfall') {
        const value = await cache.get('beacon-issue37:' + id);
        if (value !== 'fixed-cache') throw new Error('cache value changed');
      }
      if (kind === 'downstream' || kind === 'waterfall') {
        if ((await downstream(id)) !== 'fixed-downstream')
          throw new Error('HTTP value changed');
      }
      // A deliberately unsupported call must still be counted as incomplete.
      if (kind === 'unknown') Math.trunc(id);
      response.end('ok');
    } catch (error) {
      next(error);
    }
  });
  return () => agent.destroy();
}
