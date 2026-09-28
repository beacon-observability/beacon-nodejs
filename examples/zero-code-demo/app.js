/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const http = require('node:http');

const holdMillis = Number(process.env.APP_HOLD_MILLIS || 0);

const server = http.createServer((request, response) => {
  if (request.url !== '/work') {
    response.writeHead(404);
    response.end();
    return;
  }

  let total = 0;
  for (let index = 0; index < 100_000; index += 1) {
    total += Math.sqrt(index);
  }
  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ ok: true, total: Math.round(total) }));
});

server.listen(0, '127.0.0.1', async () => {
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('unable to determine application port');
  }

  const body = await request(`http://127.0.0.1:${address.port}/work`);
  const result = JSON.parse(body);
  if (result.ok !== true) {
    throw new Error(`unexpected application response: ${body}`);
  }

  await delay(holdMillis);
  server.close(error => {
    if (error) {
      throw error;
    }
    console.log('plain application completed');
  });
});

function request(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, response => {
        const chunks = [];
        response.on('data', chunk => chunks.push(chunk));
        response.on('end', () => resolve(Buffer.concat(chunks).toString()));
      })
      .on('error', reject);
  });
}

function delay(milliseconds) {
  return new Promise(resolve => setTimeout(resolve, milliseconds));
}
