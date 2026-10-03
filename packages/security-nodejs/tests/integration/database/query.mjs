import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { readFile } from 'node:fs/promises';

import express from 'express';
import pg from 'pg';
import mysql from 'mysql2/promise';

const PgClient = pg.Client || pg.default?.Client;

const pgClient = new PgClient({
  connectionString: process.env.BEACON_SECURITY_QA_PG_URL,
});
await pgClient.connect();
const mysqlConnection = await mysql.createConnection(
  process.env.BEACON_SECURITY_QA_MYSQL_URL
);

const app = express();
app.use(express.json());
app.post('/database/:mode', async (request, response) => {
  const body = request.body || {};
  const value = String(body.value || '');
  const template = request.params.mode === 'template';
  try {
    // The two modes deliberately use the same input value. The template mode
    // interpolates it into the SQL text; bind mode sends the value through the
    // driver's parameter array. Both statements execute against private DBs.
    const pgResult = template
      ? await pgClient.query(`select '${value}'::text as value`)
      : await pgClient.query('select $1::text as value', [value]);
    const [mysqlRows] = template
      ? await mysqlConnection.execute(`select '${value}' as value`)
      : await mysqlConnection.execute('select ? as value', [value]);
    response.status(200).json({
      status: 'ok',
      mode: request.params.mode,
      pg: pgResult.rows[0]?.value,
      mysql: mysqlRows[0]?.value,
    });
  } catch (error) {
    response
      .status(500)
      .json({ status: 'error', error: error?.message || String(error) });
  }
});

const server = await new Promise((resolve, reject) => {
  const value = app.listen(0, '127.0.0.1', () => resolve(value));
  value.once('error', reject);
});

function requestJson(path, body) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const request = httpRequest(
      {
        host: '127.0.0.1',
        port: server.address().port,
        path,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(payload),
        },
      },
      response => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', chunk => {
          text += chunk;
        });
        response.on('end', () => {
          try {
            resolve({ status: response.statusCode, body: JSON.parse(text) });
          } catch (error) {
            reject(error);
          }
        });
      }
    );
    request.once('error', reject);
    request.end(payload);
  });
}

const sameValue = 'qa-template-and-bind';
const templateResponse = await requestJson('/database/template', {
  value: sameValue,
});
const bindResponse = await requestJson('/database/bind', { value: sameValue });
assert.equal(templateResponse.status, 200);
assert.equal(bindResponse.status, 200);
assert.deepEqual(templateResponse.body, {
  status: 'ok',
  mode: 'template',
  pg: sameValue,
  mysql: sameValue,
});
assert.deepEqual(bindResponse.body, {
  status: 'ok',
  mode: 'bind',
  pg: sameValue,
  mysql: sameValue,
});

await new Promise((resolve, reject) =>
  server.close(error => (error ? reject(error) : resolve()))
);
await pgClient.end();
await mysqlConnection.end();

await globalThis.__securityQaShutdown?.({ timeoutMillis: 2_000 });

const output = process.env.BEACON_SECURITY_OUTPUT;
const findings = output
  ? JSON.parse(await readFile(`${output}/findings.json`, 'utf8'))
  : { findings: [] };
const sqlFindings = (findings.findings || []).filter(
  item => item.rule === 'sql_injection'
);
const templateFindings = sqlFindings.filter(
  item => item.sink?.role === 'sql_template'
);
const sourceEvidence = templateFindings.flatMap(
  item => item.sources || item.representative?.sources || []
);
const traceIds = [
  ...new Set(
    templateFindings
      .map(item => item.trace_id || item.representative?.trace_id)
      .filter(Boolean)
  ),
];
const sourceTypes = [
  ...new Set(sourceEvidence.map(source => source.type).filter(Boolean)),
];
const result = {
  status:
    templateResponse.status === 200 &&
    bindResponse.status === 200 &&
    templateResponse.body.pg === sameValue &&
    templateResponse.body.mysql === sameValue &&
    bindResponse.body.pg === sameValue &&
    bindResponse.body.mysql === sameValue &&
    templateFindings.length >= 2 &&
    sourceTypes.includes('http.request.body') &&
    traceIds.length >= 1
      ? 'pass'
      : 'fail',
  http: {
    template: templateResponse,
    bind: bindResponse,
  },
  security: {
    sql_finding_count: sqlFindings.length,
    template_finding_count: templateFindings.length,
    template_roles: [
      ...new Set(templateFindings.map(item => item.sink?.role).filter(Boolean)),
    ],
    source_types: sourceTypes,
    trace_ids: traceIds,
    findings: templateFindings.map(item => ({
      finding_id: item.finding_id,
      trace_id: item.trace_id || item.representative?.trace_id || '',
      source_types: [
        ...new Set(
          (item.sources || item.representative?.sources || [])
            .map(source => source.type)
            .filter(Boolean)
        ),
      ],
      sink: item.sink || item.representative?.sink,
      execution_observation:
        item.execution_observation ||
        item.representative?.execution_observation,
    })),
  },
};
process.stdout.write(`${JSON.stringify(result)}\n`);
