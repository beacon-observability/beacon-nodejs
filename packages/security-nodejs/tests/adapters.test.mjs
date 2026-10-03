import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';

import { installBuiltins, installLibrary } from '../src/adapters/sinks.mjs';
import { invoke } from '../src/core/calls.mjs';
import { SecurityState } from '../src/core/state.mjs';
import { bind } from '../src/core/runtime.mjs';
import { p, set } from '../src/core/values.mjs';

for (const rule of [
  'sql_injection',
  'command_execution',
  'command_injection',
  'ssrf',
  'http_request_input',
  'path_traversal',
]) {
  process.env[`BEACON_SECURITY_RULES_${rule.toUpperCase()}_ENABLED`] = 'true';
}

installBuiltins();

const identity = Object.freeze({
  application_id: 'adapters-test',
  instance_id: 'adapters-test-instance',
  service: { 'service.name': 'adapters-test' },
  code: {},
  runtime: {},
  identity_status: 'configured',
});

function state() {
  return new SecurityState(identity, { method: 'GET', url: '/adapter-test' });
}

function invokeValue(
  fn,
  receiver,
  args,
  location,
  construct = false,
  receiverMarks = []
) {
  return invoke(
    { v: fn, receiver: p(receiver, receiverMarks) },
    args.map(([value, marks = []]) => p(value, marks)),
    location,
    construct
  );
}

function markedSlice(
  current,
  value,
  type,
  name,
  start = 0,
  end = value.length
) {
  const seed = current.source(value, type, name, 'adapter-test#source');
  return current.step(seed, 'adapter-test.slice', 'adapter-test#source', {
    from: start,
    to: end,
  });
}

function findings(current, rule, role) {
  return current.pending.filter(
    event => event.rule === rule && (!role || event.sink.role === role)
  );
}

function inputFindings(current, part) {
  return findings(current, 'http_request_input', 'path_or_query').filter(
    event => event.sink.input_part === part
  );
}

function fileFindings(current, operation, pathRole) {
  return findings(current, 'path_traversal', 'file_path').filter(
    event =>
      event.sink.operation === operation &&
      (!pathRole || event.sink.path_role === pathRole)
  );
}

function run(current, callback) {
  try {
    return bind(current, callback);
  } finally {
    current.close();
  }
}

function fetchStub(input) {
  return { input };
}

installLibrary('undici', { fetch: fetchStub }, '8.0.0');

test(
  'URL query-only provenance cannot become a host finding',
  { concurrency: false },
  () => {
    const current = state();
    run(current, () => {
      const source = 'https://example.test/path?token=tainted';
      const query = markedSlice(
        current,
        source,
        'http.query',
        'request.query',
        source.indexOf('?') + 1
      );
      const url = invokeValue(
        URL,
        undefined,
        [[source, query]],
        'adapter#url-query',
        true
      );
      invokeValue(
        fetchStub,
        undefined,
        [[url.v, url.m]],
        'adapter#fetch-query'
      );
      assert.equal(findings(current, 'ssrf', 'destination_address').length, 0);
      assert.equal(inputFindings(current, 'path').length, 0);
      assert.equal(inputFindings(current, 'query').length, 1);
    });
  }
);

test(
  'Request constructed from a query-only URL keeps the host clean',
  { concurrency: false },
  () => {
    const current = state();
    run(current, () => {
      const source = 'https://example.test/path?token=tainted';
      const query = markedSlice(
        current,
        source,
        'http.query',
        'request.query',
        source.indexOf('?') + 1
      );
      const url = invokeValue(
        URL,
        undefined,
        [[source, query]],
        'adapter#request-url',
        true
      );
      const request = invokeValue(
        Request,
        undefined,
        [[url.v, url.m]],
        'adapter#request',
        true
      );
      invokeValue(
        fetchStub,
        undefined,
        [[request.v, request.m]],
        'adapter#request-fetch'
      );
      assert.equal(findings(current, 'ssrf', 'destination_address').length, 0);
      assert.equal(inputFindings(current, 'query').length, 1);
    });
  }
);

test(
  'URL base plus tainted relative path preserves path/query components',
  { concurrency: false },
  () => {
    const current = state();
    run(current, () => {
      const relative = '/next?token=tainted';
      const relativeMarks = markedSlice(
        current,
        relative,
        'http.input',
        'relative.url'
      );
      const url = invokeValue(
        URL,
        undefined,
        [
          [relative, relativeMarks],
          ['https://fixed.example/base/', []],
        ],
        'adapter#base-url',
        true
      );
      invokeValue(fetchStub, undefined, [[url.v, url.m]], 'adapter#base-fetch');
      assert.equal(findings(current, 'ssrf', 'destination_address').length, 0);
      assert.equal(inputFindings(current, 'path').length, 1);
      assert.equal(inputFindings(current, 'query').length, 1);
    });
  }
);

test(
  'changing a tracked URL search field to a constant clears its source',
  { concurrency: false },
  () => {
    const current = state();
    run(current, () => {
      const source = 'https://example.test/path?token=tainted';
      const query = markedSlice(
        current,
        source,
        'http.query',
        'request.query',
        source.indexOf('?') + 1
      );
      const url = invokeValue(
        URL,
        undefined,
        [[source, query]],
        'adapter#mutate-url',
        true
      );
      set(p(url.v, url.m), p('search'), p(''));
      invokeValue(
        fetchStub,
        undefined,
        [[url.v, url.m]],
        'adapter#mutated-fetch'
      );
      assert.equal(current.pending.length, 0);
    });
  }
);

test(
  'String slice maps indices and does not invoke an object boundary twice',
  { concurrency: false },
  () => {
    const current = state();
    run(current, () => {
      const source = 'abcdef';
      const marks = markedSlice(current, source, 'http.input', 'slice.input');
      const sliced = invokeValue(
        String.prototype.slice,
        source,
        [
          [1, []],
          [4, []],
        ],
        'adapter#slice',
        false,
        marks
      );
      assert.equal(sliced.v, 'bcd');
      assert.equal(sliced.m.length, 1);
      assert.equal(sliced.m[0].start, 0);
      assert.equal(sliced.m[0].end, 3);

      let valueOfCalls = 0;
      const boundary = {
        valueOf() {
          valueOfCalls += 1;
          return 1;
        },
      };
      const conservative = invokeValue(
        String.prototype.slice,
        source,
        [[boundary, []]],
        'adapter#slice-object',
        false,
        marks
      );
      assert.equal(conservative.v, 'bcdef');
      assert.equal(valueOfCalls, 1);
      assert.ok(current.gaps.has('string.slice_boundary_object'));
      assert.equal(conservative.m[0].exact, false);
      assert.ok(marks.length > 0);

      const fractional = invokeValue(
        String.prototype.substr,
        source,
        [
          [1.9, []],
          [2, []],
        ],
        'adapter#substr-fractional',
        false,
        marks
      );
      assert.equal(fractional.v, 'bc');
      assert.equal(fractional.m[0].start, 0);
      assert.equal(fractional.m[0].end, 2);
    });
  }
);

test(
  'Buffer and primitive/path conversions preserve bounded units and provenance',
  { concurrency: false },
  () => {
    const current = state();
    run(current, () => {
      const text = '42';
      const textMarks = markedSlice(
        current,
        text,
        'http.input',
        'conversion.input'
      );
      const number = invokeValue(
        Number,
        undefined,
        [[text, textMarks]],
        'adapter#number'
      );
      assert.equal(number.v, 42);
      assert.equal(number.m.length, 1);
      assert.equal(number.m[0].exact, false);

      const buffer = invokeValue(
        Buffer.from,
        Buffer,
        [[text, textMarks]],
        'adapter#buffer'
      );
      assert.equal(Buffer.isBuffer(buffer.v), true);
      assert.equal(buffer.m[0].unit, 'byte');
      const decoded = invokeValue(
        Buffer.prototype.toString,
        buffer.v,
        [],
        'adapter#buffer-to-string',
        false,
        buffer.m
      );
      assert.equal(decoded.v, text);
      assert.equal(decoded.m[0].unit, 'utf16_code_unit');

      const pathPart = 'nested';
      const pathMarks = markedSlice(
        current,
        pathPart,
        'http.path',
        'path.input'
      );
      const joined = invokeValue(
        path.join,
        path,
        [
          ['/tmp', []],
          [pathPart, pathMarks],
        ],
        'adapter#path-join'
      );
      assert.equal(joined.v, path.join('/tmp', pathPart));
      assert.equal(joined.m[0].exact, false);
    });
  }
);

test(
  'readFileSync reports the actual source path sink',
  { concurrency: false },
  () => {
    const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), 'beacon_security-node-adapter-')
    );
    const filename = path.join(directory, 'fixture.txt');
    fs.writeFileSync(filename, 'adapter-file-value', 'utf8');
    const current = state();
    try {
      run(current, () => {
        const marks = markedSlice(current, filename, 'http.path', 'file.path');
        const result = invokeValue(
          fs.readFileSync,
          fs,
          [
            [filename, marks],
            ['utf8', []],
          ],
          'adapter#readFileSync'
        );
        assert.equal(result.v, 'adapter-file-value');
        const event = fileFindings(current, 'read', 'source')[0];
        assert.ok(event);
        assert.equal(event.execution_observation, 'invocation_attempt');
      });
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
);

test(
  'file URL query marks are excluded from fs pathname evidence',
  { concurrency: false },
  () => {
    const directory = fs.mkdtempSync(
      path.join(os.tmpdir(), 'beacon_security-node-file-url-')
    );
    const filename = path.join(directory, 'fixture.txt');
    fs.writeFileSync(filename, 'file-url-value', 'utf8');
    try {
      const queryState = state();
      run(queryState, () => {
        const source = `${pathToFileURL(filename).href}?input=tainted`;
        const marks = markedSlice(
          queryState,
          source,
          'http.query',
          'file.query',
          source.indexOf('?') + 1
        );
        const fileUrl = invokeValue(
          URL,
          undefined,
          [[source, marks]],
          'adapter#file-url-query',
          true
        );
        const result = invokeValue(
          fs.readFileSync,
          fs,
          [
            [fileUrl.v, fileUrl.m],
            ['utf8', []],
          ],
          'adapter#file-url-query-read'
        );
        assert.equal(result.v, 'file-url-value');
        assert.equal(fileFindings(queryState, 'read', 'source').length, 0);
      });

      const pathnameState = state();
      run(pathnameState, () => {
        const source = pathToFileURL(filename).href;
        const marks = markedSlice(
          pathnameState,
          source,
          'http.path',
          'file.pathname',
          source.indexOf(filename),
          source.length
        );
        const fileUrl = invokeValue(
          URL,
          undefined,
          [[source, marks]],
          'adapter#file-url-path',
          true
        );
        const result = invokeValue(
          fs.readFileSync,
          fs,
          [
            [fileUrl.v, fileUrl.m],
            ['utf8', []],
          ],
          'adapter#file-url-path-read'
        );
        assert.equal(result.v, 'file-url-value');
        assert.equal(fileFindings(pathnameState, 'read', 'source').length, 1);
      });

      const stringState = state();
      const previousDirectory = process.cwd();
      try {
        // A string is a filesystem path.  Unix permits both ':' and '?' in a
        // filename, so a file: prefix must not be interpreted as a URL scheme.
        process.chdir(directory);
        const relativeFilename = 'file:literal?name.txt';
        fs.writeFileSync(relativeFilename, 'string-file-value', 'utf8');
        run(stringState, () => {
          const marks = markedSlice(
            stringState,
            relativeFilename,
            'http.query',
            'file.string-query',
            relativeFilename.indexOf('?')
          );
          const result = invokeValue(
            fs.readFileSync,
            fs,
            [
              [relativeFilename, marks],
              ['utf8', []],
            ],
            'adapter#file-string-query-read'
          );
          assert.equal(result.v, 'string-file-value');
          assert.equal(fileFindings(stringState, 'read', 'source').length, 1);
        });
      } finally {
        process.chdir(previousDirectory);
        fs.rmSync(path.join(directory, 'file:literal?name.txt'), {
          force: true,
        });
      }
    } finally {
      fs.rmSync(directory, { recursive: true, force: true });
    }
  }
);

test(
  'ordinary execFile argv stays command_execution while sh -c is shell injection',
  { concurrency: false },
  () => {
    const ordinary = state();
    try {
      bind(ordinary, () => {
        const input = 'ordinary-argv';
        const inputMarks = markedSlice(
          ordinary,
          input,
          'http.header',
          'child.argument'
        );
        const argv = ['-e', 'process.stdout.write(process.argv[1])', input];
        ordinary.putField(argv, '2', inputMarks);
        const output = invokeValue(
          childProcess.execFileSync,
          childProcess,
          [
            [process.execPath, []],
            [argv, []],
            [{ encoding: 'utf8' }, []],
          ],
          'adapter#execFile-argv'
        );
        assert.equal(output.v, input);
        assert.equal(
          findings(ordinary, 'command_execution', 'argument').length,
          1
        );
        assert.equal(
          findings(ordinary, 'command_injection', 'shell_script').length,
          0
        );
      });
    } finally {
      ordinary.close();
    }

    const shell = state();
    try {
      bind(shell, () => {
        const input = 'controlled-input';
        const script = `printf 'prefix:${input}'`;
        const scriptMarks = markedSlice(
          shell,
          script,
          'http.query',
          'shell.script',
          script.indexOf(input),
          script.length
        );
        const argv = ['-c', script];
        shell.putField(argv, '1', scriptMarks);
        const output = invokeValue(
          childProcess.execFileSync,
          childProcess,
          [
            ['/bin/sh', []],
            [argv, []],
            [{ encoding: 'utf8' }, []],
          ],
          'adapter#sh-c'
        );
        assert.equal(output.v, `prefix:${input}`);
        assert.equal(
          findings(shell, 'command_execution', 'argument').length,
          1
        );
        assert.equal(
          findings(shell, 'command_injection', 'shell_script').length,
          1
        );
        assert.equal(
          findings(shell, 'command_injection', 'shell_script')[0].sink.role,
          'shell_script'
        );
      });
    } finally {
      shell.close();
    }
  }
);

test(
  'standard promisify keeps the execFile sink argument contract',
  { concurrency: false },
  async () => {
    const current = state();
    try {
      await bind(current, async () => {
        const promisedExecFile = invokeValue(
          promisify,
          undefined,
          [[childProcess.execFile, []]],
          'adapter#promisify'
        ).v;
        const argument = 'promisified-argv';
        const marks = markedSlice(
          current,
          argument,
          'http.header',
          'promisified.argument'
        );
        const argv = ['-e', 'process.stdout.write(process.argv[1])', argument];
        current.putField(argv, '2', marks);
        const result = invokeValue(
          promisedExecFile,
          undefined,
          [
            [process.execPath, []],
            [argv, []],
            [{ encoding: 'utf8' }, []],
          ],
          'adapter#promisified-execFile'
        );
        const output = await result.v;
        assert.equal(output.stdout, argument);
      });
      assert.equal(
        findings(current, 'command_execution', 'argument').length,
        1
      );
      assert.equal(
        findings(current, 'command_injection', 'shell_script').length,
        0
      );
    } finally {
      current.close();
    }
  }
);

test(
  'HTTP options override URL fields and fetch init does not become a destination',
  { concurrency: false },
  async () => {
    const server = http.createServer((_request, response) =>
      response.end('adapter-http-value')
    );
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    const port = server.address().port;
    const current = state();
    try {
      await bind(current, async () => {
        const taintedUrl = `http://tainted.example:${port}/tainted?from=source`;
        const urlMarks = markedSlice(
          current,
          taintedUrl,
          'http.input',
          'http.url'
        );
        const options = { hostname: '127.0.0.1', port, path: '/constant' };
        const status = await new Promise((resolve, reject) => {
          const request = invokeValue(
            http.request,
            http,
            [
              [taintedUrl, urlMarks],
              [options, []],
            ],
            'adapter#http-options-override'
          ).v;
          request.once('error', reject);
          request.once('response', response => {
            response.resume();
            response.once('end', () => resolve(response.statusCode));
          });
          request.end();
        });
        assert.equal(status, 200);

        const init = { hostname: 'tainted.example', path: '/tainted' };
        const initHost = markedSlice(
          current,
          init.hostname,
          'http.input',
          'fetch.init.hostname'
        );
        const initPath = markedSlice(
          current,
          init.path,
          'http.input',
          'fetch.init.path'
        );
        current.putField(init, 'hostname', initHost);
        current.putField(init, 'path', initPath);
        const fetched = invokeValue(
          globalThis.fetch,
          undefined,
          [
            [`http://127.0.0.1:${port}/constant`, []],
            [init, []],
          ],
          'adapter#fetch-init-options'
        ).v;
        const response = await fetched;
        assert.equal(response.status, 200);
        await response.text();
      });
      assert.equal(findings(current, 'ssrf', 'destination_address').length, 0);
      assert.equal(inputFindings(current, 'path').length, 0);
      assert.equal(inputFindings(current, 'query').length, 0);
    } finally {
      current.close();
      await new Promise(resolve => server.close(() => resolve()));
    }
  }
);

test(
  'SQL config marks use only the driver SQL text field',
  { concurrency: false },
  () => {
    class FakePgClient {
      query(value) {
        return value;
      }
    }
    class FakeMysqlConnection {
      execute(value) {
        return value;
      }
    }
    installLibrary('pg', { Client: FakePgClient });
    installLibrary('mysql2', { PromiseConnection: FakeMysqlConnection });

    const current = state();
    run(current, () => {
      const taintedText = 'select tainted';
      const textMarks = markedSlice(
        current,
        taintedText,
        'http.request.body',
        'sql.text'
      );
      const pg = new FakePgClient();
      const pgConfig = { text: taintedText, sql: 'select constant' };
      current.putField(pgConfig, 'text', textMarks);
      invokeValue(
        FakePgClient.prototype.query,
        pg,
        [[pgConfig, []]],
        'adapter#pg-config-text'
      );
      assert.equal(
        findings(current, 'sql_injection', 'sql_template').length,
        1
      );

      const pgUnrelated = { text: 'select constant', sql: taintedText };
      current.putField(pgUnrelated, 'sql', textMarks);
      invokeValue(
        FakePgClient.prototype.query,
        pg,
        [[pgUnrelated, []]],
        'adapter#pg-config-unrelated'
      );
      assert.equal(
        findings(current, 'sql_injection', 'sql_template').length,
        1
      );

      const mysql = new FakeMysqlConnection();
      const mysqlConfig = { sql: taintedText, text: 'select constant' };
      current.putField(mysqlConfig, 'sql', textMarks);
      invokeValue(
        FakeMysqlConnection.prototype.execute,
        mysql,
        [[mysqlConfig, []]],
        'adapter#mysql-config-sql'
      );
      assert.equal(
        findings(current, 'sql_injection', 'sql_template').length,
        2
      );

      const mysqlUnrelated = { sql: 'select constant', text: taintedText };
      current.putField(mysqlUnrelated, 'text', textMarks);
      invokeValue(
        FakeMysqlConnection.prototype.execute,
        mysql,
        [[mysqlUnrelated, []]],
        'adapter#mysql-config-unrelated'
      );
      assert.equal(
        findings(current, 'sql_injection', 'sql_template').length,
        2
      );
    });
  }
);
