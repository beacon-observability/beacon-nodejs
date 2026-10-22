import assert from 'node:assert/strict';
import { constants } from 'node:fs';
import test from 'node:test';
import { installLibrary } from '../src/adapters/sinks.mjs';
import { SecurityState } from '../src/core/state.mjs';
import { bind } from '../src/core/runtime.mjs';
import { p } from '../src/core/values.mjs';
import { invoke } from '../src/core/calls.mjs';

const identity = {
  application_id: 'adapter-regression',
  instance_id: 'adapter-regression',
};
const processes = {
  spawnSync(file, argv) {
    return { file, argv };
  },
};
installLibrary('node:child_process', processes);

test('explicit shell options distinguish command strings from script operands', () => {
  const script = 'echo guest; id';
  for (const [executable, argv, expected] of [
    ['/bin/bash', ['-lc', script], 'suspected'],
    ['/bin/sh', ['-ec', script], 'suspected'],
    ['/bin/bash', ['--noprofile', '-lc', script], 'suspected'],
    ['/bin/bash', ['-o', 'errexit', '-c', script], 'suspected'],
    ['/bin/bash', ['script.sh', '-c', script], null],
    ['/bin/bash', ['--', '-c', script], null],
    ['/bin/bash', ['-o', 'c', script], null],
    ['cmd.exe', ['/C', script], 'unknown'],
    ['cmd.exe', ['/D', '/C', script], 'unknown'],
    ['powershell.exe', ['-File', 'script.ps1', '-Command', script], null],
  ]) {
    const state = new SecurityState(identity);
    state.putField(
      argv,
      String(argv.length - 1),
      state.source(script, 'http.request.parameter', 'q')
    );
    try {
      bind(state, () => {
        const result = invoke(
          { v: processes.spawnSync, receiver: p(processes) },
          [p(executable), p(argv)]
        );
        assert.equal(result.v.argv, argv);
      });
      const finding = state.pending.find(
        event => event.rule === 'command_injection'
      );
      assert.equal(
        finding?.attack_evidence.status ?? null,
        expected,
        JSON.stringify(argv)
      );
    } finally {
      state.close();
    }
  }
});

test('filesystem destination and numeric flags retain canonical operation dimensions', () => {
  const callback = {
    symlink(...args) {
      return args;
    },
    symlinkSync(...args) {
      return args;
    },
    open(...args) {
      return args;
    },
    openSync(...args) {
      return args;
    },
  };
  const promises = {
    symlink(...args) {
      return args;
    },
    open(...args) {
      return args;
    },
  };
  installLibrary('node:fs', callback);
  installLibrary('node:fs/promises', promises);
  for (const [root, method] of [
    [callback, 'symlink'],
    [callback, 'symlinkSync'],
    [promises, 'symlink'],
  ]) {
    const state = new SecurityState(identity);
    try {
      bind(state, () =>
        invoke({ v: root[method], receiver: p(root) }, [
          p('constant-link-contents'),
          p(
            '/synthetic/link',
            state.source('/synthetic/link', 'http.request.parameter', 'link')
          ),
          p(() => {}),
        ])
      );
      assert.equal(state.pending.length, 1);
      assert.equal(state.pending[0].sink.operation, 'write');
      assert.equal(state.pending[0].sink.path_role, 'target');
    } finally {
      state.close();
    }
  }
  for (const [flags, operation, pathRole] of [
    [constants.O_RDONLY, 'read', 'source'],
    [constants.O_WRONLY | constants.O_CREAT, 'write', 'target'],
    [constants.O_RDWR, 'write', 'target'],
    ['r', 'read', 'source'],
    ['r+', 'write', 'target'],
    ['wx', 'write', 'target'],
  ]) {
    for (const [root, method] of [
      [callback, 'open'],
      [callback, 'openSync'],
      [promises, 'open'],
    ]) {
      const state = new SecurityState(identity);
      try {
        bind(state, () =>
          invoke({ v: root[method], receiver: p(root) }, [
            p(
              '/synthetic/path',
              state.source('/synthetic/path', 'http.request.parameter', 'path')
            ),
            p(flags),
            p(() => {}),
          ])
        );
        assert.equal(state.pending[0].sink.operation, operation);
        assert.equal(state.pending[0].sink.path_role, pathRole);
      } finally {
        state.close();
      }
    }
  }
});
