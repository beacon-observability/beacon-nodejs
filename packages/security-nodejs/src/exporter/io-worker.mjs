import { mkdir, open, readFile, rename, stat, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { parentPort } from 'node:worker_threads';

if (!parentPort) {
  throw new Error('security exporter I/O worker requires parentPort');
}

const MAX_CONTROL_BYTES = 256 * 1024;
let evidencePath = '';
let rotateBytes = 10 * 1024 * 1024;
let backups = 3;
let evidenceBytes = 0;
let snapshot;
let committedRuns = new Map();

function encode(value) {
  return JSON.stringify(value, (_key, item) =>
    item instanceof Set
      ? [...item]
      : typeof item === 'bigint'
        ? `${item}n`
        : item
  );
}

function errorText(error) {
  const name = error && error.name ? String(error.name) : 'Error';
  const message = error && error.message ? `:${String(error.message)}` : '';
  return `${name}${message}`.slice(0, 256);
}

async function ensureParent(path) {
  await mkdir(dirname(path), { recursive: true });
}

async function initialize(value) {
  evidencePath =
    typeof value.evidencePath === 'string' ? value.evidencePath : '';
  rotateBytes = Math.max(1, Number(value.rotateBytes) || rotateBytes);
  backups = Math.min(20, Math.max(1, Number(value.backups) || backups));
  if (evidencePath) {
    await ensureParent(evidencePath);
    try {
      evidenceBytes = (await stat(evidencePath)).size;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      evidenceBytes = 0;
    }
  }
  return { initialized: true };
}

async function readControl(value) {
  const path = String(value.path || '');
  if (!path) return { exists: false };
  let bytes;
  try {
    const info = await stat(path);
    if (info.size > MAX_CONTROL_BYTES) throw new Error('control_byte_limit');
    bytes = await readFile(path);
  } catch (error) {
    if (error?.code === 'ENOENT') return { exists: false };
    throw error;
  }
  if (bytes.byteLength > MAX_CONTROL_BYTES)
    throw new Error('control_byte_limit');
  return { exists: true, value: JSON.parse(bytes.toString('utf8')) };
}

async function writeAtomic(value) {
  const path = String(value.path || '');
  if (!path) throw new Error('snapshot_path_required');
  await ensureParent(path);
  const temporary = join(
    dirname(path),
    `.security-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.tmp`
  );
  const handle = await open(temporary, 'wx');
  try {
    await handle.writeFile(String(value.contents ?? ''), 'utf8');
    await handle.sync();
  } finally {
    await handle.close();
  }
  try {
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return { path };
}

async function rotate() {
  if (!evidencePath) return;
  for (let index = backups; index >= 1; index -= 1) {
    const destination = `${evidencePath}.${index}`;
    const source = index === 1 ? evidencePath : `${evidencePath}.${index - 1}`;
    await rename(source, destination).catch(error => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }
  evidenceBytes = 0;
}

async function appendEvidence(value) {
  if (!evidencePath) return { written: false };
  const line = String(value.line ?? '') + '\n';
  await ensureParent(evidencePath);
  if (evidenceBytes + Buffer.byteLength(line) > rotateBytes) await rotate();
  const handle = await open(evidencePath, 'a');
  try {
    await handle.writeFile(line, 'utf8');
    // This is deliberately a flush/close, not an fsync contract.
  } finally {
    await handle.close();
  }
  evidenceBytes += Buffer.byteLength(line);
  return { written: true, bytes: evidenceBytes };
}

async function handle(message) {
  const { id, operation, value = {} } = message || {};
  try {
    let result;
    if (operation === 'initialize') result = await initialize(value);
    else if (operation === 'read-control') result = await readControl(value);
    else if (operation === 'write-atomic') result = await writeAtomic(value);
    else if (operation === 'write-json')
      result = await writeAtomic({
        path: value.path,
        contents: encode(value.value) + '\n',
      });
    else if (operation === 'snapshot-begin') {
      snapshot = { ...value, records: [] };
      result = { started: true };
    } else if (operation === 'snapshot-row') {
      if (!snapshot) throw new Error('snapshot_not_started');
      const record =
        value.record ||
        (snapshot.key === 'runs' && committedRuns.get(value.runId));
      if (!record) throw new Error('snapshot_row_missing');
      snapshot.records.push(record);
      result = { received: true };
    } else if (operation === 'snapshot-commit') {
      if (!snapshot) throw new Error('snapshot_not_started');
      const pending = snapshot;
      snapshot = undefined;
      result = await writeAtomic({
        path: pending.path,
        contents:
          encode({ ...pending.envelope, [pending.key]: pending.records }) +
          '\n',
      });
      if (pending.key === 'runs')
        committedRuns = new Map(
          pending.records.map(record => [record.run_id, record])
        );
    } else if (operation === 'append-evidence')
      result = await appendEvidence(value);
    else if (operation === 'close') result = { closed: true };
    else throw new Error(`unknown_io_operation:${String(operation)}`);
    parentPort.postMessage({ id, ok: true, result });
    if (operation === 'close') setImmediate(() => process.exit(0));
  } catch (error) {
    parentPort.postMessage({ id, ok: false, error: errorText(error) });
  }
}

let operationChain = Promise.resolve();
parentPort.on('message', message => {
  // Keep atomic snapshots and log rotation ordered without a lock. The parent
  // posts from one event loop, but each operation itself is asynchronous.
  operationChain = operationChain
    .then(() => handle(message))
    .catch(error => {
      parentPort.postMessage({
        id: message?.id,
        ok: false,
        error: errorText(error),
      });
    });
});
