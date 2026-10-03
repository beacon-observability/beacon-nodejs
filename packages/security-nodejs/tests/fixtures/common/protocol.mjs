import { once } from 'node:events';

export function emitLine(kind, value) {
  process.stdout.write(`${kind} ${JSON.stringify(value)}\n`);
}

export function emitResult(value) {
  emitLine('BEACON_SECURITY_QA_RESULT', value);
}

export function emitReady(value) {
  emitLine('BEACON_SECURITY_QA_READY', value);
}

export function emitOtel(value) {
  emitLine('BEACON_SECURITY_QA_OTEL', value);
}

export async function waitForClose(server) {
  if (!server.listening) return;
  await once(server, 'close');
}

export function jsonResponse(res, statusCode, value) {
  const body = JSON.stringify(value);
  res.statusCode = statusCode;
  res.setHeader('content-type', 'application/json; charset=utf-8');
  res.setHeader('content-length', Buffer.byteLength(body));
  res.end(body);
}

export function readUrl(request) {
  const host = request.headers.host || '127.0.0.1';
  return new URL(request.url || '/', `http://${host}`);
}
