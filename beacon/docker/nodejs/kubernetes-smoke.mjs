import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const [context, image, version] = process.argv.slice(2);
assert(
  context && image && version,
  'Usage: node kubernetes-smoke.mjs <context> <image> <X.Y.Z>'
);
assert.match(version, /^\d+\.\d+\.\d+$/);
const namespace = `beacon-nodejs-image-${Date.now().toString(36)}-${process.pid}`;
const runtime =
  process.env.BEACON_K8S_NODE_IMAGE ||
  'node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205';
function kubectl(args, input, allowFailure = false) {
  const result = spawnSync(
    'kubectl',
    ['--context', context, '--namespace', namespace, ...args],
    { encoding: 'utf8', input, timeout: 760000, maxBuffer: 4 * 1024 * 1024 }
  );
  if (!allowFailure && (result.error || result.status !== 0))
    throw new Error(
      `kubectl ${args.join(' ')}: ${result.error || result.stderr || result.stdout}`
    );
  return result.stdout || '';
}
const restricted = {
  runAsNonRoot: true,
  runAsUser: 65532,
  runAsGroup: 65532,
  allowPrivilegeEscalation: false,
  readOnlyRootFilesystem: true,
  capabilities: { drop: ['ALL'] },
  seccompProfile: { type: 'RuntimeDefault' },
};
let created = false;
try {
  console.log(`Testing ${image} on ${context}, namespace ${namespace}`);
  kubectl(['create', 'namespace', namespace]);
  created = true;
  const objects = [
    {
      apiVersion: 'v1',
      kind: 'ConfigMap',
      metadata: { name: 'fixture' },
      data: Object.fromEntries(
        ['smoke.mjs', 'fixture.cjs'].map(name => [
          name,
          readFileSync(join(here, name), 'utf8'),
        ])
      ),
    },
    {
      apiVersion: 'batch/v1',
      kind: 'Job',
      metadata: { name: 'application' },
      spec: {
        backoffLimit: 0,
        activeDeadlineSeconds: 600,
        template: {
          spec: {
            restartPolicy: 'Never',
            automountServiceAccountToken: false,
            securityContext: { fsGroup: 65532 },
            initContainers: [
              {
                name: 'beacon-nodejs',
                image,
                imagePullPolicy: 'IfNotPresent',
                command: ['sh', '-ec', 'cp -R /opt/beacon-nodejs/. /beacon/'],
                securityContext: restricted,
                resources: {
                  requests: { cpu: '10m', memory: '32Mi' },
                  limits: { memory: '128Mi' },
                },
                volumeMounts: [{ name: 'agent', mountPath: '/beacon' }],
              },
            ],
            containers: [
              {
                name: 'application',
                image: runtime,
                command: [
                  'node',
                  '/fixture/smoke.mjs',
                  '/opt/beacon-nodejs',
                  version,
                ],
                securityContext: restricted,
                resources: {
                  requests: { cpu: '100m', memory: '256Mi' },
                  limits: { cpu: '2', memory: '1Gi' },
                },
                volumeMounts: [
                  {
                    name: 'agent',
                    mountPath: '/opt/beacon-nodejs',
                    readOnly: true,
                  },
                  { name: 'fixture', mountPath: '/fixture', readOnly: true },
                  { name: 'tmp', mountPath: '/tmp' },
                ],
              },
            ],
            volumes: [
              { name: 'agent', emptyDir: {} },
              { name: 'fixture', configMap: { name: 'fixture' } },
              { name: 'tmp', emptyDir: {} },
            ],
          },
        },
      },
    },
  ];
  kubectl(
    ['apply', '-f', '-'],
    JSON.stringify({ apiVersion: 'v1', kind: 'List', items: objects })
  );
  kubectl([
    'wait',
    '--for=condition=complete',
    'job/application',
    '--timeout=620s',
  ]);
  const logs = kubectl(['logs', 'job/application', '-c', 'application']);
  process.stdout.write(logs);
  assert(logs.includes('PASS: CommonJS') && logs.includes('PASS: ESM'));
  console.log(
    `PASS: Kubernetes initContainer, read-only non-root application, Beacon ${version}, correlated OTLP traces, native profiles and Security SBOM.`
  );
} catch (error) {
  if (created) {
    process.stderr.write(
      kubectl(['get', 'pods', '-o', 'wide'], undefined, true)
    );
    process.stderr.write(kubectl(['describe', 'pods'], undefined, true));
    process.stderr.write(
      kubectl(
        ['logs', 'job/application', '--all-containers=true'],
        undefined,
        true
      )
    );
  }
  console.error(error);
  process.exitCode = 1;
} finally {
  if (created)
    console.log(kubectl(['delete', 'namespace', namespace, '--wait=false']));
}
