#!/usr/bin/env bash
set -euo pipefail

nodejs_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
network_name="security-node-db-${RANDOM}-${RANDOM}"
result_dir=${BEACON_SECURITY_QA_DB_RESULTS_DIR:-/tmp/beacon_security-nodejs-db-results}
node_image=${BEACON_SECURITY_QA_NODE_IMAGE:-node:24-bookworm}
pg_image=${BEACON_SECURITY_QA_PG_IMAGE:-postgres:16-alpine}
mysql_image=${BEACON_SECURITY_QA_MYSQL_IMAGE:-mysql:8.4.11}
node_cache=${BEACON_SECURITY_QA_NPM_CACHE:-/tmp/beacon_security-nodejs-npm-cache}
mkdir -p "$result_dir" "$node_cache"

docker network create "$network_name" >/dev/null
pg_id=''
mysql_id=''
cleanup() {
  if [[ -n "$pg_id" ]]; then docker rm -f "$pg_id" >/dev/null 2>&1 || true; fi
  if [[ -n "$mysql_id" ]]; then docker rm -f "$mysql_id" >/dev/null 2>&1 || true; fi
  docker network rm "$network_name" >/dev/null 2>&1 || true
}
trap cleanup EXIT

pg_id=$(docker run -d --rm --name "${network_name}-postgres" --network "$network_name" --cpus=1 --memory=384m \
  -e POSTGRES_USER=qa -e POSTGRES_PASSWORD=qa -e POSTGRES_DB=qa "$pg_image")
mysql_id=$(docker run -d --rm --name "${network_name}-mysql" --network "$network_name" --cpus=1 --memory=512m \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=qa -e MYSQL_USER=qa -e MYSQL_PASSWORD=qa "$mysql_image")

for attempt in $(seq 1 60); do
  if docker exec "$pg_id" pg_isready -U qa -d qa >/dev/null 2>&1; then break; fi
  if [[ "$attempt" -eq 60 ]]; then echo 'postgres did not become ready' >&2; exit 1; fi
  sleep 1
done
for attempt in $(seq 1 60); do
  if docker exec "$mysql_id" mysqladmin ping -h127.0.0.1 -uqa -pqa --silent >/dev/null 2>&1; then break; fi
  if [[ "$attempt" -eq 60 ]]; then echo 'mysql did not become ready' >&2; exit 1; fi
  sleep 1
done

docker run --rm --network "$network_name" --cpus=1 --memory=512m \
  -v "$nodejs_root:/workspace/nodejs:ro" \
  -v "$result_dir:/results" \
  -v "$node_cache:/npm-cache" \
  -w /workspace/nodejs "$node_image" sh -eu -c '
    rm -rf /tmp/beacon_security-nodejs
    cp -a /workspace/nodejs /tmp/beacon_security-nodejs
    cd /tmp/beacon_security-nodejs
    if [ -d node_modules/pg ] && [ -d node_modules/mysql2 ] && [ -d node_modules/express ]; then
      echo "reusing mounted node_modules" >&2
    elif [ -f package-lock.json ]; then
      node --use-system-ca /usr/local/bin/npm ci --ignore-scripts --cache /npm-cache
    else
      node --use-system-ca /usr/local/bin/npm install --ignore-scripts --cache /npm-cache
    fi
    BEACON_SECURITY_NODE_INCLUDE=/tmp/beacon_security-nodejs/tests/integration/database \
    BEACON_SECURITY_ENABLED=true BEACON_SECURITY_LOCAL_OUTPUT_ENABLED=true \
    BEACON_SECURITY_SBOM_ENABLED=false BEACON_SECURITY_OUTPUT=/results/security-output \
    BEACON_SECURITY_QA_PG_URL=postgresql://qa:qa@'"${network_name}"'-postgres:5432/qa \
    BEACON_SECURITY_QA_MYSQL_URL=mysql://qa:qa@'"${network_name}"'-mysql:3306/qa \
    node --import @beacon-observability/security-nodejs/register \
      --import ./tests/fixtures/otel-bootstrap.mjs \
      ./tests/integration/database/query.mjs > /results/database-result.json
  '

grep -q '"status":"pass"' "$result_dir/database-result.json"
echo "database_result=$result_dir/database-result.json"
