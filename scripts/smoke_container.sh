#!/usr/bin/env bash
# Smoke test of the container image: starts it in OAuth mode with the memory store (no
# cloud, no secrets) and checks the endpoints a platform and an AI client depend on.
#
#   podman build -t uem-smoke --build-arg EXTRAS=gcp .
#   scripts/smoke_container.sh uem-smoke            # ENGINE=docker to use docker
set -euo pipefail

image="${1:?usage: smoke_container.sh IMAGE}"
engine="${ENGINE:-$(command -v podman >/dev/null && echo podman || echo docker)}"
port="${SMOKE_PORT:-18080}"
name="uem-smoke-$$"
base="http://127.0.0.1:${port}"

cleanup() {
  if [[ "${rc:-0}" != 0 ]]; then "$engine" logs "$name" 2>&1 | tail -40 || true; fi
  "$engine" rm -f "$name" >/dev/null 2>&1 || true
}
rc=0
trap 'rc=$?; cleanup' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

"$engine" run -d --name "$name" -p "127.0.0.1:${port}:8080" \
  -e STORE_BACKEND=memory \
  -e PUBLIC_URL=http://localhost:8080 \
  -e LOGIN_DOMAINS=example.org=mail.example.org \
  -e MAIL_SERVERS=mail.example.org \
  -e CONTENT_ORIGIN= \
  "$image" >/dev/null

for _ in $(seq 1 40); do
  curl -fs "${base}/health" >/dev/null 2>&1 && break
  sleep 0.5
done

# Requests carry the Host of PUBLIC_URL (other hosts get 421, tested below).
host=(-H 'Host: localhost:8080')
code() { curl -s -o /dev/null -w '%{http_code}' "${host[@]}" "$@"; }

[[ "$(code "${base}/health")" == 200 ]] || fail "/health is not 200"
[[ "$(code "${base}/ready")" == 200 ]] || fail "/ready is not 200"

# OAuth mode: /mcp without a token is refused and points at the resource metadata.
headers="$(curl -s -D - -o /dev/null "${host[@]}" -X POST -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' -d '{}' "${base}/mcp")"
grep -q '^HTTP/[0-9.]* 401' <<<"$headers" || fail "/mcp without a token is not 401"
grep -qi '^www-authenticate: *bearer.*resource_metadata=' <<<"$headers" \
  || fail "/mcp 401 lacks WWW-Authenticate with resource_metadata"

[[ "$(code "${base}/.well-known/oauth-authorization-server")" == 200 ]] \
  || fail "authorization server metadata missing"
[[ "$(code "${base}/portal")" =~ ^(200|302|303)$ ]] || fail "/portal does not answer"

# A foreign Host header is refused (DNS rebinding protection) ...
[[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' "${base}/portal")" == 421 ]] \
  || fail "foreign Host header is not rejected with 421"
# ... but probes are exempt.
[[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: 10.0.0.1:8080' "${base}/health")" == 200 ]] \
  || fail "/health must answer for any Host"

# Unprivileged user, as in production.
uid="$("$engine" exec "$name" id -u)"
[[ "$uid" == 10001 ]] || fail "container runs as uid ${uid}, expected 10001"

echo "smoke test passed"
