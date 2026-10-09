#!/usr/bin/env bash
# Render deploy/gcp/service.yaml: replaces every __NAME__ placeholder with the value of
# the environment variable NAME and writes the result to stdout (or to the file $1).
# Used by cloudbuild.yaml; run it by hand to see what would be applied:
#
#   SERVICE=uem IMAGE=... RUNTIME_SA=... PROJECT_ID=... PUBLIC_URL=... LOGIN_DOMAINS=... \
#     deploy/gcp/render.sh > /tmp/service.yaml
#
# Values must not contain newlines, double quotes or backslashes. Secrets never pass through here.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
template="${TEMPLATE:-$here/service.yaml}"

: "${SERVICE:?}" "${IMAGE:?}" "${RUNTIME_SA:?}" "${PROJECT_ID:?}" "${PUBLIC_URL:?}"
: "${LOGIN_DOMAINS:?}"
export INGRESS="${INGRESS:-all}"
export MIN_INSTANCES="${MIN_INSTANCES:-0}"
export MAX_INSTANCES="${MAX_INSTANCES:-3}"
export MAIL_SERVERS="${MAIL_SERVERS:-}"
export CONTENT_ORIGIN="${CONTENT_ORIGIN:-}"
export FIRESTORE_PREFIX="${FIRESTORE_PREFIX:-}"
export TRUSTED_PROXY_HOPS="${TRUSTED_PROXY_HOPS:-1}"
export NETWORK="${NETWORK:-}" SUBNET="${SUBNET:-}"
export FIRESTORE_DATABASE="${FIRESTORE_DATABASE:-(default)}"
export STORE_ACTIVE_KEY="${STORE_ACTIVE_KEY:-}"
shopt -u patsub_replacement 2>/dev/null || true   # bash 5.2: "&" in a value is literal

# Comment lines are dropped first: they mention placeholders only as prose.
out="$(grep -v '^[[:space:]]*#' "$template")"
for name in SERVICE IMAGE RUNTIME_SA PROJECT_ID PUBLIC_URL LOGIN_DOMAINS INGRESS \
  MIN_INSTANCES MAX_INSTANCES MAIL_SERVERS CONTENT_ORIGIN FIRESTORE_PREFIX \
  TRUSTED_PROXY_HOPS NETWORK SUBNET FIRESTORE_DATABASE STORE_ACTIVE_KEY; do
  value="${!name}"
  # Values land in double-quoted YAML scalars.
  case "$value" in
    *\"* | *\\*) echo "render.sh: $name contains a quote or backslash" >&2; exit 1 ;;
  esac
  out="${out//__${name}__/${value}}"
done

if left="$(grep -o '__[A-Z_]*__' <<<"$out")"; then
  echo "render.sh: unreplaced placeholder(s):" >&2
  sort -u <<<"$left" >&2
  exit 1
fi
if [[ -n "${1:-}" ]]; then printf '%s\n' "$out" >"$1"; else printf '%s\n' "$out"; fi
