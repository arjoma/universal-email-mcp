#!/usr/bin/env bash
# One-time (and safely repeatable) setup of an empty Google Cloud project for
# universal-email-mcp: APIs, service accounts with least privilege, Artifact Registry,
# Firestore (native mode) with TTL policies, and the secrets with freshly generated keys.
#
#   PROJECT_ID=my-project REGION=europe-west1 deploy/gcp/bootstrap.sh
#
# Idempotent: every step checks first and does nothing if the thing exists. Existing
# secrets are never overwritten, and no secret value is ever printed (keys go straight
# from openssl into Secret Manager). Review the script before running it; it changes IAM.
#
# Settings (environment variables):
#   PROJECT_ID           required
#   REGION               Cloud Run / Artifact Registry / secrets region, e.g. europe-west1
#   FIRESTORE_LOCATION   Firestore location, e.g. eur3 (multi-region) or europe-west1;
#                        fixed forever once the database exists. Default: REGION
#   FIRESTORE_DATABASE   default: (default)
#   FIRESTORE_PREFIX     collection name prefix (must match the service), default empty
#   REPO                 Artifact Registry repository, default universal-email-mcp
#   RUNTIME_SA, BUILD_SA service account names, default uem-runtime / uem-build
#   STORE_KEYS_SECRET, PSEUDONYM_KEY_SECRET   secret names, default uem-store-keys /
#                        uem-pseudonym-key (must match deploy/gcp/service.yaml)
#   DRY_RUN=1            print the gcloud commands instead of running them
set -euo pipefail

: "${PROJECT_ID:?set PROJECT_ID}"
: "${REGION:?set REGION}"
FIRESTORE_LOCATION="${FIRESTORE_LOCATION:-$REGION}"
FIRESTORE_DATABASE="${FIRESTORE_DATABASE:-(default)}"
FIRESTORE_PREFIX="${FIRESTORE_PREFIX:-}"
REPO="${REPO:-universal-email-mcp}"
RUNTIME_SA="${RUNTIME_SA:-uem-runtime}"
BUILD_SA="${BUILD_SA:-uem-build}"
STORE_KEYS_SECRET="${STORE_KEYS_SECRET:-uem-store-keys}"
PSEUDONYM_KEY_SECRET="${PSEUDONYM_KEY_SECRET:-uem-pseudonym-key}"
DRY_RUN="${DRY_RUN:-0}"

runtime_email="${RUNTIME_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
build_email="${BUILD_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
source_bucket="${PROJECT_ID}-uem-build-src"

# Collections with a TTL policy on `expires_at` (docs/stored-data.md).
TTL_COLLECTIONS=(portal_sessions oauth_clients auth_codes grants tokens approvals activity)

say() { printf '==> %s\n' "$*"; }

# g: run gcloud against the project (or just show the command).
g() {
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '[dry-run] gcloud %s --project %s\n' "$*" "$PROJECT_ID"
  else
    gcloud "$@" --project "$PROJECT_ID" --quiet >/dev/null
  fi
}

# q: quiet existence probe; in a dry run nothing "exists", so every step is shown.
q() {
  [[ "$DRY_RUN" == 1 ]] && return 1
  gcloud "$@" --project "$PROJECT_ID" >/dev/null 2>&1
}

say "Enabling APIs"
g services enable \
  run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com \
  firestore.googleapis.com secretmanager.googleapis.com logging.googleapis.com \
  monitoring.googleapis.com iam.googleapis.com

say "Service accounts"
for sa in "$RUNTIME_SA" "$BUILD_SA"; do
  if ! q iam service-accounts describe "${sa}@${PROJECT_ID}.iam.gserviceaccount.com"; then
    g iam service-accounts create "$sa" --display-name "universal-email-mcp ${sa}"
  fi
done

say "Artifact Registry repository ${REPO}"
if ! q artifacts repositories describe "$REPO" --location "$REGION"; then
  g artifacts repositories create "$REPO" --repository-format docker --location "$REGION" \
    --description "universal-email-mcp images"
fi

say "Source staging bucket for Cloud Build (gs://${source_bucket})"
if ! q storage buckets describe "gs://${source_bucket}"; then
  g storage buckets create "gs://${source_bucket}" --location "$REGION" \
    --uniform-bucket-level-access --public-access-prevention
fi

say "Firestore database ${FIRESTORE_DATABASE} (native mode, ${FIRESTORE_LOCATION})"
if ! q firestore databases describe --database "$FIRESTORE_DATABASE"; then
  # Delete protection and point-in-time recovery (7 days) are on from the start.
  g firestore databases create --database "$FIRESTORE_DATABASE" \
    --location "$FIRESTORE_LOCATION" --type firestore-native \
    --delete-protection --enable-pitr
fi

say "Firestore TTL policies on expires_at"
for c in "${TTL_COLLECTIONS[@]}"; do
  g firestore fields ttls update expires_at --database "$FIRESTORE_DATABASE" \
    --collection-group "${FIRESTORE_PREFIX}${c}" --enable-ttl --async
done

say "Secrets (generated once, never printed)"
ensure_secret() { # name, generator-function
  local name="$1" gen="$2"
  if ! q secrets describe "$name"; then
    g secrets create "$name" --replication-policy user-managed --locations "$REGION"
  fi
  if [[ "$DRY_RUN" == 1 ]]; then
    printf '[dry-run] generate a value and add it as the first version of %s\n' "$name"
  else
    # A failing list aborts the script (set -e): never treat an error as "no version".
    local existing value
    existing="$(gcloud secrets versions list "$name" --project "$PROJECT_ID" --limit 1 \
      --format 'value(name)')"
    if [[ -n "$existing" ]]; then
      echo "    ${name} already has a version; left untouched"
    else
      value="$("$gen")"
      [[ -n "$value" ]] || { echo "key generation failed" >&2; exit 1; }
      printf '%s' "$value" | gcloud secrets versions add "$name" --project "$PROJECT_ID" \
        --data-file=- --quiet >/dev/null
      echo "    created the first version of ${name}"
    fi
  fi
}
gen_store_keys() { printf 'k1=%s' "$(openssl rand -base64 32)"; }
gen_pseudonym_key() { openssl rand -base64 48 | tr -d '\n'; }
ensure_secret "$STORE_KEYS_SECRET" gen_store_keys
ensure_secret "$PSEUDONYM_KEY_SECRET" gen_pseudonym_key

say "IAM: runtime service account (${runtime_email})"
# Firestore read/write; nothing else. The runtime account may read exactly the two secrets.
g projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:${runtime_email}" \
  --role roles/datastore.user --condition=None
for s in "$STORE_KEYS_SECRET" "$PSEUDONYM_KEY_SECRET"; do
  g secrets add-iam-policy-binding "$s" --member "serviceAccount:${runtime_email}" \
    --role roles/secretmanager.secretAccessor
done

say "IAM: build service account (${build_email})"
# run.admin (not developer): services replace with the invoker-iam-disabled annotation
# needs run.services.setIamPolicy. Tighten with a condition once the service exists.
g projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:${build_email}" \
  --role roles/run.admin --condition=None
g projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:${build_email}" \
  --role roles/logging.logWriter --condition=None
g iam service-accounts add-iam-policy-binding "$runtime_email" \
  --member "serviceAccount:${build_email}" --role roles/iam.serviceAccountUser
g artifacts repositories add-iam-policy-binding "$REPO" --location "$REGION" \
  --member "serviceAccount:${build_email}" --role roles/artifactregistry.writer
g storage buckets add-iam-policy-binding "gs://${source_bucket}" \
  --member "serviceAccount:${build_email}" --role roles/storage.objectViewer

say "Done. Next: build and deploy (docs/deploy-gcp.md, section 2)."
echo "    Staging bucket for gcloud builds submit: gs://${source_bucket}/source"
