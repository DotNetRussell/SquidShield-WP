#!/usr/bin/env bash
# Build a WordPress-installable plugin zip for SquidShield WP.
#
# Output: dist/squidsec-shield-<version>.zip
# Archive layout:
#   squidsec-shield/
#     squidsec-shield.php
#     includes/ ...
#     assets/ ...
#
# Install via WP Admin → Plugins → Add New → Upload Plugin.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PLUGIN_SLUG="squidsec-shield"
MAIN_FILE="${PLUGIN_SLUG}.php"

if [[ ! -f "$MAIN_FILE" ]]; then
  echo "error: missing ${MAIN_FILE}" >&2
  exit 1
fi

VERSION="$(
  grep -E '^\s*\*\s*Version:' "$MAIN_FILE" \
    | head -1 \
    | sed -E 's/.*Version:\s*([0-9][0-9A-Za-z.+-]*).*/\1/'
)"

if [[ -z "${VERSION}" ]]; then
  echo "error: could not parse Version from ${MAIN_FILE}" >&2
  exit 1
fi

DIST_DIR="${ROOT}/dist"
STAGE_DIR="${DIST_DIR}/${PLUGIN_SLUG}"
ZIP_NAME="${PLUGIN_SLUG}-${VERSION}.zip"
ZIP_PATH="${DIST_DIR}/${ZIP_NAME}"

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}"

# Copy plugin files; exclude CI/dev/test-only paths.
rsync -a \
  --exclude='.git/' \
  --exclude='.github/' \
  --exclude='.gitignore' \
  --exclude='.gitattributes' \
  --exclude='.editorconfig' \
  --exclude='dist/' \
  --exclude='tests/' \
  --exclude='bin/' \
  --exclude='phpunit.phar' \
  --exclude='phpunit.xml.dist' \
  --exclude='composer.json' \
  --exclude='composer.lock' \
  --exclude='vendor/' \
  --exclude='node_modules/' \
  --exclude='.phpunit.result.cache' \
  --exclude='*.zip' \
  ./ "${STAGE_DIR}/"

# Ensure zip CLI is available.
if ! command -v zip >/dev/null 2>&1; then
  echo "error: zip is required (apt install zip / brew install zip)" >&2
  exit 1
fi

rm -f "${ZIP_PATH}"
(
  cd "${DIST_DIR}"
  zip -r -q "${ZIP_NAME}" "${PLUGIN_SLUG}"
)

# Emit paths for CI / local use.
echo "VERSION=${VERSION}"
echo "ZIP_PATH=${ZIP_PATH}"
echo "ZIP_NAME=${ZIP_NAME}"
echo "PLUGIN_SLUG=${PLUGIN_SLUG}"
ls -lh "${ZIP_PATH}"
