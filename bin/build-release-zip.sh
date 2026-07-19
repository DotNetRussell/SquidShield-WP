#!/usr/bin/env bash
# Build a WordPress-installable plugin zip for SquidShield WP.
#
# Output: dist/squidsec-shield-<version>.zip
# Archive layout (required by WP Admin → Plugins → Upload Plugin):
#   squidsec-shield/
#     squidsec-shield.php   ← must contain "Plugin Name:" header
#     includes/ ...
#     assets/ ...
#
# Do not upload GitHub "Source code" archives or Actions artifact wrappers
# that contain a nested .zip — only this built package (or its folder).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PLUGIN_SLUG="squidsec-shield"
MAIN_FILE="${PLUGIN_SLUG}.php"

if [[ ! -f "$MAIN_FILE" ]]; then
  echo "error: missing ${MAIN_FILE}" >&2
  exit 1
fi

if ! grep -qE '^\s*\*\s*Plugin Name:' "$MAIN_FILE"; then
  echo "error: ${MAIN_FILE} is missing a Plugin Name header" >&2
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

# Copy only plugin runtime files (never nest dist/ or wrap another zip).
rsync -a \
  --exclude='.git/' \
  --exclude='.github/' \
  --exclude='.wordpress-org/' \
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
  --exclude='*:Zone.Identifier' \
  --exclude='*.bak' \
  --exclude='*.bak.*' \
  --exclude='*~' \
  --exclude='README.md' \
  ./ "${STAGE_DIR}/"

# Guard against accidental self-nesting (rsync footgun if excludes fail).
if [[ -e "${STAGE_DIR}/dist" ]] || [[ -e "${STAGE_DIR}/${PLUGIN_SLUG}" ]]; then
  echo "error: staged tree is nested incorrectly under ${STAGE_DIR}" >&2
  find "${STAGE_DIR}" -maxdepth 2 -type d >&2
  exit 1
fi

if [[ ! -f "${STAGE_DIR}/${MAIN_FILE}" ]]; then
  echo "error: staged package missing ${MAIN_FILE}" >&2
  exit 1
fi

if ! grep -qE '^\s*\*\s*Plugin Name:' "${STAGE_DIR}/${MAIN_FILE}"; then
  echo "error: staged ${MAIN_FILE} lost its Plugin Name header" >&2
  exit 1
fi

if ! command -v zip >/dev/null 2>&1; then
  echo "error: zip is required (apt install zip / brew install zip)" >&2
  exit 1
fi

rm -f "${ZIP_PATH}"
# -X strips extra file attributes that occasionally confuse older ZipArchive builds.
(
  cd "${DIST_DIR}"
  zip -r -9 -X -q "${ZIP_NAME}" "${PLUGIN_SLUG}"
)

# --- Validate the zip the same way WordPress does (one folder, header in *.php) ---
VALIDATE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sss-zip-XXXXXX")"
cleanup_validate() {
  rm -rf "${VALIDATE_ROOT}"
}
trap cleanup_validate EXIT

unzip -q "${ZIP_PATH}" -d "${VALIDATE_ROOT}"

TOP=( "${VALIDATE_ROOT}"/* )
if [[ ${#TOP[@]} -ne 1 ]] || [[ ! -d "${TOP[0]}" ]]; then
  echo "error: zip must contain exactly one top-level directory (${PLUGIN_SLUG}/)" >&2
  ls -la "${VALIDATE_ROOT}" >&2
  exit 1
fi

TOP_NAME="$(basename "${TOP[0]}")"
if [[ "${TOP_NAME}" != "${PLUGIN_SLUG}" ]]; then
  echo "error: top-level directory must be '${PLUGIN_SLUG}', got '${TOP_NAME}'" >&2
  exit 1
fi

# Nested zip = classic "plugin does not have a valid header" when uploaded to WP.
if find "${TOP[0]}" -type f -name '*.zip' | grep -q .; then
  echo "error: package contains a nested .zip (WordPress cannot read plugin headers)" >&2
  find "${TOP[0]}" -type f -name '*.zip' >&2
  exit 1
fi

HEADER_OK=0
HEADER_FILE=""
for php in "${TOP[0]}"/*.php; do
  [[ -f "${php}" ]] || continue
  if grep -qE '^\s*\*\s*Plugin Name:' "${php}"; then
    HEADER_OK=1
    HEADER_FILE="$(basename "${php}")"
    echo "Validated plugin header in: ${TOP_NAME}/${HEADER_FILE}"
    break
  fi
done

if [[ "${HEADER_OK}" -ne 1 ]]; then
  echo "error: no Plugin Name header in top-level PHP files (WordPress will reject this zip)" >&2
  ls -la "${TOP[0]}" >&2
  exit 1
fi

# Nested "Plugin Name:" headers break Activate after upload.
# WP plugin_info() uses get_plugins('/folder') which scans ONE subdirectory deep
# (e.g. dropins/*.php). It sorts by name and may pick the nested file as the
# main plugin path; validate_plugin() then fails because get_plugins() (no
# folder arg) only lists top-level PHP files → "does not have a valid header".
NESTED_HEADERS="$(
  find "${TOP[0]}" -mindepth 2 -type f -name '*.php' -print0 \
    | xargs -0 grep -l -E '^\s*\*\s*Plugin Name:' 2>/dev/null || true
)"
if [[ -n "${NESTED_HEADERS}" ]]; then
  echo "error: nested Plugin Name header(s) will break WordPress Activate:" >&2
  echo "${NESTED_HEADERS}" >&2
  exit 1
fi

# Emit paths for CI / local use.
echo "VERSION=${VERSION}"
echo "ZIP_PATH=${ZIP_PATH}"
echo "ZIP_NAME=${ZIP_NAME}"
echo "PLUGIN_SLUG=${PLUGIN_SLUG}"
echo "STAGE_DIR=${STAGE_DIR}"
ls -lh "${ZIP_PATH}"
