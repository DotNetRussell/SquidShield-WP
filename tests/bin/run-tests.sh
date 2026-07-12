#!/usr/bin/env bash
# Run SquidShield WP unit/integration tests inside the local Docker WordPress container.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# Prefer stack next to plugin mount
STACK="$(cd "$ROOT/../../.." && pwd)"
if [[ ! -f "$STACK/docker-compose.yml" ]]; then
  # local-docker layout: wordpress/wp-content/plugins/squidsec-shield
  STACK="$(cd "$ROOT/../../../.." && pwd)/local-docker"
fi
if [[ -f /home/dnradmin/emptyy/local-docker/docker-compose.yml ]]; then
  STACK=/home/dnradmin/emptyy/local-docker
fi

cd "$STACK"
if [[ ! -f phpunit.phar && -f "$ROOT/phpunit.phar" ]]; then
  :
fi

echo "Running SquidShield WP tests via Docker ($STACK)..."
docker compose exec -T \
  -e WP_LOAD=/var/www/html/wp-load.php \
  -e SQUIDSHIELD_TESTING=1 \
  wordpress \
  php /var/www/html/wp-content/plugins/squidsec-shield/phpunit.phar \
  -c /var/www/html/wp-content/plugins/squidsec-shield/phpunit.xml.dist \
  "$@"
