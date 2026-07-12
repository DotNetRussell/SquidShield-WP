# SquidShield WP Tests

PHPUnit suite covering the features SquidShield WP claims: WAF rules, virtual patches, malware signatures, FIM, login protection, user enumeration, 2FA/TOTP, fingerprint cleanup, sensitive files, hardening, vulnerability/risk scoring, audit logs, REST API, setup layers, and more.

## Run (local Docker stack)

From the host:

```bash
chmod +x tests/bin/run-tests.sh
./tests/bin/run-tests.sh
```

Or directly:

```bash
cd /path/to/local-docker
docker compose exec -T \
  -e WP_LOAD=/var/www/html/wp-load.php \
  wordpress \
  php /var/www/html/wp-content/plugins/squidsec-shield/phpunit.phar \
  -c /var/www/html/wp-content/plugins/squidsec-shield/phpunit.xml.dist
```

Filter a suite:

```bash
./tests/bin/run-tests.sh --filter RulesEngine
```

## Requirements

- Local WordPress stack with the plugin mounted (as in `local-docker`)
- PHPUnit 9 phar at `phpunit.phar` (download: `curl -fsSL -o phpunit.phar https://phar.phpunit.de/phpunit-9.6.phar`)

## Layout

| Path | Purpose |
|------|---------|
| `tests/Unit/` | Focused logic tests (options, helpers, TOTP, rules, signatures, remediation safety) |
| `tests/Integration/` | WordPress-backed tests (DB, FIM, REST, login, scanners, admin widget) |
| `tests/Support/TestCase.php` | Shared fixtures / option restore / temp files |
| `tests/bootstrap.php` | Loads `wp-load.php` + plugin autoloader |

## Notes

- Tests load the **live** local site DB. They clean temp files and restore options they change.
- Avoid running destructive full malware scans in CI without a disposable DB.
- Do not point `WP_LOAD` at production.
