# SquidShield WP

**Automatic WordPress security by [SquidSec](https://squidsec.com)** — firewall, login protection, malware & integrity scanning, hardening, and audit logging.

> Install, activate, protected.

[![Build](https://github.com/DotNetRussell/SquidShield-WP/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/DotNetRussell/SquidShield-WP/actions/workflows/ci.yml)
[![Unit tests](https://img.shields.io/github/actions/workflow/status/DotNetRussell/SquidShield-WP/ci.yml?branch=main&label=unit%20tests&logo=github)](https://github.com/DotNetRussell/SquidShield-WP/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/DotNetRussell/SquidShield-WP.svg?logo=github&label=release)](https://github.com/DotNetRussell/SquidShield-WP/releases/latest)
[![Download plugin zip](https://img.shields.io/badge/plugin%20zip-download-2ea44f.svg?logo=github&logoColor=white)](https://github.com/DotNetRussell/SquidShield-WP/releases/latest)
[![License](https://img.shields.io/github/license/DotNetRussell/SquidShield-WP.svg)](LICENSE)
[![Requires PHP](https://img.shields.io/badge/PHP-%E2%89%A5%207.4-777BB4?logo=php&logoColor=white)](https://www.php.net/)
[![Requires WordPress](https://img.shields.io/badge/WordPress-%E2%89%A5%205.8-21759B?logo=wordpress&logoColor=white)](https://wordpress.org/)

---

## Quick install

### From the latest release (recommended)

1. Open the **[latest release](https://github.com/DotNetRussell/SquidShield-WP/releases/latest)**.
2. Download **`squidsec-shield-x.y.z.zip`** (not the source code archive).
3. In WordPress: **Plugins → Add New → Upload Plugin**.
4. Choose the zip → **Install Now → Activate**.

That's it. Protective modules default **on** so a typical site is covered without opening Settings first.

### From this repository

```bash
git clone https://github.com/DotNetRussell/SquidShield-WP.git
cd SquidShield-WP
chmod +x bin/build-release-zip.sh
./bin/build-release-zip.sh
# Upload dist/squidsec-shield-<version>.zip in WP Admin
```

---

## What it does

| Area | Capabilities |
|------|----------------|
| **Web Application Firewall** | Blocks common SQLi, XSS, RCE, LFI, and malicious upload patterns; virtual patches; rate limiting |
| **Login & auth** | Brute-force lockouts, hide login errors, optional CAPTCHA/Turnstile, TOTP 2FA, user enumeration prevention |
| **Malware & integrity** | Signature scanning, file integrity monitoring (FIM), safe remediation helpers |
| **Hardening** | Disable file editor, hide WP version, security headers, sensitive-file protection, fingerprint cleanup |
| **Vulnerabilities** | Plugin risk scoring and vulnerability checks against bundled data |
| **Visibility** | Audit log, alerts (email / webhooks / Slack), REST API, dashboard widget |

Most features register on activation and honor their own settings. Defaults favor protection for average sites.

---

## Requirements

| Requirement | Minimum |
|-------------|---------|
| WordPress | 5.8+ |
| PHP | 7.4+ |
| MySQL / MariaDB | As required by your WordPress install |

---

## Plugin layout

```
squidsec-shield/
├── squidsec-shield.php    # Bootstrap & plugin headers
├── includes/              # Modules (WAF, Auth, Malware, Hardening, …)
├── assets/                # Admin CSS / JS / images
├── data/                  # Rules, signatures, vuln data
├── dropins/               # Early-load WAF drop-in
├── languages/             # Translations
└── uninstall.php
```

After install, look for **SquidShield** in the WordPress admin menu and the main Dashboard widget.

---

## CI / releases

| Trigger | What runs |
|---------|-----------|
| Pull request → `main` | PHPUnit suite against a real WordPress + MySQL stack |
| Push / merge → `main` | Tests, then build `squidsec-shield-<version>.zip`, upload as a workflow artifact, and publish/update the GitHub Release |
| Tag `v*` | Same as main: tests + zip + GitHub Release for that tag |

- **Workflow:** [.github/workflows/ci.yml](.github/workflows/ci.yml)
- **Installable zip:** [Releases](https://github.com/DotNetRussell/SquidShield-WP/releases/latest) (prefer this over “Source code” zips — those include tests and omit the correct plugin folder layout)
- **Version source:** `Version:` header in `squidsec-shield.php` (currently **1.0.0**)

When you cut a new version:

1. Bump `Version` and `SQUIDSEC_SHIELD_VERSION` in `squidsec-shield.php`.
2. Merge to `main` (or push a tag like `v1.0.1`).
3. Grab the zip from the new release.

---

## Development & tests

The suite covers WAF rules, virtual patches, malware signatures, FIM, login protection, user enumeration, 2FA/TOTP, fingerprint cleanup, sensitive files, hardening, vulnerability/risk scoring, audit logs, REST API, and more.

### Local (Docker)

If the plugin is mounted into a local WordPress container (see `tests/bin/run-tests.sh`):

```bash
chmod +x tests/bin/run-tests.sh
./tests/bin/run-tests.sh
# Optional filter:
./tests/bin/run-tests.sh --filter RulesEngine
```

### PHPUnit directly

Requires WordPress loadable via `WP_LOAD` (path to `wp-load.php`):

```bash
export WP_LOAD=/path/to/wordpress/wp-load.php
export SQUIDSHIELD_TESTING=1
php phpunit.phar -c phpunit.xml.dist
```

| Path | Purpose |
|------|---------|
| `tests/Unit/` | Focused logic tests |
| `tests/Integration/` | WordPress-backed tests (DB, REST, scanners, …) |
| `tests/Support/TestCase.php` | Shared fixtures / cleanup |
| `tests/bootstrap.php` | Loads `wp-load.php` + plugin autoloader |
| `phpunit.phar` | Download PHPUnit 9 locally (`curl -fsSL -o phpunit.phar https://phar.phpunit.de/phpunit-9.6.phar`) |

> Tests may use a live site database. Prefer disposable/local environments. Do not point `WP_LOAD` at production.

More detail: [tests/README.md](tests/README.md).

---

## Configuration notes

- **Defaults are on** — enable/disable individual modules under the SquidShield admin screens.
- **Pentest mode** — log detections without blocking (useful for staging).
- **Early drop-in** — `dropins/squidsec-shield-early.php` can run the WAF before full plugin load when placed as an MU-plugin / advanced setup (see admin docs in-plugin).
- **Notifications** — email, generic webhook, and Slack webhook fields in settings.

---

## Support & links

| | |
|--|--|
| **Plugin URI** | [squidsec.com/shield](https://squidsec.com/shield) |
| **Author** | [SquidSec](https://squidsec.com) |
| **Issues** | [GitHub Issues](https://github.com/DotNetRussell/SquidShield-WP/issues) |
| **Releases** | [GitHub Releases](https://github.com/DotNetRussell/SquidShield-WP/releases) |

---

## License

This repository is distributed under the terms in [LICENSE](LICENSE). The plugin header also notes **GPLv2 or later** for WordPress.org compatibility expectations.
