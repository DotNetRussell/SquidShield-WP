=== SquidShield ===
Contributors: dotnetrussell
Donate link: https://squidsec.com
Tags: security, firewall, malware, login, hardening
Requires at least: 5.8
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Automatic WordPress security by SquidSec: firewall, login protection, malware scanning, integrity checks, hardening, and audit logging.

== Description ==

**SquidShield** by [SquidSec](https://squidsec.com) turns on a full protection profile when you activate the plugin. No multi-plugin security suite tour required.

= What you get =

* **One-click secure defaults** — Full protection profile on activate (WooCommerce-aware when needed). First-run scans, FIM baseline, and safe auto-clean run in the background.
* **Brute-force lockouts** — Failed-login tracking per IP (and optional username), temporary lockouts, audit log events.
* **Login CAPTCHA** — Optional Google reCAPTCHA v2 or Cloudflare Turnstile on wp-login.php.
* **Login hardening + 2FA** — Generic login errors, optional custom login slug, TOTP 2FA with backup codes and role enforcement.
* **User enumeration protection** — Blocks REST, author archives, ?author= probes, oEmbed author leaks, and user sitemaps that list account names.
* **XML-RPC** — Full disable, or pingbacks-only if something still needs XML-RPC.
* **WAF + virtual patches** — Blocks SQLi, XSS, RCE, LFI, and bad uploads. Version-aware virtual patches for known plugin CVEs.
* **Rate limits + IP lists** — Limits on login, admin-ajax, REST, and XML-RPC. Allowlist / blocklist CIDRs. Optional geo-block (off by default).
* **Malware + FIM** — Signature scans on a schedule. File integrity baselines and change checks. Quarantine / delete helpers.
* **Vulns + misconfig** — Plugin risk scoring and misconfiguration checks.
* **Sensitive files + uploads** — Finds config backups and dumps; blocks sensitive paths; best-effort PHP-in-uploads hardening.
* **Fingerprint cleanup** — Removes public readme/license/changelog fingerprint files so packages cannot re-leak versions.
* **Admin hardening** — Disables the file editor, strips generator noise, security headers, application password restrictions.
* **Alerts + audit log** — Email, webhook, and Slack alerts; searchable activity log.
* **Dashboard + REST API** — Plain-language protection status and operator REST endpoints. Pentest mode logs without blocking.

= Privacy =

SquidShield processes security events on your site. Optional alert webhooks/email send event summaries you configure. CAPTCHA providers (if enabled) process visitor tokens under their privacy policies. No account is required to use the plugin.

== Installation ==

= From a release zip =

1. Download `squidsec-shield-x.y.z.zip` from the project releases (not a source-code archive).
2. In WordPress go to **Plugins → Add New → Upload Plugin**.
3. Choose the zip, click **Install Now**, then **Activate**.
4. Open **SquidShield** in the admin menu. Protection defaults are already on.

= From this repository =

1. Clone the repository.
2. Run `./bin/build-release-zip.sh`.
3. Upload `dist/squidsec-shield-x.y.z.zip` via **Plugins → Upload Plugin**.

= Manual copy =

1. Upload the `squidsec-shield` folder to `/wp-content/plugins/`.
2. Activate **SquidShield** through the **Plugins** screen.
3. Confirm the dashboard shows protections on.

== Frequently Asked Questions ==

= Does it work out of the box? =

Yes. On activation the recommended protection profile is applied. You can tune modules under the SquidShield admin screens.

= Will it break my site? =

Defaults favor safe production settings. Use **pentest mode** (log only, do not block) on staging if you want to observe detections without blocking traffic.

= Does it replace fail2ban? =

It provides application-level failed-login lockouts and IP blocks inside WordPress. It does not install or configure the host fail2ban daemon.

= Where is the early WAF drop-in? =

On activation, an early WAF drop-in may be copied to `mu-plugins` for request inspection before full plugin load. Deactivating the plugin removes scheduled jobs; uninstall can remove data and the drop-in per uninstall.php.

= Is CAPTCHA required? =

No. CAPTCHA is optional. Leave the provider on “None” if you rely on rate limiting and lockouts alone.

= How do I get support? =

Project issues and releases: https://github.com/DotNetRussell/SquidShield-WP

== Screenshots ==

1. Protection status dashboard with active layers and meter.
2. WordPress admin dashboard card summarizing Shield status.
3. Login security settings: lockouts, CAPTCHA, and 2FA options.
4. Firewall and rate-limit settings with allowlist controls.
5. Activity / audit log of security events.

== Changelog ==

= 1.0.0 =
* Initial public release.
* WAF, virtual patches, rate limiting, login protection, CAPTCHA, TOTP 2FA.
* Malware scanner, FIM, vuln/risk scoring, hardening, fingerprint cleanup.
* Audit log, alerts (email/webhook/Slack), REST API, dashboard widget.
* Early WAF drop-in install on activation.
* Fixed nested plugin header on drop-in so zip Activate works in WordPress.

== Upgrade Notice ==

= 1.0.0 =
Initial release. Activate to enable the default protection profile.
