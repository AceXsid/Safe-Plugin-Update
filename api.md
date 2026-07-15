# API contract — Safe Plugin Update

This skill is **keyless**. Everything it calls is either an on-site command (WP-CLI / PHP) or a free, public HTTP API fetched *from the site*. No secrets, no env vars.

## On-site: WP-CLI (preferred update + backup path)

Verified against the official CLI docs (2026-07-14).

- **Update one plugin (only ever one):**
  `wp plugin update <slug> --format=summary`
  Docs: https://developer.wordpress.org/cli/commands/plugin/update/
  Relevant flags (we deliberately do **not** use `--all`): `[<plugin>…]`, `--all`, `--exclude=<name>`, `--minor`, `--patch`, `--version=<version>`, `--dry-run`, `--format=<table|csv|json|summary>`. Alias: `wp plugin upgrade`.
- **List / detect updates:**
  `wp plugin list --fields=name,status,update,version,update_version --format=json`
  Docs: https://developer.wordpress.org/cli/commands/plugin/list/ (`--status=`, `--field=`, `--fields=`, `--format=`)
- **DB dump (direct backup):**
  `wp db export <path>.sql --add-drop-table`
  Docs: https://developer.wordpress.org/cli/commands/db/export/
- **UpdraftPlus (if active):**
  `wp updraftplus backup --quiet`
- Every call is scoped with `--path=<ABSPATH> --skip-themes --no-color` and its output scanned for `Error:` / `PHP Fatal`. If `shell_exec` is disabled or `wp` is absent, the runner falls back to the PHP path below.

## On-site: PHP fallbacks (no shell required)

- **Update:** `Plugin_Upgrader::upgrade( $plugin_file )` with `Automatic_Upgrader_Skin`
  Docs: https://developer.wordpress.org/reference/classes/plugin_upgrader/
- **Deactivate / reactivate on rollback:** `deactivate_plugins()` / `activate_plugin()` — the sanctioned APIs. **Never** `update_option('active_plugins', …)`.
- **Detect updates:** `wp_update_plugins()` + `get_site_transient('update_plugins')`.
- **Health:** `wp_remote_get()` (cache-busted), `get_option('wp_paused_plugins')`.
- **Caches:** `opcache_reset()`, `wp_cache_flush()`, `rocket_clean_domain()`, `w3tc_flush_all()`, `do_action('litespeed_purge_all')`.

## External: wp.org Plugin Info (FREE, keyless)

- **Endpoint:** `GET https://api.wordpress.org/plugins/info/1.0/<slug>.json`
- **Auth:** none.
- **Uses:** `version`, `last_updated` (soak age), `tested` (WP compat ceiling), `requires_php`, `active_installs`, `sections.changelog` (scanned for breaking / removed / DB-migration language).
- **Fail policy:** non-200 / missing page → verdict **NEEDS-APPROVAL** ("changelog unverifiable"); never a blind auto-update.
- Docs: https://developer.wordpress.org/plugins/wordpress-org/

## External: Wordfence scanner vuln feed (FREE, keyless)

- **Endpoint:** `GET https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner/`
- **Auth:** none (public scanner feed).
- **Cache:** fetched once per run, stored in a ~12 h transient (`sprout_wf_feed`).
- **Match:** `software[].slug` + `type=plugin`, current version within any `affected_versions` `from_version`/`to_version` range → **FORCE**.
- **Fail policy:** non-200 / timeout / unparseable → treat as **no known vuln** (fail-closed: never fabricate a FORCE from a missing feed).
- Docs: https://www.wordfence.com/help/wordfence-intelligence/
- **Note:** ARCHITECTURE §9 anticipates the Wordfence **Intelligence v3** feed (key-required) for the standalone Vulnerability Checker skill. This runner uses the **keyless v2 scanner feed** as the source playbook did, so Safe Plugin Update stays zero-key. If the team standardises on v3, swap the endpoint + add `WORDFENCE_API_KEY` to `env` here.

## Env registry

| Var | Required? | For | Free? |
|---|---|---|---|
| (none) | — | WP-CLI/PHP + wp.org info + Wordfence v2 scanner feed | ✅ all free / keyless |

## Not used

- **thum.io / any external screenshot service** — deliberately removed. Post-update visual/functional verification is done **on-site** (plugin-state, cache-busted HTTP status, `debug.log` fatal scan, optional `sprout_dom_probe` DOM check). No client page is ever sent to a third-party render service.
