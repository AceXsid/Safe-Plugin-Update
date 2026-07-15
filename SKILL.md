---
name: Safe Plugin Update
slug: safe-plugin-update
category: care
version: 0.1.0
engine: hybrid             # on-site WP-CLI + PHP (Plugin_Upgrader) + external API (wp.org info, Wordfence feed)
risk: reversible-write     # updates plugins through WP's own updater; backup + rollback make every write undoable
requires_signature: true   # a verified backup [capture] AND a human approval [approve] gate the apply
idempotent: true           # safe to re-run; a run lock prevents overlap; backups are additive insurance
env: []                    # wp.org info + Wordfence scanner feed are keyless; no secrets, no keys
free_tier: "wp.org plugin-info API — keyless, free. Wordfence scanner vuln feed — keyless, free. WP-CLI/PHP — native."
end_goal: "Keep a client's plugins current WITHOUT ever breaking the site — back up, judge each update like a careful human, apply only the safe ones one-at-a-time, verify on-site, and roll back instantly on any fatal."
---

## Purpose

Plugin updates are the single most common way an agency breaks a client site: a routine "update all" ships a fatal, a page-builder bumps a major version, or a cached white-screen hides a dead checkout. This flagship Agent updates plugins the way a careful senior would — it refuses to run on an unhealthy or staging site, takes and **verifies a real backup first**, judges every pending update against wp.org compatibility data and the Wordfence vulnerability feed, then applies **only the safe queue, one plugin at a time**, flushing OPcache and page caches before a **cache-busted on-site health check**, and **rolls back automatically** the instant anything goes wrong. Security-critical patches are forced ahead of routine updates; page-builders, WooCommerce, LMS/membership, major jumps and off-wp.org Pro plugins are held for human approval. Nothing irreversible ever happens without a captured before-state and an explicit approval.

## File-safety (the hard guarantee — ARCHITECTURE §4a)

This skill **never hand-edits arbitrary files.** Every plugin mutation flows through WordPress's own sanctioned updater — `wp plugin update <slug>` via WP-CLI, or `Plugin_Upgrader::upgrade()` in PHP — exactly as `wp_trash_comment` is Spam Deleter's only write path. Its **only** direct filesystem writes are inside its own sandbox (`wp_upload_dir()/sproutos-mcp-sandbox/{backups,rollback}`), plus — on rollback only — restoring its own pre-update stash back over the **same** plugin directory that was the declared target of the update. No other file is ever touched. No recursive/glob/wildcard deletes. No raw SQL. **Never** core, themes, or translations — plugins only.

## When to run

Scheduled **weekly** in `plan` mode (produces the approval request); proceeds to `apply` only after a human approves the queue. Also on-demand after a security advisory.

## When to STOP (skill-specific stop-conditions)

- **No updates pending** → EXIT quietly ("nothing to do") — no backup, no alarm, just a log line.
- **Staging/dev detected**, or **site already unhealthy** (home not `200` / "critical error" present) before we start → STOP + NOTIFY. Never update a broken site.
- **Low disk** (<200 MB free in `wp-content`) → STOP; a safe backup needs headroom.
- **Run lock already held** (another run in progress) → STOP.
- **Previous run ended in an unresolved critical failure** → STOP until a human clears `sprout_last_update_state`.
- **Backup fails**, or **backup verification is Failed / Verified-with-warnings** → STOP + NOTIFY. No usable backup = no updates.
- **A rollback still leaves the site broken** → STOP + NOTIFY (site state unknown; human needed).
- **Not approved** → STOP at the apply gate with the ordered queue (this is a healthy `status: ok`, not an error).

## Inputs

- `mode`: `plan` (default) | `apply`
- `approved`: bool (required `true` for `apply`)
- `approve_slugs[]`: optional subset the human approved (intersected with the safe queue)
- `use_sentinel`: bool (default `false`) — best-effort mu-plugin fatal-guard, degrades cleanly if the sandbox blocks it
- `notify`: optional channel id, passed through to the report

## Playbook

**1. `[READ]` `[PHP]` Pre-flight Readiness.** Decide whether to run at all. *First* read the `update_plugins` transient — if **no** plugin has an update, EXIT "nothing to do" (no backup, no continue). If updates exist, run the safety gauntlet: staging/dev detection; current-health check (home + `/wp-admin/` must be `200` with no critical error); disk headroom; clear a *stale* `.maintenance`; acquire a 30-minute run lock (abort if one exists); and refuse if the last run ended critical. The only writes here are clearing a stale `.maintenance` and setting the lock. → any failure = STOP + NOTIFY.

**2. `[SIGNATURE:capture]` `[WP-CLI]` `[PHP]` Smart Backup.** Create a fresh backup labeled `weekly-update` — **this is the capture signature** for the whole run. If UpdraftPlus + WP-CLI are present, trigger its verified routine (`wp updraftplus backup --quiet`); otherwise take a direct backup: DB dump (`wp db export`), a `wp-content` zip (excluding caches, our sandbox, and `wp-config.php`), and **redacted** wp-config notes (constant **names** only — never a secret value). All artifacts land inside our sandbox, which is protected with `Deny from all` + `index.php`. → backup fails = STOP + NOTIFY. Existing backups are never modified or deleted.

**3. `[READ]` `[PHP]` Verify Backup Integrity.** Prove the backup is restorable **before** any update. Read-only header checks: `.sql` exists, is >5 KB, and its header carries DDL markers (`CREATE TABLE` / `DROP TABLE` / `INSERT INTO`); the `-files.zip` opens via `ZipArchive`, has entries, and is >100 KB; the label reads `weekly-update`. → `Failed` or `Verified with warnings` = STOP + NOTIFY. We never extract the zip or read SQL data rows — header only.

**4. `[API]` `[PHP]` Check Requirements & Compatibility.** Assign every pending plugin a verdict and build the ordered apply-queue — changing nothing. Per plugin, fetch **from the site**: wp.org info (`api.wordpress.org/plugins/info/1.0/<slug>.json` → version, `last_updated` age, `tested` WP ceiling, `requires_php`, `active_installs`, changelog) and the keyless **Wordfence scanner vuln feed** (fetched once, cached ~12 h, matched against the plugin's *current* version). Verdict order: **FORCE** (current version has an active vuln — patch now) → **NEEDS-APPROVAL** (page-builder/Woo/LMS/framework, major-version jump, or not on wp.org) → **HOLD** (release <7 days old, requires newer PHP/WP than the site, or changelog flags breaking/DB-migration) → **UPDATE** (otherwise safe). Only **FORCE + UPDATE** enter the queue; it's ordered security-first, then frameworks before their add-ons. External calls are fail-closed: a missing feed means "no known vuln" (never a fabricated FORCE), a missing wp.org page means NEEDS-APPROVAL (never a blind auto-update).

**5. `[SIGNATURE:approve]` `[WP-CLI]` `[PHP]` Apply Updates Safely.** In `plan` mode (or without `approved`), emit the ordered apply-queue + deferred list and **STOP for approval** — no plugin is touched. In `apply` mode (approved), process the queue **one plugin at a time**: **(A) stash** the current folder into the sandbox (rollback source); (B) optional sentinel guard; **(C) update this plugin only** — never `--all`, never core/themes — via `wp plugin update <slug>` (WP-CLI) or `Plugin_Upgrader::upgrade()` (PHP), deleting any leftover `.maintenance`; **(D) flush OPcache + object cache + page caches** (WP Rocket / W3TC / LiteSpeed) *before* verifying — stale bytecode causes false white-screens; **(E) cache-busted verify** — home + a post + `/wp-admin/` each `200` with no critical error, plugin not in `wp_paused_plugins`; **(F) decide** — pass → keep, drop the stash, mark UPDATED; fail → **ROLLBACK**: deactivate via `deactivate_plugins()` (never `update_option('active_plugins')`), delete only *this* plugin's folder, restore the stash, reactivate if it was active, flush + re-verify. If files can't be restored → leave the plugin **deactivated** so the site stays up. If re-verify still fails → STOP + NOTIFY. Never touch HOLD / NEEDS-APPROVAL plugins.

**6. `[PHP]` `[WP-CLI]` On-Site Functional & Visual Verification.** *(Replaces the old external-screenshot step — thum.io is removed.)* Confirm the site actually works using **on-site signals only**: (a) plugin-state — every plugin the DB marks active is still active and **not paused**; (b) key-URL HTTP status (home, post, admin, and Woo shop + cart) via cache-busted `wp_remote_get`; (c) a `debug.log` / `WP_DEBUG` scan for any **new** `PHP Fatal error` since the run started; and (d) an **optional** on-site DOM probe fired through the `sprout_dom_probe` filter (a site may wire a bundled Playwright/DOM assertion) — absent → skipped, never failed. No external screenshot service is contacted.

**7. `[PHP]` Smoke Test Critical Pages.** After everything settles, flush caches once more and fetch the critical pages **cache-busted** — each must be `200`, free of critical errors, with real content (>200 bytes). **Report-only** — no auto-rollback here (update-caused breakage was already handled in Step 5).

**8. `[REPORT]` Final Report + Notify.** Emit one agency-ready result (mapped to `shared/report.md`): overall verdict, backup status + label, `updated (from → to)`, `deferred (+ reason)`, `rolled-back / deactivated (+ reason)`, functional + smoke health, and any human-attention items. **Release the run lock.** Notify on completion **and** on every earlier STOP.

## Success assertion

`apply` is "complete" only if **every** plugin marked `updated` passed a cache-busted `200` with no fatal and is not paused, and the post-run smoke test is green. Otherwise the run reports `warn` (some rolled back / health degraded) or `fail` (rollback left the site broken) — never a bare "done."

## Report → maps to `shared/report.md` schema.

## Failure modes & rollback

Every write is preceded by the Step-2 capture and undone by the Step-5 stash/restore. Edge cases handled: stale page cache masking a white-screen (flush-before-verify, cache-busting); a fatal plugin crashing its own restore (deactivate-first rollback); an un-restorable folder (leave deactivated, keep site up); WP-CLI absent or `shell_exec` disabled (PHP `Plugin_Upgrader` fallback); the vuln feed or wp.org being down (fail-closed to conservative verdicts); a concurrent run (run lock); a double-run (idempotent — additive backups, lock guard). The one hard stop that needs a human: a rollback that still can't get the site back to `200`.

## References

- https://developer.wordpress.org/cli/commands/plugin/update/ — `wp plugin update <slug>` syntax, `--all`, `--exclude`, `--minor`, `--patch`, `--version`, `--dry-run`, `--format` (verified 2026-07-14)
- https://developer.wordpress.org/cli/commands/plugin/list/ — `wp plugin list --fields=name,update,update_version --format=json`
- https://developer.wordpress.org/cli/commands/db/export/ — `wp db export` for the DB dump
- https://developer.wordpress.org/reference/classes/plugin_upgrader/ — PHP `Plugin_Upgrader::upgrade()` fallback
- https://developer.wordpress.org/reference/functions/deactivate_plugins/ — sanctioned deactivation (never `update_option('active_plugins')`)
- https://developer.wordpress.org/reference/functions/activate_plugin/ — sanctioned reactivation on rollback
- https://www.wordfence.com/help/wordfence-intelligence/ — free plugin vulnerability feed
- https://developer.wordpress.org/plugins/wordpress-org/ — wp.org plugin-info API shape
