# Safe Plugin Update — plain-English guide

**What it does:** keeps a client's WordPress plugins up to date **without ever breaking the site.** It behaves like a careful senior engineer doing the update by hand — check it's safe to start, back everything up and prove the backup works, judge each update, apply only the safe ones one at a time, check the site still works, and instantly undo anything that goes wrong.

**Category:** care · **Risk:** reversible-write · **Runs:** weekly (with a human approving the queue) · **Keys needed:** none.

---

## The one-paragraph mental model

Nothing irreversible happens without (1) a **verified backup** taken first and (2) a **human approval** of exactly which updates will run. Updates go through WordPress's own updater — the skill never hand-edits plugin files. If any single update turns the site white, the skill **rolls that plugin back by itself** and keeps going. If it can't get the site healthy again, it **stops and shouts** rather than guessing.

---

## What happens, step by step

1. **Pre-flight.** Are there even any updates? If not, it quietly stops. If yes, is the site healthy right now, is this production (not staging), is there disk space, is another run already going? Any red flag → stop and notify.
2. **Backup.** Takes a fresh, labeled backup (its own, or triggers UpdraftPlus if you use it) — database + files, with secrets redacted to names only.
3. **Verify the backup.** Actually checks the backup is real and openable *before* trusting it. A backup you can't restore is worthless.
4. **Judge each update.** For every plugin, it reads wp.org compatibility data and a free Wordfence vulnerability feed, then labels it:
   - **Force** — a security hole in the current version, patch now (goes first).
   - **Update** — routine and safe.
   - **Hold** — too new (still soaking), or needs newer PHP/WP than you have, or the changelog mentions breaking changes.
   - **Needs approval** — page-builders (Elementor/Nexter/Divi), WooCommerce, LMS/membership, big version jumps, or paid plugins not on wp.org.
   Only **Force** and **Update** are eligible to run automatically.
5. **Apply — one at a time.** For each safe plugin: stash a copy, update just that one, clear all caches, then load the homepage/a post/the admin with a cache-buster to confirm `200 OK` and no crash. Pass → keep it. Fail → **roll it back** (restore the stash, reactivate), re-check, and if it *still* won't come back, deactivate it so the rest of the site stays up.
6. **On-site health check.** Confirms every active plugin still loads, key pages (incl. WooCommerce shop + cart) return `200`, and the debug log has no new fatal errors. *No external screenshot service is used — all checks run on the site itself.*
7. **Smoke test.** One more cache-busted pass over the critical pages to be sure.
8. **Report + notify.** A short, client-ready summary: what updated (from → to), what was held and why, anything rolled back, site health, and anything a human needs to look at. Then it releases the lock so next week can run.

---

## How to run it

```php
// 1) PLAN — analyse + take a verified backup, then stop with the approval list.
$plan = ( new Sprout_Safe_Plugin_Update() )->run();

// 2) APPLY — after a human approves the queue.
$apply = ( new Sprout_Safe_Plugin_Update() )->run( array(
    'mode'     => 'apply',
    'approved' => true,
    // optional: only apply a subset the human ticked
    // 'approve_slugs' => array( 'akismet', 'wordpress-seo' ),
) );

echo wp_json_encode( $apply );
```

Both return the standard SproutOS report shape (`status`, `summary`, `findings`, …). `status: stopped` is a **healthy** outcome — it means the skill correctly refused to make a mess.

---

## The safety promises (why you can trust it on a live client site)

- **Never touches a file it didn't declare.** All plugin changes go through WordPress's updater; the only direct writes are inside its own sandbox (`wp-content/uploads/sproutos-mcp-sandbox/`) and, on rollback, restoring its own copy of the *same* plugin folder.
- **Never** `rm -rf`, no wildcard deletes, no raw SQL, **never** core/themes/translations — plugins only.
- **Always** backs up and verifies the backup before any change.
- **Always** clears caches before deciding a page is "broken" (a stale cache is the #1 false alarm).
- **Rolls back automatically** on any fatal; if it can't restore health, it **stops for a human** instead of guessing.
- **Idempotent + locked** — safe to re-run, can't overlap itself.

---

## What it does *not* do (honest limits)

- It won't auto-update the high-risk set (page-builders, WooCommerce, LMS, major jumps, off-wp.org Pro plugins) — those always wait for a human.
- Without an on-site DOM probe wired to the `sprout_dom_probe` filter, "visual" verification is HTTP-status + fatal-log based, not pixel-diff. A page that returns `200` but looks subtly wrong won't be caught by the automatic checks — which is exactly why visual-critical plugins are held for approval.
- It updates plugins, not themes or WordPress core.


## Validation — 2026-07-14 (live on Docker WP 6.8.3)

✅ **Validated live on a real WordPress site.** Found akismet 5.5 to 5.7 and safety-stopped on a detected dev environment; the new allow_dev:true override lets you run intentionally on staging.
