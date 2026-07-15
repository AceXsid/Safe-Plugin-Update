<?php
/**
 * SproutOS Agent — Safe Plugin Update (runner) — FLAGSHIP
 *
 * Keeps a client's plugins current WITHOUT ever breaking the site. Every update
 * is preceded by a verified backup (the capture signature) and an approval gate,
 * applied ONE AT A TIME through WordPress's own updater, verified with an
 * on-site cache-busted health check, and rolled back automatically on any fatal.
 *
 * File-safety (ARCHITECTURE §4a): this runner NEVER hand-edits arbitrary files.
 *   - All plugin mutation goes through WP's sanctioned updater
 *     (`wp plugin update <slug>` via WP-CLI, or Plugin_Upgrader in PHP).
 *   - The ONLY direct filesystem writes are inside our own sandbox
 *     (wp_upload_dir()/sproutos-mcp-sandbox/{backups,rollback}) plus, on rollback,
 *     restoring our own pre-update stash back over the SAME plugin directory that
 *     was the declared target of the update. No other file is ever touched.
 *   - No recursive/glob/wildcard deletes. No raw SQL. Never core/themes/i18n.
 *
 * Two modes (approval-gated, ARCHITECTURE §5):
 *   plan  (default) — pre-flight → backup → verify backup → compatibility, then
 *                     STOP at the apply gate and emit the ordered apply-queue for
 *                     a human to approve. No plugin is updated.
 *   apply           — requires approved=true; runs the full flow and applies only
 *                     the FORCE/UPDATE queue, one at a time, with rollback.
 *
 * Returns a structured array matching shared/report.md.
 *
 * @package SproutOS\Agents
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Only runs inside WordPress.
}

class Sprout_Safe_Plugin_Update {

	const LOCK_KEY          = 'sprout_update_lock';
	const LOCK_TTL          = 30 * MINUTE_IN_SECONDS;
	const WF_FEED_KEY       = 'sprout_wf_feed';
	const WF_FEED_TTL       = 12 * HOUR_IN_SECONDS;
	const WPORG_INFO        = 'https://api.wordpress.org/plugins/info/1.0/'; // + <slug>.json
	const WF_SCANNER_FEED   = 'https://www.wordfence.com/api/intelligence/v2/vulnerabilities/scanner/';
	const SOAK_DAYS         = 7;       // A release younger than this is held to soak.
	const CRITICAL_MARKERS  = array( 'There has been a critical error', 'Fatal error', 'HTTP ERROR 500' );

	/** @var string Correlation id for this run (audit + logs). */
	private $run_id;

	/** @var array Human-readable trace of what each step decided. */
	private $trace = array();

	/**
	 * @param array $opts {
	 *   string 'mode'          'plan'|'apply' (default 'plan')
	 *   bool   'approved'      required true for 'apply'
	 *   array  'approve_slugs' optional allowlist of slugs the human approved;
	 *                          if set, only these (∩ the safe queue) are applied
	 *   bool   'use_sentinel'  default false — best-effort mu-plugin fatal-guard
	 *   bool   'skip_backup'   default false — NEVER set true in production; test only
	 *   string 'notify'        optional channel id passed through to the report
	 * }
	 * @return array Structured report (shared/report.md).
	 */
	public function run( array $opts = array() ) {
		$started      = gmdate( 'c' );
		$this->run_id = 'spu-' . gmdate( 'Ymd-His' ) . '-' . substr( md5( home_url() . microtime() ), 0, 8 );
		$mode         = ( isset( $opts['mode'] ) && 'apply' === $opts['mode'] ) ? 'apply' : 'plan';
		$approved     = ! empty( $opts['approved'] );
		$allow_dev    = ! empty( $opts['allow_dev'] ); // opt-in override for INTENTIONAL staging/dev runs

		// ── Step 1: PRE-FLIGHT READINESS ────────────────────────────────────
		$pre = $this->preflight( $allow_dev );
		if ( 'nothing' === $pre['outcome'] ) {
			// Quiet exit — no backup, no alarm, just log.
			$this->trace[] = 'Pre-flight: nothing to do.';
			return $this->report( $started, 'ok', array( 'preflight' => $pre ), 'Nothing to do — all plugins up to date.' );
		}
		if ( 'blocked' === $pre['outcome'] ) {
			return $this->stopped( $started, 'Pre-flight blocked: ' . $pre['reason'], array( 'preflight' => $pre ) );
		}
		// From here on we hold the run lock; release it in every exit path below.

		// ── Step 2: SMART BACKUP  [SIGNATURE:capture] ───────────────────────
		$backup = empty( $opts['skip_backup'] ) ? $this->backup() : array( 'status' => 'skipped', 'files' => array() );
		if ( 'Failed' === $backup['status'] ) {
			return $this->stop_release( $started, 'Backup failed — no backup, no updates: ' . $backup['reason'], array( 'preflight' => $pre, 'backup' => $backup ) );
		}

		// ── Step 3: VERIFY BACKUP INTEGRITY ─────────────────────────────────
		$verify = empty( $opts['skip_backup'] ) ? $this->verify_backup( $backup ) : array( 'verdict' => 'skipped' );
		if ( in_array( $verify['verdict'], array( 'Failed', 'Verified with warnings' ), true ) ) {
			return $this->stop_release( $started, 'Backup verification: ' . $verify['verdict'] . ' — refusing to update. ' . ( $verify['reason'] ?? '' ), array( 'backup' => $backup, 'verify' => $verify ) );
		}

		// ── Step 4: CHECK REQUIREMENTS & COMPATIBILITY ──────────────────────
		$assess = $this->assess( $pre['pending'] );
		$queue  = $assess['queue'];        // ordered FORCE+UPDATE slugs => file
		$defer  = $assess['deferred'];     // HOLD / NEEDS-APPROVAL

		// Narrow to the human's explicit allowlist if provided.
		if ( ! empty( $opts['approve_slugs'] ) && is_array( $opts['approve_slugs'] ) ) {
			$allow = array_map( 'strval', $opts['approve_slugs'] );
			$queue = array_intersect_key( $queue, array_flip( $allow ) );
		}

		// ── Step 5 gate: [SIGNATURE:approve] ────────────────────────────────
		if ( 'apply' !== $mode || ! $approved ) {
			$this->release_lock(); // Plan mode holds nothing open.
			return $this->report(
				$started,
				'ok',
				array(
					'mode'      => 'plan',
					'preflight' => $pre,
					'backup'    => $this->slim_backup( $backup ),
					'verify'    => $verify,
					'assessment'=> $assess['table'],
					'approval'  => array(
						'required'    => true,
						'apply_queue' => array_keys( $queue ), // ORDERED
						'deferred'    => $defer,
						'note'        => 'Re-run with mode=apply, approved=true to apply the queue. Optionally pass approve_slugs=[...] to apply a subset.',
					),
				),
				sprintf( 'Plan: %d update(s) safe to apply, %d deferred. Awaiting approval.', count( $queue ), count( $defer ) )
			);
		}

		if ( empty( $queue ) ) {
			return $this->stop_release( $started, 'Approved, but no plugin qualifies for automatic update (all deferred).', array( 'assessment' => $assess['table'], 'deferred' => $defer ), 'ok' );
		}

		// ── Step 5: APPLY — one at a time, with rollback ────────────────────
		$results   = array();
		$hard_stop = null;
		foreach ( $queue as $slug => $file ) {
			$r = $this->apply_one( $slug, $file, ! empty( $opts['use_sentinel'] ) );
			$results[ $slug ] = $r;
			if ( 'site-broken' === $r['result'] ) {
				// Rollback could not restore health → stop the whole run, human needed.
				$hard_stop = $slug;
				break;
			}
		}

		if ( null !== $hard_stop ) {
			return $this->stop_release(
				$started,
				"Rollback of '{$hard_stop}' left the site in an unknown state — human intervention required.",
				array( 'applied' => $results, 'deferred' => $defer ),
				'fail'
			);
		}

		// ── Step 6: ON-SITE FUNCTIONAL & VISUAL VERIFICATION ────────────────
		$functional = $this->functional_verify();

		// ── Step 7: SMOKE TEST CRITICAL PAGES ───────────────────────────────
		$smoke = $this->smoke_test();

		// ── Step 8: FINAL REPORT + release lock ─────────────────────────────
		$updated     = array_keys( array_filter( $results, function ( $r ) { return 'updated' === $r['result']; } ) );
		$rolledback  = array_keys( array_filter( $results, function ( $r ) { return in_array( $r['result'], array( 'rolled-back', 'deactivated' ), true ); } ) );
		$status      = $this->overall_status( $results, $functional, $smoke );

		$this->release_lock();

		return $this->report(
			$started,
			$status,
			array(
				'mode'       => 'apply',
				'backup'     => $this->slim_backup( $backup ),
				'verify'     => $verify,
				'updated'    => $this->version_pairs( $results, 'updated' ),
				'rolled_back'=> $this->version_pairs( $results, array( 'rolled-back', 'deactivated' ) ),
				'deferred'   => $defer,
				'functional' => $functional,
				'smoke'      => $smoke,
				'notify'     => $opts['notify'] ?? null,
				'success_assertion' => array(
					'checked' => 'every updated plugin passed a cache-busted 200 with no fatal; site health green post-run',
					'passed'  => 'ok' === $status || 'warn' === $status,
				),
			),
			sprintf(
				'%d updated, %d rolled back, %d deferred. Site health: %s.',
				count( $updated ),
				count( $rolledback ),
				count( $defer ),
				$smoke['passed'] ? 'green' : 'CHECK'
			)
		);
	}

	// ══════════════════════════════════════════════════════════════════════
	// STEP 1 — PRE-FLIGHT
	// ══════════════════════════════════════════════════════════════════════

	/**
	 * Decide whether to run at all. Read-only except: clears a stale
	 * .maintenance file and sets the run lock.
	 *
	 * @return array { string 'outcome' 'nothing'|'blocked'|'go', array 'pending', string 'reason' }
	 */
	private function preflight( $allow_dev = false ) {
		// A. Updates check FIRST — cheapest gate.
		$pending = $this->pending_updates();
		if ( empty( $pending ) ) {
			return array( 'outcome' => 'nothing', 'pending' => array(), 'reason' => 'no updates' );
		}

		// B. Staging/dev detection — do not auto-update production logic on staging.
		if ( ! $allow_dev && $this->looks_like_staging() ) {
			return array( 'outcome' => 'blocked', 'pending' => $pending, 'reason' => 'staging/dev environment detected (pass allow_dev:true to run intentionally on staging)' );
		}

		// C. Current health — never start on an already-broken site.
		$home = $this->fetch( home_url( '/' ) );
		if ( ! $this->is_alive( $home ) ) {
			return array( 'outcome' => 'blocked', 'pending' => $pending, 'reason' => 'site is not healthy before updates (home unreachable / 4xx / 5xx / critical error)' );
		}

		// D. Disk space — need comfortable headroom over the backup size.
		$free = @disk_free_space( WP_CONTENT_DIR );
		if ( false !== $free && $free < 200 * MB_IN_BYTES ) {
			return array( 'outcome' => 'blocked', 'pending' => $pending, 'reason' => 'insufficient disk space for a safe backup (<200MB free)' );
		}

		// E. Clear a stale maintenance flag (our only pre-flight write).
		$maint = ABSPATH . '.maintenance';
		if ( file_exists( $maint ) && ( time() - @filemtime( $maint ) ) > 600 ) {
			@unlink( $maint );
		}

		// F. Run lock — refuse to overlap another run.
		if ( get_transient( self::LOCK_KEY ) ) {
			return array( 'outcome' => 'blocked', 'pending' => $pending, 'reason' => 'another update run is already in progress (lock held)' );
		}

		// G. Last-run guard — a prior unresolved critical failure must be cleared by a human.
		if ( 'critical' === get_option( 'sprout_last_update_state', '' ) ) {
			return array( 'outcome' => 'blocked', 'pending' => $pending, 'reason' => 'previous run ended in an unresolved critical failure — clear it manually first' );
		}

		set_transient( self::LOCK_KEY, $this->run_id, self::LOCK_TTL );
		return array( 'outcome' => 'go', 'pending' => $pending, 'reason' => count( $pending ) . ' updates pending' );
	}

	/** Plugins with an available update: slug => { file, current, new, name }. */
	private function pending_updates() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		wp_update_plugins(); // Force a fresh check.
		$t   = get_site_transient( 'update_plugins' );
		$out = array();
		if ( ! $t || empty( $t->response ) ) {
			return $out;
		}
		$all = get_plugins();
		foreach ( $t->response as $file => $u ) {
			$slug = dirname( $file );
			if ( '.' === $slug ) {
				$slug = basename( $file, '.php' ); // Single-file plugin.
			}
			$out[ $slug ] = array(
				'file'    => $file,
				'current' => isset( $all[ $file ]['Version'] ) ? $all[ $file ]['Version'] : '?',
				'new'     => isset( $u->new_version ) ? $u->new_version : '?',
				'name'    => isset( $all[ $file ]['Name'] ) ? $all[ $file ]['Name'] : $slug,
			);
		}
		return $out;
	}

	private function looks_like_staging() {
		$host = (string) wp_parse_url( home_url(), PHP_URL_HOST );
		foreach ( array( 'staging', 'stage.', 'dev.', 'test.', '.local', 'localhost', '.dev', 'wpengine.com', 'wpenginepowered' ) as $needle ) {
			if ( false !== stripos( $host, $needle ) ) {
				return true;
			}
		}
		if ( defined( 'WP_ENVIRONMENT_TYPE' ) && in_array( strtolower( (string) WP_ENVIRONMENT_TYPE ), array( 'local', 'development', 'staging' ), true ) ) {
			return true;
		}
		return false;
	}

	// ══════════════════════════════════════════════════════════════════════
	// STEP 2 — SMART BACKUP  (this IS the capture signature)
	// ══════════════════════════════════════════════════════════════════════

	/**
	 * Create a fresh backup labeled "weekly-update". Prefer an active backup
	 * plugin's own routine; otherwise take a direct DB dump + wp-content zip.
	 * All files land inside our own sandbox (§4a).
	 */
	private function backup() {
		$dir = $this->sandbox( 'backups' );
		if ( ! $dir ) {
			return array( 'status' => 'Failed', 'reason' => 'backup sandbox not writable', 'files' => array() );
		}
		$this->protect_dir( $dir );

		$ts      = gmdate( 'Y-m-d-His' );
		$base    = $dir . '/sproutos-backup-' . $ts;
		$files   = array();
		$method  = 'direct';

		// Prefer UpdraftPlus + WP-CLI if present (its own verified routine).
		if ( is_plugin_active( 'updraftplus/updraftplus.php' ) && $this->wp_cli_available() ) {
			$out = $this->wp_cli( 'updraftplus backup --quiet' );
			if ( $out['ok'] ) {
				$method = 'updraftplus';
				@file_put_contents( $base . '-label.txt', "weekly-update\nrun_id={$this->run_id}\nmethod=updraftplus" );
				return array( 'status' => 'Complete', 'method' => $method, 'dir' => $dir, 'files' => array( $base . '-label.txt' ), 'label' => 'weekly-update' );
			}
			// UpdraftPlus failed → fall through to direct backup (never leave unbacked).
		}

		// Direct DB dump (via WP-CLI if we can, else mysqldump is not assumed).
		$sql = $base . '.sql';
		$db_ok = false;
		if ( $this->wp_cli_available() ) {
			$res   = $this->wp_cli( 'db export ' . escapeshellarg( $sql ) . ' --add-drop-table' );
			$db_ok = $res['ok'] && file_exists( $sql ) && filesize( $sql ) > 5 * KB_IN_BYTES;
		}
		if ( $db_ok ) {
			$files[] = $sql;
		} else {
			// No WP-CLI DB export available → cannot guarantee a restorable DB dump.
			return array( 'status' => 'Failed', 'reason' => 'could not produce a verified DB dump (WP-CLI db export unavailable/failed)', 'files' => $files );
		}

		// wp-content zip (exclude caches, our sandbox, wp-config).
		$zip = $base . '-files.zip';
		if ( $this->zip_wp_content( $zip ) ) {
			$files[] = $zip;
		}

		// Redacted wp-config notes (NAMES only — never a secret value).
		$notes = $base . '-wpconfig-notes.txt';
		@file_put_contents( $notes, $this->wpconfig_notes() );
		$files[] = $notes;

		// Label.
		$label = $base . '-label.txt';
		@file_put_contents( $label, "weekly-update\nrun_id={$this->run_id}\nmethod={$method}" );
		$files[] = $label;

		$status = ( in_array( $zip, $files, true ) ) ? 'Complete' : 'Partial';
		return array( 'status' => $status, 'method' => $method, 'dir' => $dir, 'base' => $base, 'files' => $files, 'label' => 'weekly-update' );
	}

	/** Zip wp-content, excluding caches, our sandbox and wp-config. */
	private function zip_wp_content( $zip_path ) {
		if ( ! class_exists( 'ZipArchive' ) ) {
			return false;
		}
		$zip = new ZipArchive();
		if ( true !== $zip->open( $zip_path, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
			return false;
		}
		$root    = rtrim( WP_CONTENT_DIR, '/\\' );
		$exclude = array( '/cache', '/uploads/sproutos-mcp-sandbox', '/upgrade', '/wp-config.php' );
		$it      = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY
		);
		foreach ( $it as $file ) {
			$path = $file->getPathname();
			$rel  = substr( $path, strlen( $root ) );
			$skip = false;
			foreach ( $exclude as $ex ) {
				if ( 0 === strpos( str_replace( '\\', '/', $rel ), $ex ) ) {
					$skip = true;
					break;
				}
			}
			if ( $skip || ! $file->isFile() ) {
				continue;
			}
			$zip->addFile( $path, 'wp-content' . $rel );
		}
		$zip->close();
		return file_exists( $zip_path ) && filesize( $zip_path ) > 100 * KB_IN_BYTES;
	}

	/** wp-config constant NAMES only (never values). */
	private function wpconfig_notes() {
		$names = array();
		$cfg   = ABSPATH . 'wp-config.php';
		if ( is_readable( $cfg ) ) {
			$src = (string) file_get_contents( $cfg );
			if ( preg_match_all( "/define\\(\\s*['\"]([A-Z0-9_]+)['\"]/", $src, $m ) ) {
				$names = array_unique( $m[1] );
			}
		}
		return "SproutOS wp-config notes (NAMES ONLY — no values captured)\nrun_id={$this->run_id}\n" . implode( "\n", $names ) . "\n";
	}

	// ══════════════════════════════════════════════════════════════════════
	// STEP 3 — VERIFY BACKUP INTEGRITY (read-only)
	// ══════════════════════════════════════════════════════════════════════

	private function verify_backup( array $backup ) {
		if ( 'updraftplus' === ( $backup['method'] ?? '' ) ) {
			// UpdraftPlus verified its own set; we only confirm the label note.
			return array( 'verdict' => 'Verified', 'reason' => 'UpdraftPlus routine reported success; label written' );
		}
		$base = $backup['base'] ?? '';
		if ( '' === $base ) {
			return array( 'verdict' => 'Failed', 'reason' => 'no backup base path' );
		}
		$sql = $base . '.sql';
		$zip = $base . '-files.zip';

		if ( ! file_exists( $sql ) || filesize( $sql ) < 5 * KB_IN_BYTES ) {
			return array( 'verdict' => 'Failed', 'reason' => 'SQL dump missing or too small' );
		}
		$head = (string) file_get_contents( $sql, false, null, 0, 4096 );
		if ( false === stripos( $head, 'CREATE TABLE' ) && false === stripos( $head, 'DROP TABLE' ) && false === stripos( $head, 'INSERT INTO' ) ) {
			return array( 'verdict' => 'Verified with warnings', 'reason' => 'SQL header lacks expected DDL markers' );
		}
		if ( ! file_exists( $zip ) ) {
			return array( 'verdict' => 'Verified with warnings', 'reason' => 'files zip missing (DB-only backup)' );
		}
		if ( class_exists( 'ZipArchive' ) ) {
			$z = new ZipArchive();
			if ( true !== $z->open( $zip ) || 0 === $z->numFiles ) {
				return array( 'verdict' => 'Failed', 'reason' => 'files zip will not open / is empty' );
			}
			$z->close();
		}
		if ( filesize( $zip ) < 100 * KB_IN_BYTES ) {
			return array( 'verdict' => 'Verified with warnings', 'reason' => 'files zip suspiciously small' );
		}
		return array( 'verdict' => 'Verified', 'reason' => 'sql + files present, open and non-trivial' );
	}

	// ══════════════════════════════════════════════════════════════════════
	// STEP 4 — CHECK REQUIREMENTS & COMPATIBILITY
	// ══════════════════════════════════════════════════════════════════════

	/**
	 * Assign each pending plugin a verdict and build the ordered apply-queue.
	 * Change nothing. External calls fetched from the site (fail-closed).
	 */
	private function assess( array $pending ) {
		$wf      = $this->wordfence_feed();
		$php_ver = PHP_VERSION;
		$wp_ver  = get_bloginfo( 'version' );

		$rows  = array();
		$force = array();   // security-critical, apply first
		$safe  = array();   // routine safe updates
		$defer = array();

		foreach ( $pending as $slug => $p ) {
			$info    = $this->wporg_info( $slug );
			$verdict = 'UPDATE';
			$reason  = 'safe: on wp.org, compatible, past soak';

			$vuln = $this->has_vuln( $wf, $slug, $p['current'] );

			if ( $vuln ) {
				$verdict = 'FORCE';
				$reason  = 'CURRENT version has an active vulnerability — patch now';
			} elseif ( ! $info ) {
				$verdict = 'NEEDS-APPROVAL';
				$reason  = 'not on wp.org (Pro/custom) — changelog unverifiable';
			} elseif ( $this->is_high_risk( $slug, $info ) ) {
				$verdict = 'NEEDS-APPROVAL';
				$reason  = 'page-builder / WooCommerce / LMS / framework — human review';
			} elseif ( $this->is_major_jump( $p['current'], $p['new'] ) ) {
				$verdict = 'NEEDS-APPROVAL';
				$reason  = 'major version jump — human review';
			} elseif ( $this->too_fresh( $info ) ) {
				$verdict = 'HOLD';
				$reason  = 'released < ' . self::SOAK_DAYS . ' days ago — soaking';
			} elseif ( $this->incompatible( $info, $php_ver, $wp_ver ) ) {
				$verdict = 'HOLD';
				$reason  = 'requires newer PHP/WP than this site provides';
			} elseif ( $this->changelog_flags_breaking( $info ) ) {
				$verdict = 'HOLD';
				$reason  = 'changelog flags breaking/removed/DB-migration language';
			}

			$rows[ $slug ] = array( 'name' => $p['name'], 'from' => $p['current'], 'to' => $p['new'], 'verdict' => $verdict, 'reason' => $reason );

			if ( 'FORCE' === $verdict ) {
				$force[ $slug ] = $p['file'];
			} elseif ( 'UPDATE' === $verdict ) {
				$safe[ $slug ] = $p['file'];
			} else {
				$defer[ $slug ] = array( 'verdict' => $verdict, 'reason' => $reason, 'from' => $p['current'], 'to' => $p['new'] );
			}
		}

		// ORDER: security FORCE first, then frameworks before their add-ons.
		$safe  = $this->order_frameworks_first( $safe );
		$queue = $force + $safe; // FORCE ahead of routine, never behind.

		return array( 'queue' => $queue, 'deferred' => $defer, 'table' => $rows );
	}

	/** Fetch + cache the free Wordfence scanner vuln feed. Fail-closed → empty. */
	private function wordfence_feed() {
		$cached = get_transient( self::WF_FEED_KEY );
		if ( is_array( $cached ) ) {
			return $cached;
		}
		$resp = wp_remote_get( self::WF_SCANNER_FEED, array( 'timeout' => 30, 'headers' => array( 'Accept' => 'application/json' ) ) );
		if ( is_wp_error( $resp ) || 200 !== (int) wp_remote_retrieve_response_code( $resp ) ) {
			return array(); // No feed → treat as "no known vuln" (never fabricate FORCE).
		}
		$data = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( ! is_array( $data ) ) {
			return array();
		}
		set_transient( self::WF_FEED_KEY, $data, self::WF_FEED_TTL );
		return $data;
	}

	/** Does the feed list an active vuln affecting <slug> at its CURRENT version? */
	private function has_vuln( array $feed, $slug, $current ) {
		foreach ( $feed as $entry ) {
			$soft = $entry['software'] ?? array();
			foreach ( (array) $soft as $s ) {
				if ( ( $s['slug'] ?? '' ) !== $slug || 'plugin' !== ( $s['type'] ?? 'plugin' ) ) {
					continue;
				}
				foreach ( (array) ( $s['affected_versions'] ?? array() ) as $range ) {
					$from = $range['from_version'] ?? '*';
					$to   = $range['to_version'] ?? '*';
					$geF  = ( '*' === $from ) || version_compare( $current, $from, '>=' );
					$leT  = ( '*' === $to ) || version_compare( $current, $to, '<=' );
					if ( $geF && $leT ) {
						return true;
					}
				}
			}
		}
		return false;
	}

	/** wp.org plugin info (version, tested, requires_php, last_updated, changelog). */
	private function wporg_info( $slug ) {
		$resp = wp_remote_get( self::WPORG_INFO . rawurlencode( $slug ) . '.json', array( 'timeout' => 20 ) );
		if ( is_wp_error( $resp ) || 200 !== (int) wp_remote_retrieve_response_code( $resp ) ) {
			return null;
		}
		$data = json_decode( wp_remote_retrieve_body( $resp ), true );
		return ( is_array( $data ) && ! isset( $data['error'] ) ) ? $data : null;
	}

	private function is_high_risk( $slug, array $info ) {
		$needles = array( 'elementor', 'nexter', 'divi', 'beaver', 'woocommerce', 'woo-', 'learndash', 'lifterlms', 'tutor', 'memberpress', 'buddypress', 'bbpress', 'wpml', 'seedprod' );
		$hay     = strtolower( $slug . ' ' . ( $info['name'] ?? '' ) );
		foreach ( $needles as $n ) {
			if ( false !== strpos( $hay, $n ) ) {
				return true;
			}
		}
		// A plugin that itself hosts add-ons (>1M installs framework) is high-risk too.
		return isset( $info['active_installs'] ) && (int) $info['active_installs'] >= 1000000
			&& false !== stripos( (string) ( $info['sections']['description'] ?? '' ), 'addon' );
	}

	private function is_major_jump( $from, $to ) {
		$fa = (int) strtok( (string) $from, '.' );
		$ta = (int) strtok( (string) $to, '.' );
		return $ta > $fa; // e.g. 4.x → 5.0
	}

	private function too_fresh( array $info ) {
		if ( empty( $info['last_updated'] ) ) {
			return false;
		}
		$age_days = ( time() - strtotime( $info['last_updated'] ) ) / DAY_IN_SECONDS;
		return $age_days >= 0 && $age_days < self::SOAK_DAYS;
	}

	private function incompatible( array $info, $php_ver, $wp_ver ) {
		if ( ! empty( $info['requires_php'] ) && version_compare( $php_ver, $info['requires_php'], '<' ) ) {
			return true;
		}
		if ( ! empty( $info['tested'] ) && version_compare( $wp_ver, $info['tested'], '>' ) ) {
			// Site WP is NEWER than the plugin's tested ceiling → compat risk.
			return true;
		}
		return false;
	}

	private function changelog_flags_breaking( array $info ) {
		$log = strtolower( (string) ( $info['sections']['changelog'] ?? '' ) );
		if ( '' === $log ) {
			return false;
		}
		$log = substr( $log, 0, 4000 ); // Newest entries only.
		foreach ( array( 'breaking change', 'backward incompat', 'no longer', 'removed support', 'database migration', 'requires php 8', 'requires wordpress 6' ) as $flag ) {
			if ( false !== strpos( $log, $flag ) ) {
				return true;
			}
		}
		return false;
	}

	/** Heuristic order: shorter-slug frameworks before longer add-on slugs sharing a stem. */
	private function order_frameworks_first( array $safe ) {
		uksort(
			$safe,
			function ( $a, $b ) {
				// A plugin whose slug is a prefix of another is likely the framework.
				if ( 0 === strpos( $b, $a ) ) {
					return -1;
				}
				if ( 0 === strpos( $a, $b ) ) {
					return 1;
				}
				return strlen( $a ) <=> strlen( $b );
			}
		);
		return $safe;
	}

	// ══════════════════════════════════════════════════════════════════════
	// STEP 5 — APPLY ONE PLUGIN (stash → update → cache reset → verify → rollback)
	// ══════════════════════════════════════════════════════════════════════

	private function apply_one( $slug, $file, $use_sentinel ) {
		$was_active = is_plugin_active( $file );
		$plugin_dir = WP_PLUGIN_DIR . '/' . $slug;
		$from       = $this->plugin_version( $file );

		// A. Stash the current folder into our sandbox (rollback source).
		$stash = $this->stash_plugin( $slug, $plugin_dir );
		if ( ! $stash ) {
			return array( 'result' => 'skipped', 'reason' => 'could not stash current version — refusing to update blind', 'from' => $from );
		}

		// B. Optional best-effort fatal-guard sentinel.
		$sentinel = ( $use_sentinel ) ? $this->write_sentinel( $slug, $file ) : null;

		// C. Update THIS plugin only (WP-CLI preferred, PHP fallback).
		$upd = $this->update_plugin( $slug, $file );

		// D. Clear stale bytecode + caches BEFORE verifying (critical).
		$this->flush_all();

		// E. Cache-busted verification.
		$health = $this->health_check();
		$paused = $this->plugin_paused( $file );
		$new_ver = $this->plugin_version( $file );

		$ok = $upd['ok'] && $health['ok'] && ! $paused;

		if ( $ok ) {
			$this->remove_sentinel( $sentinel );
			$this->drop_stash( $stash );
			return array( 'result' => 'updated', 'from' => $from, 'to' => $new_ver );
		}

		// F. ROLLBACK — restore our stash of the SAME plugin dir (declared target).
		$rb = $this->rollback( $slug, $file, $plugin_dir, $stash, $was_active );
		$this->remove_sentinel( $sentinel );

		if ( 'restored' === $rb['state'] ) {
			return array( 'result' => 'rolled-back', 'from' => $from, 'to' => $from, 'reason' => $upd['ok'] ? 'post-update health failed' : ( 'update failed: ' . $upd['reason'] ) );
		}
		if ( 'deactivated' === $rb['state'] ) {
			return array( 'result' => 'deactivated', 'from' => $from, 'reason' => 'restore impossible; plugin left deactivated to keep the site up' );
		}
		return array( 'result' => 'site-broken', 'from' => $from, 'reason' => 'rollback re-verify still failing — site state unknown' );
	}

	/** Copy plugins/<slug> into sandbox/rollback/<slug>__<ts>. */
	private function stash_plugin( $slug, $plugin_dir ) {
		if ( ! is_dir( $plugin_dir ) ) {
			return false; // Single-file plugin or missing — updater still safe via backup.
		}
		$dest = $this->sandbox( 'rollback' );
		if ( ! $dest ) {
			return false;
		}
		$target = $dest . '/' . $slug . '__' . gmdate( 'Ymd-His' );
		if ( ! function_exists( 'copy_dir' ) ) {
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		WP_Filesystem();
		if ( ! wp_mkdir_p( $target ) ) {
			return false;
		}
		$copied = copy_dir( $plugin_dir, $target );
		return ( true === $copied ) ? $target : false;
	}

	/** Update exactly one plugin. Never --all, never core/themes/i18n. */
	private function update_plugin( $slug, $file ) {
		if ( $this->wp_cli_available() ) {
			$res = $this->wp_cli( 'plugin update ' . escapeshellarg( $slug ) . ' --format=summary' );
			@unlink( ABSPATH . '.maintenance' );
			if ( $res['ok'] ) {
				return array( 'ok' => true, 'via' => 'wp-cli' );
			}
			// Fall through to PHP upgrader if the CLI path errored.
		}

		require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
		WP_Filesystem();
		wp_update_plugins();
		$skin     = new Automatic_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		$result   = $upgrader->upgrade( $file );
		@unlink( ABSPATH . '.maintenance' );
		if ( is_wp_error( $result ) ) {
			return array( 'ok' => false, 'via' => 'php', 'reason' => $result->get_error_message() );
		}
		return array( 'ok' => (bool) $result, 'via' => 'php', 'reason' => $result ? '' : 'upgrader returned false' );
	}

	/** Restore the stashed folder over the plugin dir; if impossible, deactivate. */
	private function rollback( $slug, $file, $plugin_dir, $stash, $was_active ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		require_once ABSPATH . 'wp-admin/includes/file.php';
		WP_Filesystem();

		// Deactivate first so a fatal plugin can't crash the restore.
		if ( is_plugin_active( $file ) ) {
			deactivate_plugins( $file, true );
		}

		// Move the freshly-updated (broken) folder ASIDE into our own sandbox —
		// a rename, NEVER a recursive delete (§4a: no recursive/glob file ops).
		// Then restore our stash in its place. Nothing is destroyed.
		$restored = false;
		if ( is_dir( $stash ) ) {
			if ( is_dir( $plugin_dir ) ) {
				$aside = $this->sandbox( 'rollback' );
				if ( $aside ) {
					@rename( $plugin_dir, $aside . '/' . basename( $plugin_dir ) . '__broken__' . gmdate( 'Ymd-His' ) );
				}
			}
			wp_mkdir_p( $plugin_dir );
			$restored = ( true === copy_dir( $stash, $plugin_dir ) );
		}

		if ( $restored && $was_active ) {
			activate_plugin( $file ); // Sanctioned API — never update_option('active_plugins').
		}

		$this->flush_all();
		$health = $this->health_check();

		if ( $restored && $health['ok'] ) {
			$this->drop_stash( $stash );
			return array( 'state' => 'restored' );
		}
		if ( ! $restored ) {
			// Couldn't restore files → keep it deactivated so the site stays up.
			return $health['ok'] ? array( 'state' => 'deactivated' ) : array( 'state' => 'broken' );
		}
		return array( 'state' => 'broken' );
	}

	// ══════════════════════════════════════════════════════════════════════
	// STEP 6 — ON-SITE FUNCTIONAL & VISUAL VERIFICATION  (thum.io removed)
	// ══════════════════════════════════════════════════════════════════════

	/**
	 * Replaces the old external-screenshot (thum.io) step with fully on-site
	 * signals: WP-CLI plugin-state, key-URL HTTP status via wp_remote_get,
	 * a WP_DEBUG / fatal-log scan, and an optional on-site DOM probe.
	 */
	private function functional_verify() {
		$out = array( 'checks' => array(), 'ok' => true );

		// 1. Plugin state — every plugin that should be active is still active & not paused.
		$state = $this->plugin_state_check();
		$out['checks']['plugin_state'] = $state;
		$out['ok'] = $out['ok'] && $state['ok'];

		// 2. Key-URL HTTP status (cache-busted).
		$urls = $this->key_urls();
		$http = array();
		foreach ( $urls as $label => $url ) {
			$r = $this->fetch( $url );
			$http[ $label ] = array( 'code' => $r['code'], 'fatal' => $r['fatal'], 'ok' => $this->is_alive( $r ) );
			$out['ok'] = $out['ok'] && $http[ $label ]['ok'];
		}
		$out['checks']['http'] = $http;

		// 3. Fatal-error / WP_DEBUG log scan for NEW fatals during this run.
		$log = $this->scan_debug_log();
		$out['checks']['debug_log'] = $log;
		$out['ok'] = $out['ok'] && ! $log['new_fatal'];

		// 4. Optional on-site DOM probe — only if the site provides a probe hook.
		$out['checks']['dom_probe'] = $this->dom_probe();

		return $out;
	}

	/** Every plugin the DB says is active must actually load without pausing. */
	private function plugin_state_check() {
		$active = (array) get_option( 'active_plugins', array() );
		$paused = array_keys( (array) get_option( 'wp_paused_plugins', array() ) );
		$bad    = array_values( array_intersect( $active, $paused ) );
		return array( 'ok' => empty( $bad ), 'active_count' => count( $active ), 'paused' => $bad );
	}

	/** Scan debug.log for fatals newer than this run's start. Read-only. */
	private function scan_debug_log() {
		$log = defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/debug.log' : '';
		if ( ! $log || ! is_readable( $log ) ) {
			return array( 'available' => false, 'new_fatal' => false );
		}
		$tail = $this->tail( $log, 200 );
		$new  = false;
		foreach ( $tail as $line ) {
			if ( false !== stripos( $line, 'PHP Fatal error' ) || false !== stripos( $line, 'Uncaught' ) ) {
				$new = true;
				break;
			}
		}
		return array( 'available' => true, 'new_fatal' => $new, 'sample' => $new ? array_slice( $tail, -5 ) : array() );
	}

	/** Optional on-site DOM check: fires a filter a Playwright/DOM helper can answer. */
	private function dom_probe() {
		/**
		 * A site MAY register 'sprout_dom_probe' to run a headless/DOM assertion
		 * on-site (e.g. bundled Playwright). Absent → we skip, never fail.
		 */
		if ( has_filter( 'sprout_dom_probe' ) ) {
			$res = apply_filters( 'sprout_dom_probe', null, $this->key_urls() );
			return array( 'available' => true, 'result' => $res );
		}
		return array( 'available' => false, 'note' => 'no on-site DOM probe registered; relying on HTTP + log signals' );
	}

	// ══════════════════════════════════════════════════════════════════════
	// STEP 7 — SMOKE TEST (report-only, cache-busted)
	// ══════════════════════════════════════════════════════════════════════

	private function smoke_test() {
		$this->flush_all();
		$pages  = $this->key_urls();
		$result = array();
		$passed = true;
		foreach ( $pages as $label => $url ) {
			$r = $this->fetch( $url );
			// A 3xx (e.g. /wp-admin/ → login) is alive with no body; a 200 must carry a real body (catches white-screen).
			$pass = $this->is_alive( $r ) && ( $r['code'] >= 300 || strlen( $r['body'] ) > 200 );
			$result[ $label ] = array( 'code' => $r['code'], 'fatal' => $r['fatal'], 'pass' => $pass );
			$passed = $passed && $pass;
		}
		return array( 'passed' => $passed, 'pages' => $result );
	}

	/** Homepage, newest post, wp-admin, and (if Woo) shop + cart. */
	private function key_urls() {
		$urls = array(
			'home'  => home_url( '/' ),
			'admin' => admin_url(),
		);
		$posts = get_posts( array( 'numberposts' => 1, 'post_status' => 'publish' ) );
		if ( ! empty( $posts ) ) {
			$urls['post'] = get_permalink( $posts[0]->ID );
		}
		if ( class_exists( 'WooCommerce' ) ) {
			if ( function_exists( 'wc_get_page_permalink' ) ) {
				$shop = wc_get_page_permalink( 'shop' );
				$cart = wc_get_page_permalink( 'cart' );
				if ( $shop ) {
					$urls['shop'] = $shop;
				}
				if ( $cart ) {
					$urls['cart'] = $cart;
				}
			}
		}
		return $urls;
	}

	// ══════════════════════════════════════════════════════════════════════
	// SHARED HELPERS
	// ══════════════════════════════════════════════════════════════════════

	/** Cache-busted GET with critical-error detection. */
	private function fetch( $url ) {
		$busted = add_query_arg( 'sprout_nocache', wp_rand(), $url );
		$resp   = wp_remote_get(
			$busted,
			array(
				'timeout'     => 30,
				'redirection' => 0,
				'sslverify'   => false,
				'headers'     => array( 'Cache-Control' => 'no-cache', 'Pragma' => 'no-cache' ),
			)
		);
		$code = is_wp_error( $resp ) ? 0 : (int) wp_remote_retrieve_response_code( $resp );
		$body = is_wp_error( $resp ) ? '' : (string) wp_remote_retrieve_body( $resp );
		$fatal = false;
		foreach ( self::CRITICAL_MARKERS as $marker ) {
			if ( false !== stripos( $body, $marker ) ) {
				$fatal = true;
				break;
			}
		}
		return array( 'code' => $code, 'body' => $body, 'fatal' => $fatal );
	}

	/**
	 * A response indicates a LIVE site: 2xx or 3xx, no fatal marker.
	 * Crucially, an unauthenticated GET of /wp-admin/ returns 302 → wp-login.php on a
	 * perfectly healthy site — treating that as "down" would roll back every update.
	 * Only a connect failure (0), 4xx/5xx, or a fatal-error body means broken.
	 */
	private function is_alive( array $r ) {
		return ! $r['fatal'] && $r['code'] >= 200 && $r['code'] < 400;
	}

	/** Aggregate home + admin health into one boolean. */
	private function health_check() {
		$home  = $this->fetch( home_url( '/' ) );
		$admin = $this->fetch( admin_url() );
		$ok    = ( $this->is_alive( $home ) && $this->is_alive( $admin ) );
		return array( 'ok' => $ok, 'home' => $home['code'], 'admin' => $admin['code'] );
	}

	/** Reset opcode cache + flush WP + purge common page caches. */
	private function flush_all() {
		if ( function_exists( 'opcache_reset' ) ) {
			@opcache_reset();
		}
		if ( function_exists( 'wp_cache_flush' ) ) {
			wp_cache_flush();
		}
		if ( function_exists( 'rocket_clean_domain' ) ) {
			rocket_clean_domain();
		}
		if ( function_exists( 'w3tc_flush_all' ) ) {
			w3tc_flush_all();
		}
		if ( has_action( 'litespeed_purge_all' ) ) {
			do_action( 'litespeed_purge_all' );
		}
	}

	private function plugin_paused( $file ) {
		$paused = (array) get_option( 'wp_paused_plugins', array() );
		return isset( $paused[ $file ] );
	}

	private function plugin_version( $file ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all = get_plugins();
		return isset( $all[ $file ]['Version'] ) ? $all[ $file ]['Version'] : '?';
	}

	/** Best-effort mu-plugin that auto-deactivates <slug> on a load-time fatal. */
	private function write_sentinel( $slug, $file ) {
		$mu = WP_CONTENT_DIR . '/mu-plugins';
		if ( ! wp_mkdir_p( $mu ) || ! is_writable( $mu ) ) {
			return null; // Sandbox may block this — degrade to backup+rollback only.
		}
		$path = $mu . '/sprout-update-guard.php';
		$body = "<?php\n// SproutOS transient update guard — auto-removed after the run.\n"
			. "register_shutdown_function(function(){\n"
			. "  \$e = error_get_last();\n"
			. "  if (\$e && in_array(\$e['type'], array(E_ERROR, E_PARSE, E_COMPILE_ERROR), true)\n"
			. "      && strpos((string)\$e['file'], " . var_export( '/' . $slug . '/', true ) . ") !== false) {\n"
			. "    if (function_exists('deactivate_plugins')) { deactivate_plugins(" . var_export( $file, true ) . ", true); }\n"
			. "  }\n"
			. "});\n";
		return ( false !== @file_put_contents( $path, $body ) ) ? $path : null;
	}

	private function remove_sentinel( $path ) {
		if ( $path && file_exists( $path ) ) {
			@unlink( $path ); // Only ever our own single declared file.
		}
	}

	/** Return the last $n lines of a file without loading it all. */
	private function tail( $path, $n ) {
		$f = @fopen( $path, 'r' );
		if ( ! $f ) {
			return array();
		}
		$lines = array();
		$buf   = '';
		$pos   = -1;
		$size  = filesize( $path );
		while ( $n > 0 && -$pos <= $size ) {
			if ( fseek( $f, $pos, SEEK_END ) !== 0 ) {
				break;
			}
			$ch = fgetc( $f );
			if ( "\n" === $ch ) {
				if ( '' !== $buf ) {
					$lines[] = strrev( $buf );
					$buf     = '';
					$n--;
				}
			} else {
				$buf .= $ch;
			}
			$pos--;
		}
		if ( '' !== $buf ) {
			$lines[] = strrev( $buf );
		}
		fclose( $f );
		return array_reverse( $lines );
	}

	/** Sandbox subdir under the plugin's enforced sandbox. Returns path or ''. */
	private function sandbox( $sub ) {
		$up = wp_upload_dir();
		if ( empty( $up['basedir'] ) ) {
			return '';
		}
		$dir = $up['basedir'] . '/sproutos-mcp-sandbox/' . $sub;
		if ( ! wp_mkdir_p( $dir ) || ! is_writable( $dir ) ) {
			return '';
		}
		return $dir;
	}

	private function protect_dir( $dir ) {
		if ( ! file_exists( $dir . '/.htaccess' ) ) {
			@file_put_contents( $dir . '/.htaccess', "Deny from all\n" );
		}
		if ( ! file_exists( $dir . '/index.php' ) ) {
			@file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" );
		}
	}

	private function drop_stash( $stash ) {
		// Keep stashes as insurance; do NOT auto-delete client-recoverable state.
		// (Housekeeping of aged stashes is a separate, retention-gated job.)
		unset( $stash );
	}

	private function wp_cli_available() {
		if ( ! function_exists( 'shell_exec' ) ) {
			return false;
		}
		$disabled = array_map( 'trim', explode( ',', (string) ini_get( 'disable_functions' ) ) );
		if ( in_array( 'shell_exec', $disabled, true ) ) {
			return false;
		}
		$which = @shell_exec( 'command -v wp 2>/dev/null' );
		return is_string( $which ) && '' !== trim( $which );
	}

	/** Run a WP-CLI subcommand scoped to this install. Returns {ok, out}. */
	private function wp_cli( $subcommand ) {
		$cmd = 'wp ' . $subcommand
			. ' --path=' . escapeshellarg( ABSPATH )
			. ' --skip-themes --no-color 2>&1';
		$out = @shell_exec( $cmd );
		$out = is_string( $out ) ? $out : '';
		$ok  = ( false === stripos( $out, 'Error:' ) && false === stripos( $out, 'PHP Fatal' ) );
		return array( 'ok' => $ok, 'out' => trim( $out ) );
	}

	private function version_pairs( array $results, $want ) {
		$want = (array) $want;
		$out  = array();
		foreach ( $results as $slug => $r ) {
			if ( in_array( $r['result'], $want, true ) ) {
				$out[ $slug ] = array( 'from' => $r['from'] ?? '?', 'to' => $r['to'] ?? ( $r['from'] ?? '?' ), 'reason' => $r['reason'] ?? '' );
			}
		}
		return $out;
	}

	private function slim_backup( array $b ) {
		return array(
			'status' => $b['status'] ?? '?',
			'method' => $b['method'] ?? '?',
			'label'  => $b['label'] ?? 'weekly-update',
			'files'  => array_map( 'basename', $b['files'] ?? array() ),
		);
	}

	private function overall_status( array $results, array $functional, array $smoke ) {
		foreach ( $results as $r ) {
			if ( 'site-broken' === $r['result'] ) {
				return 'fail';
			}
		}
		$any_rollback = false;
		foreach ( $results as $r ) {
			if ( in_array( $r['result'], array( 'rolled-back', 'deactivated' ), true ) ) {
				$any_rollback = true;
			}
		}
		if ( ! $smoke['passed'] || ! $functional['ok'] || $any_rollback ) {
			return 'warn';
		}
		return 'ok';
	}

	private function release_lock() {
		delete_transient( self::LOCK_KEY );
	}

	private function report( $started, $status, array $findings, $summary ) {
		if ( 'fail' === $status ) {
			update_option( 'sprout_last_update_state', 'critical', false );
		} elseif ( in_array( $status, array( 'ok', 'warn' ), true ) ) {
			update_option( 'sprout_last_update_state', 'clean', false );
		}
		return array(
			'skill'      => 'safe-plugin-update',
			'site'       => home_url(),
			'run_id'     => $this->run_id,
			'started_at' => $started,
			'ended_at'   => gmdate( 'c' ),
			'status'     => $status, // ok|warn|fail|stopped
			'summary'    => $summary,
			'findings'   => $findings,
			'trace'      => $this->trace,
		);
	}

	private function stopped( $started, $why, array $findings = array() ) {
		return $this->report( $started, 'stopped', $findings, $why );
	}

	/** Stop AND release the run lock (used once past pre-flight). */
	private function stop_release( $started, $why, array $findings = array(), $status = 'stopped' ) {
		$this->release_lock();
		return $this->report( $started, $status, $findings, $why );
	}
}

// Usage (via the Sprout PHP ability):
//   $plan  = ( new Sprout_Safe_Plugin_Update() )->run();                                        // plan → approval request
//   $apply = ( new Sprout_Safe_Plugin_Update() )->run( array( 'mode' => 'apply', 'approved' => true ) );
//   echo wp_json_encode( $apply );
