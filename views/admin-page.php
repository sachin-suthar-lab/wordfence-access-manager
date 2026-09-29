<?php
/**
 * Wordfence → Access Manager screen shell. Table bodies are filled by
 * assets/admin.js over AJAX.
 *
 * Variables from WFAM_Admin::render_page():
 *
 * @var array                 $settings      WFAM_Wordfence::lockout_settings().
 * @var array<string, string> $cause_labels
 * @var string                $current_ip
 * @var bool                  $ip_is_public
 * @var array<string, string> $expiry_labels
 * @var callable              $human_minutes
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

$wfam_settings_url = admin_url( 'admin.php?page=WordfenceWAF&subpage=waf_options#waf-options-bruteforce' );
?>
<div class="wrap wfam">
	<h1><?php esc_html_e( 'Access Manager', 'wordfence-access-manager' ); ?></h1>
	<p class="wfam-intro">
		<?php esc_html_e( 'People currently locked out by Wordfence because of failed login attempts. Lockout times come from Wordfence and are not changed here. Unblock a legitimate user, or unblock them and allowlist their IP for a limited time.', 'wordfence-access-manager' ); ?>
	</p>

	<section class="wfam-card wfam-settings" aria-label="<?php esc_attr_e( 'Wordfence login lockout settings', 'wordfence-access-manager' ); ?>">
		<h2><?php esc_html_e( 'Wordfence lockout rules in effect', 'wordfence-access-manager' ); ?></h2>
		<?php if ( ! $settings['enabled'] ) : ?>
			<p class="notice notice-warning inline"><?php esc_html_e( 'Wordfence brute force protection is turned off, so Wordfence is not creating new login lockouts.', 'wordfence-access-manager' ); ?></p>
		<?php endif; ?>
		<ul class="wfam-settings-list">
			<li>
				<span><?php esc_html_e( 'Lock out after', 'wordfence-access-manager' ); ?></span>
				<strong>
					<?php
					/* translators: 1: number of failures, 2: time period. */
					echo esc_html( sprintf( __( '%1$d failed logins within %2$s', 'wordfence-access-manager' ), $settings['max_failures'], $human_minutes( $settings['count_window'] ) ) );
					?>
				</strong>
			</li>
			<li>
				<span><?php esc_html_e( 'Password reset attempts', 'wordfence-access-manager' ); ?></span>
				<strong><?php echo esc_html( (string) $settings['max_forgot'] ); ?></strong>
			</li>
			<li>
				<span><?php esc_html_e( 'Lockout lasts', 'wordfence-access-manager' ); ?></span>
				<strong><?php echo esc_html( $settings['lockout_seconds'] > 0 ? $human_minutes( $settings['lockout_seconds'] ) : __( 'No expiry', 'wordfence-access-manager' ) ); ?></strong>
			</li>
			<li>
				<span><?php esc_html_e( 'Unknown username/email', 'wordfence-access-manager' ); ?></span>
				<strong><?php echo $settings['lock_invalid'] ? esc_html__( 'Locked out immediately', 'wordfence-access-manager' ) : esc_html__( 'Counted as a failure', 'wordfence-access-manager' ); ?></strong>
			</li>
		</ul>
		<p class="description">
			<?php esc_html_e( 'These are read from Wordfence and only shown for reference. Change them in Wordfence:', 'wordfence-access-manager' ); ?>
			<a href="<?php echo esc_url( $wfam_settings_url ); ?>"><?php esc_html_e( 'Firewall Options → Brute Force Protection', 'wordfence-access-manager' ); ?></a>.
			<?php esc_html_e( 'A lockout keeps the end time it was given when it started, even if the setting changes later.', 'wordfence-access-manager' ); ?>
		</p>
		<p class="description">
			<?php esc_html_e( 'Your IP as Wordfence sees it:', 'wordfence-access-manager' ); ?>
			<code><?php echo esc_html( '' !== $current_ip ? $current_ip : '—' ); ?></code>
			<?php if ( ! $ip_is_public ) : ?>
				<strong class="wfam-warn"><?php esc_html_e( 'This is a private or reserved address: the site is probably behind a proxy or CDN and Wordfence may be seeing the proxy instead of visitors. Check "How does Wordfence get IPs" before allowlisting anything.', 'wordfence-access-manager' ); ?></strong>
			<?php endif; ?>
		</p>
	</section>

	<div id="wfam-notices" class="wfam-notices" aria-live="polite"></div>

	<section class="wfam-card">
		<h2><?php esc_html_e( 'Currently locked out', 'wordfence-access-manager' ); ?></h2>

		<form id="wfam-filters" class="wfam-filters" role="search" onsubmit="return false;">
			<label>
				<span><?php esc_html_e( 'IP address', 'wordfence-access-manager' ); ?></span>
				<input type="search" name="ip" maxlength="64" autocomplete="off">
			</label>
			<label>
				<span><?php esc_html_e( 'Username / email / member', 'wordfence-access-manager' ); ?></span>
				<input type="search" name="user" maxlength="100" autocomplete="off">
			</label>
			<label>
				<span><?php esc_html_e( 'Cause', 'wordfence-access-manager' ); ?></span>
				<select name="cause">
					<?php foreach ( $cause_labels as $cause_key => $cause_label ) : ?>
						<option value="<?php echo esc_attr( $cause_key ); ?>"><?php echo esc_html( $cause_label ); ?></option>
					<?php endforeach; ?>
				</select>
			</label>
			<label>
				<span><?php esc_html_e( 'Allowlisted', 'wordfence-access-manager' ); ?></span>
				<select name="allowlisted">
					<option value="all"><?php esc_html_e( 'All', 'wordfence-access-manager' ); ?></option>
					<option value="yes"><?php esc_html_e( 'Allowlisted', 'wordfence-access-manager' ); ?></option>
					<option value="no"><?php esc_html_e( 'Not allowlisted', 'wordfence-access-manager' ); ?></option>
				</select>
			</label>
			<label>
				<span><?php esc_html_e( 'Show', 'wordfence-access-manager' ); ?></span>
				<select name="member">
					<option value="all"><?php esc_html_e( 'All lockouts', 'wordfence-access-manager' ); ?></option>
					<option value="likely"><?php esc_html_e( 'Likely members only', 'wordfence-access-manager' ); ?></option>
				</select>
			</label>
			<button type="button" class="button" id="wfam-refresh"><?php esc_html_e( 'Refresh', 'wordfence-access-manager' ); ?></button>
		</form>

		<div class="wfam-table-wrap" id="wfam-blocks-wrap" aria-busy="false">
			<table class="widefat striped wfam-table" id="wfam-blocks">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'IP address', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Attempted username / email', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'WordPress user', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Failed attempts', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Block reason', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Blocked at', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Lockout remaining', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Allowlist status', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Actions', 'wordfence-access-manager' ); ?></th>
					</tr>
				</thead>
				<tbody></tbody>
			</table>
			<div class="wfam-loading" aria-hidden="true"><span class="spinner is-active"></span></div>
		</div>

		<div class="wfam-pagination">
			<button type="button" class="button" id="wfam-prev" aria-label="<?php esc_attr_e( 'Previous page', 'wordfence-access-manager' ); ?>">&lsaquo;</button>
			<span id="wfam-pageinfo"></span>
			<button type="button" class="button" id="wfam-next" aria-label="<?php esc_attr_e( 'Next page', 'wordfence-access-manager' ); ?>">&rsaquo;</button>
		</div>

		<p class="description">
			<?php esc_html_e( '"Failed attempts" counts the failures Wordfence logged from the IP in its counting window before the lockout. "WordPress user" only means an attempted username or email matches an account; it does not prove the IP belongs to that person, so confirm with the user first.', 'wordfence-access-manager' ); ?>
		</p>
	</section>

	<section class="wfam-card">
		<h2><?php esc_html_e( 'Temporary allowlist (added by this helper)', 'wordfence-access-manager' ); ?></h2>
		<div class="wfam-table-wrap" id="wfam-registry-wrap" aria-busy="false">
			<table class="widefat striped wfam-table" id="wfam-registry">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'IP', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Note', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Added by', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Added', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Expires', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Actions', 'wordfence-access-manager' ); ?></th>
					</tr>
				</thead>
				<tbody></tbody>
			</table>
		</div>
		<p class="description"><?php esc_html_e( 'Each entry is removed from the Wordfence allowlist automatically when it expires, after which normal Wordfence protection applies. Entries added directly in the Wordfence settings are never changed by this helper.', 'wordfence-access-manager' ); ?></p>
	</section>

	<details class="wfam-card wfam-audit">
		<summary><?php esc_html_e( 'Recent activity (audit log)', 'wordfence-access-manager' ); ?></summary>
		<div class="wfam-table-wrap">
			<table class="widefat striped wfam-table" id="wfam-audit">
				<thead>
					<tr>
						<th scope="col"><?php esc_html_e( 'When', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Admin', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Action', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'IP', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Details', 'wordfence-access-manager' ); ?></th>
					</tr>
				</thead>
				<tbody></tbody>
			</table>
		</div>
	</details>

	<dialog id="wfam-dialog" class="wfam-dialog" aria-labelledby="wfam-dialog-title">
		<form method="dialog">
			<h2 id="wfam-dialog-title"></h2>
			<p class="wfam-dialog-message"></p>
			<p class="wfam-dialog-warning notice notice-warning inline" hidden></p>
			<div class="wfam-dialog-fields" hidden>
				<fieldset>
					<legend><?php esc_html_e( 'Allowlist for', 'wordfence-access-manager' ); ?></legend>
					<div class="wfam-expiry-choices">
						<?php foreach ( $expiry_labels as $value => $label ) : ?>
							<label class="wfam-radio">
								<input type="radio" name="expiry" value="<?php echo esc_attr( $value ); ?>" <?php checked( $value, '1h' ); ?>>
								<span><?php echo esc_html( $label ); ?></span>
							</label>
						<?php endforeach; ?>
					</div>
				</fieldset>
				<label class="wfam-custom" hidden>
					<span><?php esc_html_e( 'Expires at (your local time)', 'wordfence-access-manager' ); ?></span>
					<input type="datetime-local" name="custom">
				</label>
				<p class="wfam-expiry-preview description"></p>
				<label>
					<span><?php esc_html_e( 'Note (optional)', 'wordfence-access-manager' ); ?></span>
					<input type="text" name="note" maxlength="200" placeholder="<?php esc_attr_e( 'e.g. Jane Doe called support', 'wordfence-access-manager' ); ?>">
				</label>
			</div>
			<p class="wfam-dialog-error notice notice-error inline" hidden></p>
			<div class="wfam-dialog-buttons">
				<button type="submit" value="cancel" class="button" formnovalidate><?php esc_html_e( 'Cancel', 'wordfence-access-manager' ); ?></button>
				<button type="submit" value="confirm" class="button button-primary"><?php esc_html_e( 'Confirm', 'wordfence-access-manager' ); ?></button>
			</div>
		</form>
	</dialog>
</div>
