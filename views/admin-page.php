<?php
/**
 * Wordfence → Access Manager screen shell. Table bodies are filled by
 * assets/admin.js over AJAX.
 *
 * Variables from WFAM_Admin::render_page():
 *
 * @var array<int, string>    $type_labels
 * @var string                $current_ip
 * @var bool                  $ip_is_public
 * @var bool                  $ip_allowed
 * @var array<string, string> $expiry_labels
 *
 * @package Wordfence_Access_Manager
 */

defined( 'ABSPATH' ) || exit;

$wfam_expiry_options = static function () use ( $expiry_labels ) {
	foreach ( $expiry_labels as $value => $label ) {
		printf( '<option value="%1$s"%3$s>%2$s</option>', esc_attr( $value ), esc_html( $label ), selected( $value, '7', false ) );
	}
};
?>
<div class="wrap wfam">
	<h1><?php esc_html_e( 'Access Manager', 'wordfence-access-manager' ); ?></h1>
	<p class="wfam-intro">
		<?php esc_html_e( 'IPs Wordfence is currently blocking or locking out. Unblock a trusted user, or unblock and allowlist a trusted fixed IP. All actions use Wordfence\'s own functions; Wordfence settings and login protection for everyone else are not changed.', 'wordfence-access-manager' ); ?>
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=WordfenceWAF#top#blocking' ) ); ?>"><?php esc_html_e( 'Wordfence Blocking', 'wordfence-access-manager' ); ?></a> ·
		<a href="<?php echo esc_url( admin_url( 'admin.php?page=WordfenceWAF&subpage=waf_options' ) ); ?>"><?php esc_html_e( 'Firewall Options (full allowlist)', 'wordfence-access-manager' ); ?></a>
	</p>

	<div class="notice inline <?php echo $ip_is_public ? 'notice-info' : 'notice-warning'; ?> wfam-ipinfo">
		<p>
			<?php esc_html_e( 'Your IP as Wordfence sees it:', 'wordfence-access-manager' ); ?>
			<code><?php echo esc_html( '' !== $current_ip ? $current_ip : '—' ); ?></code>
			<?php echo $ip_allowed ? esc_html__( '(allowlisted)', 'wordfence-access-manager' ) : esc_html__( '(not allowlisted)', 'wordfence-access-manager' ); ?>
		</p>
		<?php if ( ! $ip_is_public ) : ?>
			<p><strong><?php esc_html_e( 'This is a private or reserved address.', 'wordfence-access-manager' ); ?></strong> <?php esc_html_e( 'The site is probably behind a proxy, load balancer or CDN, and Wordfence may be seeing the proxy instead of visitors. Check Wordfence → All Options → General Wordfence Options → "How does Wordfence get IPs" before allowlisting anything.', 'wordfence-access-manager' ); ?></p>
		<?php endif; ?>
	</div>

	<div id="wfam-notices" class="wfam-notices" aria-live="polite"></div>

	<section class="wfam-card">
		<h2><?php esc_html_e( 'Blocked IPs', 'wordfence-access-manager' ); ?></h2>

		<form id="wfam-filters" class="wfam-filters" role="search" onsubmit="return false;">
			<label>
				<span><?php esc_html_e( 'IP address', 'wordfence-access-manager' ); ?></span>
				<input type="search" name="ip" maxlength="64" autocomplete="off" placeholder="203.0.113.10">
			</label>
			<label>
				<span><?php esc_html_e( 'Username / email', 'wordfence-access-manager' ); ?></span>
				<input type="search" name="user" maxlength="100" autocomplete="off">
			</label>
			<label>
				<span><?php esc_html_e( 'Block type', 'wordfence-access-manager' ); ?></span>
				<select name="type">
					<option value="all"><?php esc_html_e( 'All types', 'wordfence-access-manager' ); ?></option>
					<?php foreach ( $type_labels as $type_id => $type_label ) : ?>
						<option value="<?php echo esc_attr( (string) $type_id ); ?>"><?php echo esc_html( $type_label ); ?></option>
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
					<option value="all"><?php esc_html_e( 'All blocks', 'wordfence-access-manager' ); ?></option>
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
						<th scope="col"><?php esc_html_e( 'Member / user', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Username / email attempted', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Failed logins', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Last attempt', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Block type', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Block reason', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Expires', 'wordfence-access-manager' ); ?></th>
						<th scope="col"><?php esc_html_e( 'Allowlisted', 'wordfence-access-manager' ); ?></th>
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
			<?php esc_html_e( '"Likely member" only means an attempted username or email matches a WordPress account. It does not prove the IP belongs to that person; confirm with the user before allowlisting.', 'wordfence-access-manager' ); ?>
		</p>
	</section>

	<div class="wfam-grid">
		<section class="wfam-card">
			<h2><?php esc_html_e( 'Add IP to Allowlist', 'wordfence-access-manager' ); ?></h2>
			<form id="wfam-add-form" class="wfam-add-form" novalidate>
				<label>
					<span><?php esc_html_e( 'IP address (single public IP)', 'wordfence-access-manager' ); ?></span>
					<input type="text" name="ip" required maxlength="45" autocomplete="off" spellcheck="false" placeholder="203.0.113.10">
				</label>
				<label>
					<span><?php esc_html_e( 'Note (optional)', 'wordfence-access-manager' ); ?></span>
					<input type="text" name="note" maxlength="200" placeholder="<?php esc_attr_e( 'e.g. Jane Doe – head office', 'wordfence-access-manager' ); ?>">
				</label>
				<label>
					<span><?php esc_html_e( 'Expires', 'wordfence-access-manager' ); ?></span>
					<select name="expiry"><?php $wfam_expiry_options(); ?></select>
				</label>
				<label class="wfam-check">
					<input type="checkbox" name="unblock" value="1" checked>
					<span><?php esc_html_e( 'Also remove any current block or login lockout for this IP', 'wordfence-access-manager' ); ?></span>
				</label>
				<p><button type="submit" class="button button-primary"><?php esc_html_e( 'Add to allowlist', 'wordfence-access-manager' ); ?></button></p>
				<p class="description"><?php esc_html_e( 'Only allowlist fixed addresses (office, VPN exit). Home and mobile IPs change; if one is reassigned, a stranger inherits the bypass. For those, use Unblock only.', 'wordfence-access-manager' ); ?></p>
			</form>
		</section>

		<section class="wfam-card">
			<h2><?php esc_html_e( 'Added through this helper', 'wordfence-access-manager' ); ?></h2>
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
			<p class="description"><?php esc_html_e( 'Only entries added here can be removed here. Entries added directly in Wordfence are never changed by this helper.', 'wordfence-access-manager' ); ?></p>
		</section>
	</div>

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
				<label>
					<span><?php esc_html_e( 'Note (optional)', 'wordfence-access-manager' ); ?></span>
					<input type="text" name="note" maxlength="200">
				</label>
				<label>
					<span><?php esc_html_e( 'Expires', 'wordfence-access-manager' ); ?></span>
					<select name="expiry"><?php $wfam_expiry_options(); ?></select>
				</label>
			</div>
			<div class="wfam-dialog-buttons">
				<button type="submit" value="cancel" class="button"><?php esc_html_e( 'Cancel', 'wordfence-access-manager' ); ?></button>
				<button type="submit" value="confirm" class="button button-primary"><?php esc_html_e( 'Confirm', 'wordfence-access-manager' ); ?></button>
			</div>
		</form>
	</dialog>
</div>
