/**
 * Wordfence → Access Manager admin screen.
 *
 * Plain JS, no dependencies. All server data is inserted with textContent /
 * text nodes (never innerHTML): attempted usernames are attacker-controlled.
 *
 * @package Wordfence_Access_Manager
 */
/* global wfamHelper */
( function () {
	'use strict';

	const cfg = window.wfamHelper;
	const root = document.querySelector( '.wfam' );
	if ( ! cfg || ! root ) {
		return;
	}
	const t = cfg.i18n;

	const els = {
		filters: document.getElementById( 'wfam-filters' ),
		blocksWrap: document.getElementById( 'wfam-blocks-wrap' ),
		blocksBody: document.querySelector( '#wfam-blocks tbody' ),
		prev: document.getElementById( 'wfam-prev' ),
		next: document.getElementById( 'wfam-next' ),
		pageInfo: document.getElementById( 'wfam-pageinfo' ),
		refresh: document.getElementById( 'wfam-refresh' ),
		notices: document.getElementById( 'wfam-notices' ),
		addForm: document.getElementById( 'wfam-add-form' ),
		registryWrap: document.getElementById( 'wfam-registry-wrap' ),
		registryBody: document.querySelector( '#wfam-registry tbody' ),
		auditBody: document.querySelector( '#wfam-audit tbody' ),
		dialog: document.getElementById( 'wfam-dialog' ),
	};

	const state = { page: 1, requestId: 0 };

	/* ------------------------------------------------------------------ */
	/* Helpers                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Minimal sprintf for the localized strings: %s, %d, %1$s, %2$d …
	 *
	 * @param {string} str
	 * @param {...*}   args
	 * @return {string}
	 */
	function fmt( str, ...args ) {
		let auto = 0;
		return str.replace( /%(?:(\d+)\$)?([sd])/g, ( match, pos ) => {
			const value = pos ? args[ pos - 1 ] : args[ auto++ ];
			return undefined === value ? match : String( value );
		} );
	}

	/**
	 * Creates an element. Children that are not Nodes become text nodes.
	 *
	 * @param {string} tag
	 * @param {Object} attrs
	 * @param {...*}   children
	 * @return {HTMLElement}
	 */
	function el( tag, attrs = {}, ...children ) {
		const node = document.createElement( tag );
		Object.entries( attrs ).forEach( ( [ key, value ] ) => {
			if ( null === value || undefined === value || false === value ) {
				return;
			}
			if ( 'class' === key ) {
				node.className = value;
			} else {
				node.setAttribute( key, true === value ? '' : String( value ) );
			}
		} );
		children.flat().forEach( ( child ) => {
			if ( null === child || undefined === child || false === child ) {
				return;
			}
			node.append( child instanceof Node ? child : document.createTextNode( String( child ) ) );
		} );
		return node;
	}

	/**
	 * POSTs to admin-ajax.php with the nonce. Resolves with `data`, rejects
	 * with an Error carrying the server message.
	 *
	 * @param {string} action Suffix after "wfam_".
	 * @param {Object} data
	 * @return {Promise<Object>}
	 */
	async function post( action, data = {} ) {
		const body = new FormData();
		body.append( 'action', 'wfam_' + action );
		body.append( 'nonce', cfg.nonce );
		Object.entries( data ).forEach( ( [ key, value ] ) => body.append( key, value ) );

		let response;
		try {
			response = await fetch( cfg.ajaxUrl, { method: 'POST', credentials: 'same-origin', body } );
		} catch ( e ) {
			throw new Error( t.requestFailed );
		}

		let json = null;
		try {
			json = await response.json();
		} catch ( e ) {
			// Non-JSON (e.g. "0" when logged out) falls through to the generic error.
		}
		if ( ! json || ! json.success ) {
			throw new Error( json && json.data && json.data.message ? json.data.message : t.requestFailed );
		}
		return json.data;
	}

	/**
	 * Shows a dismissible WP-style notice at the top of the screen.
	 *
	 * @param {'success'|'error'} type
	 * @param {string}            message
	 */
	function notify( type, message ) {
		const dismiss = el( 'button', { type: 'button', class: 'notice-dismiss' }, el( 'span', { class: 'screen-reader-text' }, 'Dismiss' ) );
		const notice = el( 'div', { class: 'notice inline is-dismissible notice-' + type }, el( 'p', {}, message ), dismiss );
		dismiss.addEventListener( 'click', () => notice.remove() );
		els.notices.prepend( notice );
		if ( 'success' === type ) {
			setTimeout( () => notice.remove(), 10000 );
		}
		notice.scrollIntoView( { block: 'nearest', behavior: 'smooth' } );
	}

	function setBusy( wrap, busy ) {
		wrap.classList.toggle( 'is-loading', busy );
		wrap.setAttribute( 'aria-busy', busy ? 'true' : 'false' );
	}

	/** Header labels, reused as data-label for the stacked mobile layout. */
	function headerLabels( body ) {
		return Array.from( body.closest( 'table' ).querySelectorAll( 'thead th' ) ).map( ( th ) => th.textContent.trim() );
	}

	function fillBody( body, rows, emptyText ) {
		const labels = headerLabels( body );
		body.replaceChildren();
		if ( ! rows.length ) {
			body.append( el( 'tr', {}, el( 'td', { colspan: labels.length, class: 'wfam-empty' }, emptyText ) ) );
			return;
		}
		rows.forEach( ( cells ) => {
			body.append( el( 'tr', {}, cells.map( ( cell, i ) => el( 'td', { 'data-label': labels[ i ] }, cell ) ) ) );
		} );
	}

	function debounce( fn, wait ) {
		let timer;
		return ( ...args ) => {
			clearTimeout( timer );
			timer = setTimeout( () => fn( ...args ), wait );
		};
	}

	/* ------------------------------------------------------------------ */
	/* Confirmation dialog                                                */
	/* ------------------------------------------------------------------ */

	/**
	 * Opens the confirmation dialog. Resolves with {note, expiry} on confirm
	 * or null on cancel. Falls back to window.confirm without <dialog>.
	 *
	 * @param {{title:string, message:string, warning?:string, withFields?:boolean}} opts
	 * @return {Promise<?{note:string, expiry:string}>}
	 */
	function confirmDialog( opts ) {
		const dialog = els.dialog;
		if ( ! dialog || 'function' !== typeof dialog.showModal ) {
			const text = [ opts.title, opts.message, opts.warning ].filter( Boolean ).join( '\n\n' );
			return Promise.resolve( window.confirm( text ) ? { note: '', expiry: '7' } : null ); // eslint-disable-line no-alert
		}

		const warning = dialog.querySelector( '.wfam-dialog-warning' );
		const fields = dialog.querySelector( '.wfam-dialog-fields' );
		const note = fields.querySelector( '[name="note"]' );
		const expiry = fields.querySelector( '[name="expiry"]' );

		dialog.querySelector( 'h2' ).textContent = opts.title;
		dialog.querySelector( '.wfam-dialog-message' ).textContent = opts.message;
		warning.textContent = opts.warning || '';
		warning.hidden = ! opts.warning;
		fields.hidden = ! opts.withFields;
		note.value = '';
		expiry.value = '7';
		dialog.returnValue = '';

		return new Promise( ( resolve ) => {
			dialog.addEventListener(
				'close',
				() => resolve( 'confirm' === dialog.returnValue ? { note: note.value.trim(), expiry: expiry.value } : null ),
				{ once: true }
			);
			dialog.showModal();
			( opts.withFields ? note : dialog.querySelector( 'button[value="cancel"]' ) ).focus();
		} );
	}

	/* ------------------------------------------------------------------ */
	/* Blocked IPs table                                                  */
	/* ------------------------------------------------------------------ */

	function renderBlocks( rows ) {
		fillBody(
			els.blocksBody,
			rows.map( ( r ) => [
				el( 'code', {}, r.ip ),
				r.member ? el( 'a', { href: r.member.url }, r.member.name ) : el( 'span', { class: 'wfam-muted' }, t.noMatch ),
				[
					r.username ? el( 'code', {}, r.username ) : '—',
					r.otherUsernames ? el( 'div', { class: 'wfam-muted' }, fmt( t.others, r.otherUsernames ) ) : null,
				],
				[
					String( r.attempts ),
					r.blockedHits ? el( 'div', { class: 'wfam-muted' }, fmt( t.blockedHits, r.blockedHits ) ) : null,
				],
				r.lastAttempt,
				r.types.join( ', ' ),
				el( 'span', { class: 'wfam-reason' }, r.reason || '—' ),
				r.expiration,
				r.allowlisted
					? el( 'span', { class: 'wfam-badge is-yes' }, r.helperOwned ? t.yes + ' (' + t.helperAdded + ')' : t.yes )
					: el( 'span', { class: 'wfam-badge is-no' }, t.no ),
				el(
					'div',
					{ class: 'wfam-actions' },
					el( 'button', { type: 'button', class: 'button button-small', 'data-act': 'unblock', 'data-ip': r.ip }, t.unblock ),
					r.allowlisted
						? null
						: el( 'button', { type: 'button', class: 'button button-small button-primary', 'data-act': 'unblock_allowlist', 'data-ip': r.ip, 'data-many': r.manyUsernames }, t.unblockAllowlist )
				),
			] ),
			t.none
		);
	}

	/**
	 * Loads the current page with the current filters. Out-of-order
	 * responses (fast typing) are ignored via requestId.
	 */
	async function loadBlocks() {
		const id = ++state.requestId;
		const data = Object.fromEntries( new FormData( els.filters ) );
		data.page = state.page;

		setBusy( els.blocksWrap, true );
		try {
			const res = await post( 'list', data );
			if ( id !== state.requestId ) {
				return;
			}
			state.page = res.page;
			renderBlocks( res.rows );
			els.pageInfo.textContent = fmt( t.pageOf, res.page, res.pages, res.total );
			els.prev.disabled = res.page <= 1;
			els.next.disabled = res.page >= res.pages;
		} catch ( e ) {
			if ( id === state.requestId ) {
				notify( 'error', e.message );
			}
		} finally {
			if ( id === state.requestId ) {
				setBusy( els.blocksWrap, false );
			}
		}
	}

	/* ------------------------------------------------------------------ */
	/* Helper registry + audit                                            */
	/* ------------------------------------------------------------------ */

	async function loadRegistry() {
		setBusy( els.registryWrap, true );
		try {
			const res = await post( 'registry' );
			fillBody(
				els.registryBody,
				res.entries.map( ( e ) => [
					el( 'code', {}, e.ip ),
					e.note || '—',
					e.addedBy,
					e.added,
					e.expiry,
					el( 'button', { type: 'button', class: 'button button-small button-link-delete', 'data-act': 'remove_allowlist', 'data-ip': e.ip }, t.remove ),
				] ),
				t.noHelperEntries
			);
			fillBody(
				els.auditBody,
				res.audit.map( ( a ) => [ a.time, a.user, a.action, el( 'code', {}, a.ip ), a.details || '—' ] ),
				t.noAudit
			);
		} catch ( e ) {
			notify( 'error', e.message );
		} finally {
			setBusy( els.registryWrap, false );
		}
	}

	/* ------------------------------------------------------------------ */
	/* Actions                                                            */
	/* ------------------------------------------------------------------ */

	/**
	 * Runs a mutating action, then reloads both tables.
	 *
	 * @param {string}             action
	 * @param {Object}             data
	 * @param {?HTMLButtonElement} button Disabled while running.
	 * @return {Promise<boolean>} Success.
	 */
	async function runAction( action, data, button ) {
		if ( button ) {
			button.disabled = true;
		}
		try {
			const res = await post( action, data );
			notify( 'success', res.message );
			await Promise.all( [ loadBlocks(), loadRegistry() ] );
			return true;
		} catch ( e ) {
			notify( 'error', e.message );
			return false;
		} finally {
			if ( button ) {
				button.disabled = false;
			}
		}
	}

	async function onTableAction( event ) {
		const button = event.target.closest( 'button[data-act]' );
		if ( ! button ) {
			return;
		}
		const ip = button.dataset.ip;
		const act = button.dataset.act;

		if ( 'unblock' === act ) {
			if ( await confirmDialog( { title: t.confirmUnblockT, message: fmt( t.confirmUnblock, ip ) } ) ) {
				runAction( 'unblock', { ip }, button );
			}
		} else if ( 'unblock_allowlist' === act ) {
			const many = parseInt( button.dataset.many || '0', 10 );
			const warning = ( many ? fmt( t.manyWarning, many ) + ' ' : '' ) + t.dynamicWarning;
			const choice = await confirmDialog( { title: t.confirmAllowT, message: fmt( t.confirmAllow, ip ), warning, withFields: true } );
			if ( choice ) {
				runAction( 'unblock_allowlist', { ip, note: choice.note, expiry: choice.expiry }, button );
			}
		} else if ( 'remove_allowlist' === act ) {
			if ( await confirmDialog( { title: t.confirmRemoveT, message: fmt( t.confirmRemove, ip ) } ) ) {
				runAction( 'remove_allowlist', { ip }, button );
			}
		}
	}

	async function onAddSubmit( event ) {
		event.preventDefault();
		const form = els.addForm;
		const ip = form.elements.ip.value.trim();
		if ( ! ip ) {
			form.elements.ip.focus();
			return;
		}

		const ok = await confirmDialog( { title: t.confirmAddT, message: fmt( t.confirmAdd, ip ), warning: t.dynamicWarning } );
		if ( ! ok ) {
			return;
		}

		const done = await runAction(
			'add_allowlist',
			{
				ip,
				note: form.elements.note.value.trim(),
				expiry: form.elements.expiry.value,
				unblock: form.elements.unblock.checked ? '1' : '0',
			},
			form.querySelector( 'button[type="submit"]' )
		);
		if ( done ) {
			form.elements.ip.value = '';
			form.elements.note.value = '';
		}
	}

	/* ------------------------------------------------------------------ */
	/* Wiring                                                             */
	/* ------------------------------------------------------------------ */

	const reloadFromFirstPage = () => {
		state.page = 1;
		loadBlocks();
	};

	els.filters.addEventListener( 'input', debounce( ( e ) => {
		if ( 'INPUT' === e.target.tagName ) {
			reloadFromFirstPage();
		}
	}, 350 ) );
	els.filters.addEventListener( 'change', ( e ) => {
		if ( 'SELECT' === e.target.tagName ) {
			reloadFromFirstPage();
		}
	} );
	els.refresh.addEventListener( 'click', () => {
		loadBlocks();
		loadRegistry();
	} );
	els.prev.addEventListener( 'click', () => {
		state.page = Math.max( 1, state.page - 1 );
		loadBlocks();
	} );
	els.next.addEventListener( 'click', () => {
		state.page += 1;
		loadBlocks();
	} );
	els.blocksBody.addEventListener( 'click', onTableAction );
	els.registryBody.addEventListener( 'click', onTableAction );
	els.addForm.addEventListener( 'submit', onAddSubmit );

	loadBlocks();
	loadRegistry();
}() );
