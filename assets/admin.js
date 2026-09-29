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
		registryWrap: document.getElementById( 'wfam-registry-wrap' ),
		registryBody: document.querySelector( '#wfam-registry tbody' ),
		auditBody: document.querySelector( '#wfam-audit tbody' ),
		dialog: document.getElementById( 'wfam-dialog' ),
	};

	const state = {
		page: 1,
		requestId: 0,
		clockOffset: 0, // server time - browser time, in ms.
		reloadQueued: false,
	};

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

	/** Current time in unix seconds, corrected to the server clock. */
	function now() {
		return ( Date.now() + state.clockOffset ) / 1000;
	}

	function syncClock( serverTime ) {
		if ( serverTime ) {
			state.clockOffset = serverTime * 1000 - Date.now();
		}
	}

	/**
	 * "1 h 05 m", "4 m 09 s", "2 d 3 h".
	 *
	 * @param {number} seconds
	 * @return {string}
	 */
	function duration( seconds ) {
		const s = Math.max( 0, Math.floor( seconds ) );
		const d = Math.floor( s / 86400 );
		const h = Math.floor( ( s % 86400 ) / 3600 );
		const m = Math.floor( ( s % 3600 ) / 60 );
		const pad = ( n ) => String( n ).padStart( 2, '0' );
		if ( d ) {
			return d + ' d ' + h + ' h';
		}
		if ( h ) {
			return h + ' h ' + pad( m ) + ' m';
		}
		return m + ' m ' + pad( s % 60 ) + ' s';
	}

	/**
	 * A live countdown element; ticked by tick().
	 *
	 * @param {number} until Unix seconds.
	 * @return {HTMLElement}
	 */
	function countdown( until ) {
		const node = el( 'strong', { class: 'wfam-countdown', 'data-until': until } );
		renderCountdown( node );
		return node;
	}

	function renderCountdown( node ) {
		const left = Number( node.dataset.until ) - now();
		if ( left <= 0 ) {
			node.textContent = t.expired;
			node.classList.add( 'is-expired' );
			return false;
		}
		node.textContent = fmt( t.left, duration( left ) );
		return true;
	}

	/** Updates every countdown each second; reloads once when one reaches 0. */
	function tick() {
		let expired = false;
		root.querySelectorAll( '.wfam-countdown:not(.is-expired)' ).forEach( ( node ) => {
			if ( ! renderCountdown( node ) ) {
				expired = true;
			}
		} );
		if ( expired && ! state.reloadQueued ) {
			state.reloadQueued = true;
			setTimeout( () => {
				state.reloadQueued = false;
				loadBlocks();
				loadRegistry();
			}, 2000 );
		}
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
			setTimeout( () => notice.remove(), 12000 );
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

	/** Date -> value for <input type="datetime-local"> (browser local time). */
	function toLocalInput( date ) {
		const pad = ( n ) => String( n ).padStart( 2, '0' );
		return date.getFullYear() + '-' + pad( date.getMonth() + 1 ) + '-' + pad( date.getDate() ) + 'T' + pad( date.getHours() ) + ':' + pad( date.getMinutes() );
	}

	/* ------------------------------------------------------------------ */
	/* Confirmation dialog                                                */
	/* ------------------------------------------------------------------ */

	const presetSeconds = { '1h': 3600, '4h': 14400, '24h': 86400, '7d': 604800 };

	/**
	 * Resolves the dialog's expiry choice to unix seconds, or null if the
	 * custom value is missing/out of range.
	 *
	 * @param {HTMLFormElement} form
	 * @return {?{choice:string, ts:number}}
	 */
	function readExpiry( form ) {
		const choice = form.querySelector( '[name="expiry"]:checked' ).value;
		if ( presetSeconds[ choice ] ) {
			return { choice, ts: Math.floor( now() ) + presetSeconds[ choice ] };
		}
		const value = form.elements.custom.value;
		const ts = value ? Math.floor( new Date( value ).getTime() / 1000 ) : NaN;
		if ( ! Number.isFinite( ts ) || ts < now() + cfg.minSeconds || ts > now() + cfg.maxSeconds ) {
			return null;
		}
		return { choice, ts };
	}

	function updateExpiryPreview( form ) {
		const isCustom = 'custom' === form.querySelector( '[name="expiry"]:checked' ).value;
		form.querySelector( '.wfam-custom' ).hidden = ! isCustom;
		const expiry = readExpiry( form );
		form.querySelector( '.wfam-expiry-preview' ).textContent = expiry
			? fmt( t.helperUntil, new Date( expiry.ts * 1000 ).toLocaleString() )
			: ( isCustom ? t.customInvalid : '' );
	}

	/**
	 * Opens the confirmation dialog. Resolves with the choice on confirm or
	 * null on cancel. Falls back to window.confirm without <dialog>.
	 *
	 * @param {{title:string, message:string, warning?:string, withExpiry?:boolean}} opts
	 * @return {Promise<?{note:string, choice:string, ts:number}>}
	 */
	function confirmDialog( opts ) {
		const dialog = els.dialog;
		if ( ! dialog || 'function' !== typeof dialog.showModal ) {
			const text = [ opts.title, opts.message, opts.warning ].filter( Boolean ).join( '\n\n' );
			// eslint-disable-next-line no-alert
			return Promise.resolve( window.confirm( text ) ? { note: '', choice: '1h', ts: 0 } : null );
		}

		const form = dialog.querySelector( 'form' );
		const warning = dialog.querySelector( '.wfam-dialog-warning' );
		const error = dialog.querySelector( '.wfam-dialog-error' );
		const fields = dialog.querySelector( '.wfam-dialog-fields' );

		dialog.querySelector( 'h2' ).textContent = opts.title;
		dialog.querySelector( '.wfam-dialog-message' ).textContent = opts.message;
		warning.textContent = opts.warning || '';
		warning.hidden = ! opts.warning;
		error.hidden = true;
		fields.hidden = ! opts.withExpiry;

		form.elements.note.value = '';
		form.querySelector( '[name="expiry"][value="1h"]' ).checked = true;
		const min = new Date( ( now() + cfg.minSeconds + 60 ) * 1000 );
		form.elements.custom.min = toLocalInput( min );
		form.elements.custom.max = toLocalInput( new Date( ( now() + cfg.maxSeconds ) * 1000 ) );
		form.elements.custom.value = '';
		updateExpiryPreview( form );
		dialog.returnValue = '';

		return new Promise( ( resolve ) => {
			let result = null;

			// Validate before the dialog closes, so a bad custom time keeps it open.
			const onSubmit = ( event ) => {
				if ( ! event.submitter || 'confirm' !== event.submitter.value ) {
					return;
				}
				if ( opts.withExpiry ) {
					const expiry = readExpiry( form );
					if ( ! expiry ) {
						event.preventDefault();
						error.textContent = t.customInvalid;
						error.hidden = false;
						return;
					}
					result = { note: form.elements.note.value.trim(), choice: expiry.choice, ts: expiry.ts };
				} else {
					result = { note: '', choice: '', ts: 0 };
				}
			};

			form.addEventListener( 'submit', onSubmit );
			dialog.addEventListener(
				'close',
				() => {
					form.removeEventListener( 'submit', onSubmit );
					resolve( 'confirm' === dialog.returnValue ? result : null );
				},
				{ once: true }
			);
			dialog.showModal();
			dialog.querySelector( 'button[value="cancel"]' ).focus();
		} );
	}

	/* ------------------------------------------------------------------ */
	/* Locked-out IPs table                                               */
	/* ------------------------------------------------------------------ */

	function allowlistCell( r ) {
		if ( r.helperExpiresAt ) {
			return [
				el( 'span', { class: 'wfam-badge is-temp' }, fmt( t.helperUntil, r.helperExpires ) ),
				el( 'div', {}, countdown( r.helperExpiresAt ) ),
			];
		}
		if ( r.allowlisted ) {
			return el( 'span', { class: 'wfam-badge is-yes' }, t.wordfenceEntry );
		}
		return el( 'span', { class: 'wfam-badge is-no' }, t.notAllowlisted );
	}

	function renderBlocks( rows, totalAll ) {
		fillBody(
			els.blocksBody,
			rows.map( ( r ) => [
				[
					el( 'code', {}, r.ip ),
					r.firewallBlock ? el( 'div', { class: 'wfam-warn' }, t.firewallBlock ) : null,
				],
				[
					r.username ? el( 'code', {}, r.username ) : '—',
					r.otherUsernames ? el( 'div', { class: 'wfam-muted' }, fmt( t.others, r.otherUsernames ) ) : null,
				],
				r.member ? el( 'a', { href: r.member.url }, r.member.name ) : el( 'span', { class: 'wfam-muted' }, t.noMatch ),
				[
					el( 'strong', {}, String( r.attempts ) ),
					el( 'div', { class: 'wfam-muted' }, fmt( t.attemptsTotal, r.attemptsTotal ) ),
				],
				[
					el( 'strong', {}, r.cause ),
					el( 'div', { class: 'wfam-muted wfam-reason' }, r.reason ),
				],
				r.blockedAt,
				r.expiresAt
					? [ countdown( r.expiresAt ), el( 'div', { class: 'wfam-muted' }, r.expires ) ]
					: el( 'strong', {}, t.noExpiry ),
				allowlistCell( r ),
				el(
					'div',
					{ class: 'wfam-actions' },
					el( 'button', { type: 'button', class: 'button button-small', 'data-act': 'unblock', 'data-ip': r.ip }, t.unblock ),
					( r.canAllowlist && ( ! r.allowlisted || r.helperExpiresAt ) )
						? el( 'button', { type: 'button', class: 'button button-small button-primary', 'data-act': 'unblock_allowlist', 'data-ip': r.ip, 'data-many': r.manyUsernames }, t.unblockAllowlist )
						: null
				),
			] ),
			totalAll ? t.noneFiltered : t.none
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
			syncClock( res.serverTime );
			state.page = res.page;
			renderBlocks( res.rows, res.totalAll );
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
	/* Temporary allowlist + audit                                        */
	/* ------------------------------------------------------------------ */

	async function loadRegistry() {
		setBusy( els.registryWrap, true );
		try {
			const res = await post( 'registry' );
			syncClock( res.serverTime );
			fillBody(
				els.registryBody,
				res.entries.map( ( e ) => [
					el( 'code', {}, e.ip ),
					e.note || '—',
					e.addedBy,
					e.added,
					e.expiresAt ? [ countdown( e.expiresAt ), el( 'div', { class: 'wfam-muted' }, e.expires ) ] : e.expires,
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
	 */
	async function runAction( action, data, button ) {
		if ( button ) {
			button.disabled = true;
		}
		try {
			const res = await post( action, data );
			notify( 'success', res.message );
		} catch ( e ) {
			notify( 'error', e.message );
		} finally {
			if ( button ) {
				button.disabled = false;
			}
			await Promise.all( [ loadBlocks(), loadRegistry() ] );
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
			const choice = await confirmDialog( { title: t.confirmAllowT, message: fmt( t.confirmAllow, ip ), warning, withExpiry: true } );
			if ( choice ) {
				runAction( 'unblock_allowlist', { ip, note: choice.note, expiry: choice.choice, custom_ts: 'custom' === choice.choice ? choice.ts : 0 }, button );
			}
		} else if ( 'remove_allowlist' === act ) {
			if ( await confirmDialog( { title: t.confirmRemoveT, message: fmt( t.confirmRemove, ip ) } ) ) {
				runAction( 'remove_allowlist', { ip }, button );
			}
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

	if ( els.dialog ) {
		const form = els.dialog.querySelector( 'form' );
		form.addEventListener( 'change', () => updateExpiryPreview( form ) );
		form.addEventListener( 'input', () => updateExpiryPreview( form ) );
	}

	loadBlocks();
	loadRegistry();
	setInterval( tick, 1000 );
}() );
