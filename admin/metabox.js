/**
 * JS for the plugin admin metabox
 */

( function( $, wp, pluginDirectory ) {
	var ScanMetabox = {
		ready: function() {
			window.Prism = window.Prism || {};
			Prism.manual = true;
			$( '#scan_plugin_version' ).on( 'change', ScanMetabox.selectPlugin );

			if ( $( '#scan_plugin_output .placeholder' ).length ) {
				ScanMetabox.scanPlugin('');
			}
		},

		selectPlugin: function() {
			ScanMetabox.scanPlugin( $( this ).val() );
		},

		scanPlugin: function( version ) {
			var data = {
					_ajax_nonce: $( '#scan_plugin_nonce' ).val(),
					version:     version,
					p:           $( '#post_ID' ).val(),
				},
				$output = $( '#scan_plugin_output' );

			$output.html( '<p>Loading...</p>' );

			wp.ajax.post( 'scan-plugin', data ).done( function( response ) {
				response = wpAjax.parseAjaxResponse( response );

				$output.html( response.responses[0].data );
			} ).fail( function( response, t, e ) {
				$output.html( '<p>Error loading plugin scan.</p>' );
				console.debug( response );
				console.debug( t );
				console.debug( e );
			} ).done( function() {
				Prism.highlightAllUnder( $output.get(0), true );
			} );
		}

	};

	$( ScanMetabox.ready );
} )( window.jQuery, window.wp, window.pluginDirectory );