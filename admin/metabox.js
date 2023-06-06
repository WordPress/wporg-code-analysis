/**
 * JS for the plugin admin metabox
 */

( function( $, wp, pluginDirectory ) {
	var ScanMetabox = {
		ready: function() {
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

			wp.ajax.post( 'scan-plugin', data ).always( function( response ) {
				response = wpAjax.parseAjaxResponse( response );

				$output.html( response.responses[0].data );
			} );
		}

	};

	$( ScanMetabox.ready );
} )( window.jQuery, window.wp, window.pluginDirectory );