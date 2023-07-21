/**
 * JS for the detail page
 */

( function( $, wp, pluginDirectory ) {
	var ScanDetail = {
		ready: function() {
			window.Prism = window.Prism || {};
		},

		moveMessages: function( env ) {
			$( '.message-detail' ).each( function() {
				var $this = $( this ),
					$target   = $( '#line-' + $this.data( 'line' ) );

				if ( $target.length ) {
					$target.append( $this );
				}
			} );
		},

		selectPlugin: function() {
			ScanDetail.scanPlugin( $( this ).val() );
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
				$output.html( response );
				Prism.highlightAllUnder( $output.get(0), true );
			} ).fail( function( response, t, e ) {
				$output.append( '<p>Error loading plugin scan.</p>' );
			} );
		}

	};

	$( ScanDetail.ready );
} )( window.jQuery, window.wp, window.pluginDirectory );