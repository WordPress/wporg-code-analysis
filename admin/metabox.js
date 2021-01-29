/**
 * JS for the plugin admin metabox
 */

( function( $, wp, pluginDirectory ) {
    var ScanMetabox = {
        ready: function() {
            data = {
                _ajax_nonce: $( '#scan_plugin_nonce' ).val(),
                p:           $( '#post_ID' ).val(),
            };
            wp.ajax.post( 'scan-plugin', data ).always( function( response ) {
                response = wpAjax.parseAjaxResponse( response );

                console.log( 'ajax response', response.responses[0].data );

                $( '#scan_plugin_output' ).html( response.responses[0].data );

            } );
        }

    };

    $( ScanMetabox.ready );
} )( window.jQuery, window.wp, window.pluginDirectory );