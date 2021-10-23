<?php
    class cyphper {

        function __construct() {
            // nothing to see here
        }

        public static function bytes_gen( $length = 16, $strongEnforce = true ) {
            $bytes = openssl_random_pseudo_bytes( $length, $strongResult );
            if( false === $strongResult && true === $strongEnforce ) {
                return cyphper::hex_gen( $length );
            } else {
                return $bytes;
            }
        }

        public static function hex_gen( $length = 16, $strongEnforce = true ) {
            $bytes = cyphper::bytes_gen( $length / 2 );
            return bin2hex( $bytes );
        }

        public static function hmac_sign( $ct, $key ) {
            return hash_hmac( 'sha256', $ct, $key ) . $ct;
        }

        public static function hmac_auth( $msg, $key ) {
            $hmac = substr( $msg, 0, 64 );
            $ct = substr( $msg, 64 );
            return hash_equals( hash_hmac( 'sha256', $ct, $key ), $hmac );
        }

        public static function encrypt( string $pt, string $key = null, string $iv = null ) {
            $key = ( empty( $key ) || 32 > strlen( $key )) ? cyphper::hex_gen( 32 ) : $key;
            $iv = ( empty( $iv ) || 16 > strlen( $iv )) ? cyphper::hex_gen( 16 ) : $iv;
            $ct = openssl_encrypt( $pt, 'AES-256-CTR', $key, 0, $iv );
            $msg = cyphper::hmac_sign( $ct, $key );
            return array( 'message' => $msg, 'key' => $key, 'iv' => $iv );
        }

        public static function decrypt( string $msg, string $key, string $iv ) {
            if( true !== cyphper::hmac_auth( $msg, $key )) {
                return false;
            } else {
                $ct = substr( $msg, 64 );
                return openssl_decrypt( $ct, 'AES-256-CTR', $key, 0, $iv );
            }
        }
    }
