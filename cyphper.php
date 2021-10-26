<?php
    class cyphper {

        function __construct() {
            // nothing to see here...yet
        }

        public static function bytes_gen( int $length = 16, bool $strongEnforce = true ): string {
            $bytes = openssl_random_pseudo_bytes( $length, $strongResult );
            if( false === $strongResult && true === $strongEnforce ) {
                return cyphper::hex_gen( $length );
            } else {
                return $bytes;
            }
        }

        public static function hex_gen( int $length = 16, bool $strongEnforce = true ): string {
            $bytes = cyphper::bytes_gen( $length / 2 );
            return bin2hex( $bytes );
        }

        public static function hmac_sign( string $ct, string $key ): string {
            return hash_hmac( 'sha256', $ct, $key ) . $ct;
        }

        public static function hmac_auth( string $msg, string $key ): bool {
            $hmac = substr( $msg, 0, 64 );
            $ct = substr( $msg, 64 );
            return hash_equals( hash_hmac( 'sha256', $ct, $key ), $hmac );
        }

        public static function encrypt( string $pt, string $key = null, string $iv = null ): array {
            $key = ( empty( $key ) || 32 > strlen( $key )) ? cyphper::hex_gen( 32 ) : $key;
            $iv = ( empty( $iv ) || 16 > strlen( $iv )) ? cyphper::hex_gen( 16 ) : $iv;
            $ct = openssl_encrypt( $pt, 'AES-256-CBC', $key, 0, $iv );
            $msg = cyphper::hmac_sign( $ct, $key );
            return array( 'message' => $msg, 'key' => $key, 'iv' => $iv );
        }

        public static function decrypt( string $msg, string $key, string $iv ): string {
            if( true !== cyphper::hmac_auth( $msg, $key )) {
                return "Encrypted message failed HMAC authentication";
            } else {
                $ct = substr( $msg, 64 );
                return openssl_decrypt( $ct, 'AES-256-CBC', $key, 0, $iv );
            }
        }
    }
