<?php
    class cyphper_static {

        function __construct()
        {
            // nothing to see here
        }

        public static function gen_bytes( $length = 16, $strongEnforce = true ): string
        {
            $bytes = openssl_random_pseudo_bytes( $length, $strongResult );
            if( false === $strongResult && true === $strongEnforce ) {
                return cyphper_static::gen_hex( $length );
            } else {
                return $bytes;
            }
        }

        public static function gen_hex( $length = 16, $strongEnforce = true ): string
        {
            $bytes = cyphper_static::gen_bytes( $length / 2 );
            return bin2hex( $bytes );
        }

        public static function hmac_sign( $ct, $key ): string
        {
            return hash_hmac( 'sha256', $ct, $key ) . $ct;
        }

        public static function hmac_auth( $msg, $key ): bool
        {
            $hmac = substr( $msg, 0, 64 );
            $ct = substr( $msg, 64 );
            return hash_equals( hash_hmac( 'sha256', $ct, $key ), $hmac );
        }

        public static function encrypt( string $pt, string $key = null, string $iv = null ): array
        {
            $key = ( empty( $key ) || 32 > strlen( $key )) ? cyphper_static::gen_hex( 32 ) : $key;
            $iv = ( empty( $iv ) || 16 > strlen( $iv )) ? cyphper_static::gen_hex( 16 ) : $iv;
            $ct = openssl_encrypt( $pt, 'AES-256-CBC', $key, 0, $iv );
            $msg = cyphper_static::hmac_sign( $ct, $key );
            return array( 'message' => $msg, 'key' => $key, 'iv' => $iv );
        }

        public static function decrypt( string $msg, string $key, string $iv ): string
        {
            if( true !== cyphper_static::hmac_auth( $msg, $key )) {
                throw new Exception( 'Encrypted message failed HMAC authentication' );
            } else {
                $ct = substr( $msg, 64 );
                return openssl_decrypt( $ct, 'AES-256-CBC', $key, 0, $iv );
            }
        }
    }
