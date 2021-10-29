<?php
	class cyphper {
		/*
			0.0 - Initialization and Structs
		*/

		// data containers
		private $data = null;
		private $ct = null;
		private $iv = null;
		private $encMsg = null;
		private $decMsg = null;

		// encryption keys
		private $password = null;
		private $keys = null;
		private $encryptionKey = null;
		private $hmacKey = null;

		// methods and algorithms
		private $encryptionMethod = "";
		private $hmacHashMethod = "";
		private $hashDepth = 80000;
		private $cypherMethods = array();
		private $hashAlgorithms = array();

		function __construct( string $data, string $password )
		{
			// set encryption method
			$this->encryptionMethod = "AES-256-CBC";

			// set hmac algorithm
			$this->hmacHashMethod = "SHA256";

			// check available methods and algorithms
			$this->cypherMethods = openssl_get_cipher_methods();
			$this->hashAlgorithms = hash_hmac_algos();

			// load data into class
			$this->data = ( string ) $data;

			// load encryption key seed password into class
			$this->password = ( string ) $password;
		}

		function __destruct()
		{
			foreach( $this as $key => $val ) {
				$this->$key = null;
			}
			$val = null;
		}

		/*
			1.0 - Encryption & Decryption
		*/

		public function encrypt(): bool
		{
			// verify data is present
			if( empty( $this->data )) {
				throw new Exception( "Missing data to encrypt." );
			}

			// prepare decryption and authentication keys
			$this->gen_keys_from_password( $this->password );

			// verify keys are present
			if( empty( $this->hmacKey ) || empty( $this->encryptionKey )) {
				throw new Exception( "Missing one or more encryption keys." );
			}

			// clear any previously encrypted message
			$this->encMsg = null;

			// perform encryption
			if( !in_array( strtolower( $this->encryptionMethod ), $this->cypherMethods )) {
				throw new Exception( "Encryption method not supported." );
			} else {
				$this->ct = openssl_encrypt( $this->data, $this->encryptionMethod, $this->encryptionKey, OPENSSL_RAW_DATA, $this->iv );
			}

			// sign encrypted data
			$this->hmac_sign();

			// encode encryption to base64 for ease of use
			if( empty( $this->hmac ) || empty( $this->iv ) || empty( $this->ct )) {
				throw new Exception( "There was an error while attempting to encrypt the data." );
			} else {
				$this->encMsg = base64_encode( $this->hmac . $this->iv . $this->ct );
			}

			// create authenticated message
			if( empty( $this->encMsg )) {
				throw new Exception( "Failed to create authenticated encrypted message." );
			} else {
				return true;
			}
		}

		public function decrypt(): bool
		{
			// verify data is present
			if( empty( $this->data )) {
				throw new Exception( "Missing data to encrypt." );
			}

			// clear any previously decrypted message
			$this->decMsg = null;

			// decode encryption for processing
			$this->data = base64_decode( $this->data );

			// separate data to respective portions
			$this->hmac	= mb_substr( $this->data, 0, 64, "8bit" );	// hmac signature
			$this->iv	= mb_substr( $this->data, 64, 16, "8bit" );	// initialization vector
			$this->ct	= mb_substr( $this->data, 80, null, "8bit" );	// encrypted data

			// prepare decryption and authentication keys
			$this->gen_keys_from_password( $this->password );

			// verify keys are present
			if( empty( $this->hmacKey ) || empty( $this->encryptionKey )) {
				throw new Exception( "Missing one or more decryption keys." );
			}

			// authenticate encryption
			if( !$this->hmac_auth()) {
				throw new Exception( "Encrypted data failed authentication." );
			}

			// perform decryption
			$this->decMsg = openssl_decrypt( $this->ct, $this->encryptionMethod, $this->encryptionKey, OPENSSL_RAW_DATA, $this->iv );

			if( empty( $this->decMsg )) {
				throw new Exception( 'Unable to decrypt.' );
			} else {
				return true;
			}
		}

		/*
			3.0 - Authentication
		*/

		private function hmac_sign(): bool
		{
			$this->hmac = null;
			if( !in_array( strtolower( $this->hmacHashMethod ), $this->hashAlgorithms )) {
				throw new Exception( "Hash method not available: {$this->hmacHashMethod}" );
			} else {
				if( empty( $this->iv ) || empty( $this->ct )) {
					throw new Exception( "Cannot authenticate empty data." );
				} else {
					$this->hmac = hash_hmac( $this->hmacHashMethod, $this->iv . $this->ct, $this->hmacKey );
				}
			}
			if( empty( $this->hmac )) {
				return false;
			} else {
				return true;
			}
		}

		private function hmac_auth(): bool
		{
			// $hmac = substr( $data, 0, 64 );
			// $ct = substr( $data, 64 );
			return hash_equals( hash_hmac( "sha256", $this->iv . $this->ct, $this->hmacKey ), $this->hmac );
		}

		/*
			4.0 - Raw Data Generation
		*/

		private function gen_iv( $iv = null ): bool
		{
			$this->iv = null;
			if( empty( $iv ) || 16 > strlen( $iv )) {
				$this->iv = cyphper::gen_bytes( 16 );
			} else {
				$this->iv = substr( $iv, 0, 16 );
			}
			if( empty( $this->iv )) {
				return false;
			} else {
				return true;
			}
		}

		public static function gen_bytes( int $length = 16, bool $strongEnforce = true ): string
		{
			if( abs( $length ) !== $length ) {
				throw new Exception( "Defined length of bites must be a positive integer." );
			} else {
				$bytes = openssl_random_pseudo_bytes( $length, $strongResult );
				if( false === $strongResult && true === $strongEnforce ) {
					return $this->gen_bytes( $length );
				} else {
					return $bytes;
				}
			}
		}

		private function gen_keys_from_password( $password ): void
		{
			// prepare initialization vector if empty
			if( empty( $this->iv )) {
				$this->gen_iv();
			}

			// generate raw keys
			$this->keys = hash_pbkdf2( "sha256", $password, $this->iv, $this->hashDepth, 64, true ); // use $this->iv as salt

			// cut keys from raw key data
			$this->encryptionKey = mb_substr( $this->keys, 0, 32, "8bit" );
			$this->hmacKey = mb_substr( $this->keys, 32, null, "8bit" );
		}

		/*
			5.0 - Message Retrieval
		*/

		public function get_encrypted_message(): string
		{
			if( empty( $this->encMsg )) {
				$this->encrypt();
			}
			return $this->encMsg;
		}

		public function get_enc_msg(): string
		{
			return $this->get_encrypted_message();
		}

		public function get_decrypted_message(): string
		{
			if( empty( $this->decMsg )) {
				$this->decrypt();
			}
			return $this->decMsg;
		}

		public function get_dec_msg(): string
		{
			return $this->get_decrypted_message();
		}
	}
