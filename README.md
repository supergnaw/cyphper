# cyphper
Simple PHP class to easily implement authenticated data encryption and decryption. This can be used as a base class to expand upon or simply just to use the static classes.

***This by no means is meant to replace robust and significantly tested libraries like [Halite](https://github.com/paragonie/halite). This is a learning exercise in capabilities for the author.***

## Instantiated
The instantiated version of cyphper is recommended since all variables are generated and handled internally to protect the data. It also generates stronger keys for encryption and authentication. The only information able to be retrieved is the encrypted message of the original information or the decrypted message from the provided data upon instantiation.

### Basic Usage
The `cyphper()` class is instantiated with the data to be encrypted/decrypted, along with the secret password to be used.
```php
$cyp = new cyphper( $data, $password );
```

#### Encryption
Encryption is handled internally when the encrypted message is requested from the class. This can be triggered through either `get_encrypted_message()` or the `get_enc_msg()` alias:
```php
$enc = $cyp->get_enc_msg();
```

#### Decryption
Decryption, like encryption, is triggered when requestiong the decrypted message. To do this use `get_decrypted_message()` or its alias `get_enc_msg()`:
```php
$dec = $cyp->get_dec_msg();
```

### Example
```php
<?php
	// setting example variables
	$ptd = "example.php";
	$pwd = "super secret password";
	echo "Plaintext data: {$ptd}";

	// encrypt
	try {
		$cyp = new cyphper( $msg, $pwd );
		$enc = $cyp->get_enc_msg();
	} catch( Exception $e ) {
		die( $e->getMessage());
	}
	echo "Encrypted data: {$enc}<br>\n";

	// decrypt
	try {
		$cyp = new cyphper( $enc, $pwd );
		$dec = $cyp->get_dec_msg();
	} catch( Exception $e ) {
		die( $e->getMessage());
	}
	echo "Decrypted data: {$dec}<br>\n";
```
The above would output something like so:
```
Plaintext data: example.php
Encrypted data: NzQ4MGMwNzgxYWM0ODk3MmYyZTUxZGZiMTBjMGY5NTg1YTFiYjdlMjU1YjI5MWZmZDZkZjkzZjFiZjQ0MmVjZB4JVj5Q6tAXGg9tqhMzPZTi5PsxFcNO5szDN78g/Qb2
Decrypted data: example.php
```

### Exception Codes
While all the data handling within cyphper is handled automagically to mitigate any errors, there might be an edge case scenario where an exception is thrown. Each exception has a detailed message, however the following codes also accompany their respective message:
|No.|Description|
|---|-----------|
|1|Missing input data|
|2|Missing encryption keys|
|3|Encryption/Hash method Unsupported|
|4|Encryption error|
|5|Decryption error|
|6|Authentication failure|
|7|Invalid key byte length|

## Static
The static class was the first iteration and remains here for historical purposes. It likely will not be updated in the future, but might be in the instance the author becomes bored or a pull request is created.

### Basic Usage
Basic encryption and decryption is accomplished using `encrypt()` and `decrypt()`, as shown below:

#### Encryption
Providing `encrypt()` will return the HMAC-signed cyphertext, the encryption key, and IV used to encrypt the data.

#### Decryption
Providing `decrypt()` with the HMAC-signed cyphertext, the encryption key, and IV will return the decrypted message.

### Example
```php
<?php
	$pt = "Example usage of cyphper.";
	[ 'message' => $msg, 'key' => $key, 'iv' => $iv ] = cyphper_static::encrypt( $pt );
	echo "
		Plaintext Message:\t{$pt}
		Encrypted Message:\t{$msg}
		Encryption Key:\t\t{$key}
		Initialization Vector:\t{$iv}
		Decrypted Message:\t" . cyphper_static::decrypt( $msg, $key, $iv )
	);
```

The above would output something like so:
```
Plaintext Message:	Example usage of cyphper.
Encrypted Message:	72f93e27b49b9870374cc0cc1e1699930f657128e3768d34a90520a5e39c03a8MKsGsaZ1IuIqywqkXGwvx1/UFTpyZEXgMQ==
Encryption Key:		b8e505c4f42f808834f39b60f4e1b4d5
Initialization Vector:	4404ee99e171be6f
Decrypted Message:	Example usage of cyphper.
```

# References
Since this was a project designed for learning, here are some great references used during the creation of this project:
- [Encryption, Authentication, & Data Integrity in PHP 7](https://www.zimuel.it/slides/zendcon2016/encrypt#/)
- [NIST 800-63B - Digital Identity Guidelines (Sec. 5 - Authenticator & Verifier Req.)](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5)
