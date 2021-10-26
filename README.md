# cyphper
Simple PHP class to easily implement data encryption and decryption. This can be used as a base class to expand upon or simply just to use the static classes.

***This by no means is meant to replace robust and significantly test libraries. This is a learning exercise in capabilities for the author.***

## Basic Usage

Basic encryption and decryption is accomplished using `encrypt()` and `decrypt()`, as shown below:

### Encryption

Providing `encrypt()` will return the HMAC-signed cyphertext, the encryption key, and IV used to encrypt the data.

### Decryption

Providing `decrypt()` with the HMAC-signed cyphertext, the encryption key, and IV will return the decrypted message.

### Example

```php
<?php
  $pt = "Example usage of cyphper.";
  [ 'message' => $msg, 'key' => $key, 'iv' => $iv ] = cyphper::encrypt( $pt );
  echo "
    Plaintext Message:\t{$pt}
    Encrypted Message:\t{$msg}
    Encryption Key:\t\t{$key}
    Initialization Vector:\t{$iv}
    Decrypted Message:\t" . cyphper::decrypt( $msg, $key, $iv )
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
