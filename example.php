<?php
	// setting example variables
	$ptd = "example.php";
	$pwd = "super secret password";
	echo "Plaintext Data: {$ptd}";

	// encrypt
	try {
		$cyp = new cyphper( $ptd, $pwd );
		$enc = $cyp->get_enc_msg();
	} catch( Exception $e ) {
		die( $e->getMessage());
	}
	echo "Encrypted data: {$enc}<br>\n";
	
	// decrypt
	$cyp = new cyphper( $enc, $pwd );
	try {
		$dec = $cyp->get_dec_msg();
	} catch( Exception $e ) {
		die( $e->getMessage());
	}
	echo "Decrypted data: {$dec}<br>\n";
