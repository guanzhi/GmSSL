


/*
 * from GM/T 0009-2012
 * "SM2 Cryptography Algorithm Application Specification"
 *
	SM2PrivateKey ::= INTEGER
	
	SM2PublicKey ::= BIT STRING

	SM2CiphertextValue ::= SEQUENCE {
		XCoordinate	INTEGER,
		YCoordinate	INTEGER,
		Hash		OCTET STRING SIZE(32),
		Ciphertext	OCTET STRING
	}

	SM2Signature ::= SEQUENCE {
		R		INTEGER,
		S		INTEGER,
	}

	SM2EnvelopedKey ::= SEQUENCE {
		symAlgID	AlgorithmIdentifier,
		symEncryptedKey	SM2CiphertextValue,
		sm2PublicKey	SM2PublicKey,
		sm2EncryptedPrivateKey	BIT STRING
	}

	ZID = SM3(nbits(ID)||ID||a||b||xG||yG||xA||yA)
	
	Default ID = "1234567812345678"

*/


