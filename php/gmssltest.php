<?php
/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

printf("Versoin : %s\n", OPENSSL_VERSION_TEXT);

$digests = openssl_get_md_methods(false);
echo "Digests : ";
foreach ($digests as $digest) {
	echo $digest.",";
}
echo "\n";

$ciphers = openssl_get_cipher_methods(false);
echo "Ciphers : ";
foreach ($ciphers as $cipher) {
	echo $cipher.",";
}
echo "\n";

$curves = openssl_get_curve_names();
echo "Curves : ";
foreach ($curves as $curve) {
	echo $curve.",";
}
echo "\n";
echo "\n";

$msg = "abc";
printf("sm3(\"%s\") = %s\n", $msg, openssl_digest($msg, "sm3"));

$key = openssl_random_pseudo_bytes(16);
$ivlen = openssl_cipher_iv_length("sms4");
$iv = openssl_random_pseudo_bytes($ivlen);
$plaintext = "message to be encrypted";
$ciphertext = openssl_encrypt($plaintext, "sms4", $key, $options=0, $iv);
$original_plaintext = openssl_decrypt($ciphertext, "sms4", $key, $options=0, $iv);
printf("sms4enc(\"%s\") = %s\n", $plaintext, bin2hex($ciphertext));
printf("sms4dec(%s) = \"%s\"\n", bin2hex($ciphertext), $original_plaintext);

#$pubkey = openssl_pkey_get_public("file://localhost-signcer.pem");
#$prikey = openssl_pkey_get_private("file://localhost-signkey.pem");

$prikey = openssl_pkey_new(array("private_key_type" => OPENSSL_KEYTYPE_EC, "curve_name" => "sm2p256v1"));
openssl_pkey_export($prikey, $prikeypem);
echo $prikeypem;
$pubkeypem = openssl_pkey_get_details($prikey)["key"];
echo $pubkeypem;
$pubkey = openssl_pkey_get_public($pubkeypem);

$point = openssl_pkey_get_details($pubkey)["ec"];
printf("SM2 Public Key: (%s, %s)\n", bin2hex($point["x"]), bin2hex($point["y"]));
$ec = openssl_pkey_get_details($prikey)["ec"];
printf("SM2 Private Key: %s\n", bin2hex($ec["d"]));

openssl_sign($msg, $signature, $prikey, "sm3");
$ok = openssl_verify($msg, $signature, $pubkey, OPENSSL_ALGO_SM3);
printf("sm2sign(\"%s\") = %s\n", $msg, bin2hex($signature));
printf("sm2verify(\"%s\", %s) = %s\n", $msg, bin2hex($signature), $ok ? "OK" : "Failure");

openssl_seal($plaintext, $sealed, $ekeys, array($pubkey), "sms4", $iv);
openssl_open($sealed, $opened, $ekeys[0], $prikey, "sms4", $iv);
printf("sm2seal(\"%s\") = %s\n", $plaintext, bin2hex($sealed));
printf("sm2open(%s) = \"%s\"\n", bin2hex($sealed), $opened);

?>
