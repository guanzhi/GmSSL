# crypto/err/openssl.ec

# configuration file for util/mkerr.pl

# files that may have to be rewritten by util/mkerr.pl
L ERR		NONE				NONE
L BN		include/openssl/bn.h		crypto/bn/bn_err.c
L RSA		include/openssl/rsa.h		crypto/rsa/rsa_err.c
L DH		include/openssl/dh.h		crypto/dh/dh_err.c
L EVP		include/openssl/evp.h		crypto/evp/evp_err.c
L BUF		include/openssl/buffer.h	crypto/buffer/buf_err.c
L OBJ		include/openssl/objects.h	crypto/objects/obj_err.c
L PEM		include/openssl/pem.h		crypto/pem/pem_err.c
L DSA		include/openssl/dsa.h		crypto/dsa/dsa_err.c
L X509		include/openssl/x509.h		crypto/x509/x509_err.c
L ASN1		include/openssl/asn1.h		crypto/asn1/asn1_err.c
L CONF		include/openssl/conf.h		crypto/conf/conf_err.c
L CRYPTO	include/openssl/crypto.h	crypto/cpt_err.c
L EC		include/openssl/ec.h		crypto/ec/ec_err.c
L SSL		include/openssl/ssl.h		ssl/ssl_err.c
L BIO		include/openssl/bio.h		crypto/bio/bio_err.c
L PKCS7		include/openssl/pkcs7.h		crypto/pkcs7/pkcs7err.c
L X509V3	include/openssl/x509v3.h	crypto/x509v3/v3err.c
L PKCS12	include/openssl/pkcs12.h	crypto/pkcs12/pk12err.c
L RAND		include/openssl/rand.h		crypto/rand/rand_err.c
L DSO		include/internal/dso.h		crypto/dso/dso_err.c
L ENGINE	include/openssl/engine.h	crypto/engine/eng_err.c
L OCSP		include/openssl/ocsp.h		crypto/ocsp/ocsp_err.c
L UI		include/openssl/ui.h		crypto/ui/ui_err.c
L COMP		include/openssl/comp.h		crypto/comp/comp_err.c
L TS		include/openssl/ts.h		crypto/ts/ts_err.c
#L HMAC		include/openssl/hmac.h		crypto/hmac/hmac_err.c
L CMS		include/openssl/cms.h		crypto/cms/cms_err.c
#L FIPS		include/openssl/fips.h		crypto/fips_err.h
L CT		include/openssl/ct.h		crypto/ct/ct_err.c
L ASYNC		include/openssl/async.h		crypto/async/async_err.c
L KDF		include/openssl/kdf.h		crypto/kdf/kdf_err.c
L KDF2		include/openssl/kdf2.h		crypto/kdf2/kdf2_err.c
L FFX		include/openssl/ffx.h		crypto/ffx/ffx_err.c
L PAILLIER	include/openssl/paillier.h	crypto/paillier/pai_err.c
L CPK		include/openssl/cpk.h		crypto/cpk/cpk_err.c
L OTP		include/openssl/otp.h		crypto/otp/otp_err.c
L GMAPI		include/openssl/gmapi.h		crypto/gmapi/gmapi_err.c
L BFIBE		include/openssl/bfibe.h		crypto/bfibe/bfibe_err.c
L BB1IBE	include/openssl/bb1ibe.h	crypto/bb1ibe/bb1ibe_err.c
L SM2		include/openssl/sm2.h		crypto/sm2/sm2_err.c
L SM9		include/openssl/sm9.h		crypto/sm9/sm9_err.c
L SAF		include/openssl/gmsaf.h		crypto/saf/saf_err.c
L SDF		include/openssl/gmsdf.h		crypto/sdf/sdf_err.c
L SKF		include/openssl/gmskf.h		crypto/skf/skf_err.c
L SOF		include/openssl/gmsof.h		crypto/sof/sof_err.c
L BASE58	include/openssl/base58.h	crypto/base58/base58_err.c

# additional header files to be scanned for function names
L NONE		crypto/x509/x509_vfy.h		NONE
L NONE		crypto/ec/ec_lcl.h		NONE
L NONE		crypto/asn1/asn_lcl.h		NONE
L NONE		crypto/cms/cms_lcl.h		NONE
L NONE		crypto/ct/ct_locl.h		NONE
L NONE		fips/rand/fips_rand.h		NONE
L NONE		ssl/ssl_locl.h			NONE

F RSAREF_F_RSA_BN2BIN
F RSAREF_F_RSA_PRIVATE_DECRYPT
F RSAREF_F_RSA_PRIVATE_ENCRYPT
F RSAREF_F_RSA_PUBLIC_DECRYPT
F RSAREF_F_RSA_PUBLIC_ENCRYPT

R SSL_R_SSLV3_ALERT_UNEXPECTED_MESSAGE         1010
R SSL_R_SSLV3_ALERT_BAD_RECORD_MAC             1020
R SSL_R_TLSV1_ALERT_DECRYPTION_FAILED          1021
R SSL_R_TLSV1_ALERT_RECORD_OVERFLOW            1022
R SSL_R_SSLV3_ALERT_DECOMPRESSION_FAILURE      1030
R SSL_R_SSLV3_ALERT_HANDSHAKE_FAILURE          1040
R SSL_R_SSLV3_ALERT_NO_CERTIFICATE             1041
R SSL_R_SSLV3_ALERT_BAD_CERTIFICATE            1042
R SSL_R_SSLV3_ALERT_UNSUPPORTED_CERTIFICATE    1043
R SSL_R_SSLV3_ALERT_CERTIFICATE_REVOKED        1044
R SSL_R_SSLV3_ALERT_CERTIFICATE_EXPIRED        1045
R SSL_R_SSLV3_ALERT_CERTIFICATE_UNKNOWN        1046
R SSL_R_SSLV3_ALERT_ILLEGAL_PARAMETER          1047
R SSL_R_TLSV1_ALERT_UNKNOWN_CA                 1048
R SSL_R_TLSV1_ALERT_ACCESS_DENIED              1049
R SSL_R_TLSV1_ALERT_DECODE_ERROR               1050
R SSL_R_TLSV1_ALERT_DECRYPT_ERROR              1051
R SSL_R_TLSV1_ALERT_EXPORT_RESTRICTION         1060
R SSL_R_TLSV1_ALERT_PROTOCOL_VERSION           1070
R SSL_R_TLSV1_ALERT_INSUFFICIENT_SECURITY      1071
R SSL_R_TLSV1_ALERT_INTERNAL_ERROR             1080
R SSL_R_TLSV1_ALERT_INAPPROPRIATE_FALLBACK     1086
R SSL_R_TLSV1_ALERT_USER_CANCELLED             1090
R SSL_R_TLSV1_ALERT_NO_RENEGOTIATION           1100
R SSL_R_TLSV1_UNSUPPORTED_EXTENSION            1110
R SSL_R_TLSV1_CERTIFICATE_UNOBTAINABLE         1111
R SSL_R_TLSV1_UNRECOGNIZED_NAME                1112
R SSL_R_TLSV1_BAD_CERTIFICATE_STATUS_RESPONSE  1113
R SSL_R_TLSV1_BAD_CERTIFICATE_HASH_VALUE       1114
R TLS1_AD_UNKNOWN_PSK_IDENTITY                 1115
R TLS1_AD_NO_APPLICATION_PROTOCOL              1120

R RSAREF_R_CONTENT_ENCODING			0x0400
R RSAREF_R_DATA					0x0401
R RSAREF_R_DIGEST_ALGORITHM			0x0402
R RSAREF_R_ENCODING				0x0403
R RSAREF_R_KEY					0x0404
R RSAREF_R_KEY_ENCODING				0x0405
R RSAREF_R_LEN					0x0406
R RSAREF_R_MODULUS_LEN				0x0407
R RSAREF_R_NEED_RANDOM				0x0408
R RSAREF_R_PRIVATE_KEY				0x0409
R RSAREF_R_PUBLIC_KEY				0x040a
R RSAREF_R_SIGNATURE				0x040b
R RSAREF_R_SIGNATURE_ENCODING			0x040c
R RSAREF_R_ENCRYPTION_ALGORITHM			0x040d

