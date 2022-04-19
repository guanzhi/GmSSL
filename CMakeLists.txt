cmake_minimum_required(VERSION 3.0)
project(GmSSL)

set(CMAKE_MACOSX_RPATH 1)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mrdrnd -mrdseed")

include_directories(include)

add_library(
	gmssl

	src/aes.c
	src/aes_modes.c
	src/asn1.c
	src/base64.c
	src/block_cipher.c
	src/chacha20.c
	src/cms.c
	src/debug.c
	src/des.c
	src/digest.c
	src/ec.c
	src/gcm.c
	src/gf128.c
	src/hash_drbg.c
	src/hex.c
	src/hkdf.c
	src/hmac.c
	src/md5.c
	src/pbkdf2.c
	src/pem.c
	src/pkcs8.c
	src/rand.c
	src/rc4.c
#	src/rdrand.c
	src/rsa.c
	src/sha1.c
	src/sha256.c
	src/sha512.c
	src/sm2_alg.c
	src/sm2_key.c
	src/sm2_lib.c
	src/sm3.c
	src/sm3_hmac.c
	src/sm4_common.c
	src/sm4_enc.c
	src/sm4_modes.c
	src/sm4_setkey.c
#	src/sm9_keygen.c
#	src/sm9_math.c
#	src/sm9_sign.c
	src/tlcp.c
	src/tls.c
	src/tls12.c
	src/tls13.c
	src/tls_trace.c
	src/version.c
	src/x509_alg.c
	src/x509_cer.c
	src/x509_crl.c
	src/x509_ext.c
	src/x509_oid.c
	src/x509_req.c
	src/x509_str.c
	src/zuc_core.c
	src/zuc_eea.c
	src/zuc_eia.c
)


SET_TARGET_PROPERTIES(gmssl PROPERTIES VERSION 3.0 SOVERSION 3)


# tools

add_executable(
	gmssl-bin
	tools/gmssl.c
	tools/rand.c
	tools/sm2keygen.c
	tools/sm2sign.c
	tools/sm2verify.c
	tools/sm2encrypt.c
	tools/sm2decrypt.c
	tools/sm3.c
	tools/sm3hmac.c
	tools/sm4.c
	tools/certgen.c
	tools/certparse.c
	tools/certverify.c
	tools/crlparse.c
	tools/pbkdf2.c
	tools/reqgen.c
	tools/reqparse.c
	tools/reqsign.c
	tools/tlcp_client.c
	tools/tlcp_server.c
	tools/tls12_client.c
	tools/tls12_server.c
	tools/tls13_client.c
	tools/tls13_server.c
)
target_link_libraries (gmssl-bin LINK_PUBLIC gmssl)
set_target_properties (gmssl-bin PROPERTIES RUNTIME_OUTPUT_NAME gmssl)


# tests
enable_testing()

add_executable(aestest tests/aestest.c)
target_link_libraries (aestest LINK_PUBLIC gmssl)

add_executable(asn1test tests/asn1test.c)
target_link_libraries (asn1test LINK_PUBLIC gmssl)

add_executable(base64test tests/base64test.c)
target_link_libraries (base64test LINK_PUBLIC gmssl)

add_executable(block_ciphertest tests/block_ciphertest.c)
target_link_libraries (block_ciphertest LINK_PUBLIC gmssl)

add_executable(chacha20test tests/chacha20test.c)
target_link_libraries (chacha20test LINK_PUBLIC gmssl)

add_executable(cmstest tests/cmstest.c)
target_link_libraries (cmstest LINK_PUBLIC gmssl)

add_executable(destest tests/destest.c)
target_link_libraries (destest LINK_PUBLIC gmssl)

add_executable(digesttest tests/digesttest.c)
target_link_libraries (digesttest LINK_PUBLIC gmssl)

add_executable(ectest tests/ectest.c)
target_link_libraries (ectest LINK_PUBLIC gmssl)

add_executable(gcmtest tests/gcmtest.c)
target_link_libraries (gcmtest LINK_PUBLIC gmssl)

add_executable(gf128test tests/gf128test.c)
target_link_libraries (gf128test LINK_PUBLIC gmssl)

add_executable(hash_drbgtest tests/hash_drbgtest.c)
target_link_libraries (hash_drbgtest LINK_PUBLIC gmssl)

add_executable(hextest tests/hextest.c)
target_link_libraries (hextest LINK_PUBLIC gmssl)

add_executable(hkdftest tests/hkdftest.c)
target_link_libraries (hkdftest LINK_PUBLIC gmssl)

add_executable(hmactest tests/hmactest.c)
target_link_libraries (hmactest LINK_PUBLIC gmssl)

add_executable(md5test tests/md5test.c)
target_link_libraries (md5test LINK_PUBLIC gmssl)

add_executable(pbkdf2test tests/pbkdf2test.c)
target_link_libraries (pbkdf2test LINK_PUBLIC gmssl)

add_executable(pemtest tests/pemtest.c)
target_link_libraries (pemtest LINK_PUBLIC gmssl)

add_executable(pkcs8test tests/pkcs8test.c)
target_link_libraries (pkcs8test LINK_PUBLIC gmssl)

add_executable(rc4test tests/rc4test.c)
target_link_libraries (rc4test LINK_PUBLIC gmssl)

add_executable(sha1test tests/sha1test.c)
target_link_libraries (sha1test LINK_PUBLIC gmssl)

add_executable(sha224test tests/sha224test.c)
target_link_libraries (sha224test LINK_PUBLIC gmssl)

add_executable(sha256test tests/sha256test.c)
target_link_libraries (sha256test LINK_PUBLIC gmssl)

add_executable(sha384test tests/sha384test.c)
target_link_libraries (sha384test LINK_PUBLIC gmssl)

add_executable(sha512test tests/sha512test.c)
target_link_libraries (sha512test LINK_PUBLIC gmssl)

add_executable(sm2test tests/sm2test.c)
target_link_libraries (sm2test LINK_PUBLIC gmssl)

add_executable(sm3test tests/sm3test.c)
target_link_libraries (sm3test LINK_PUBLIC gmssl)

add_executable(sm4test tests/sm4test.c)
target_link_libraries (sm4test LINK_PUBLIC gmssl)

add_executable(x509test tests/x509test.c)
target_link_libraries (x509test LINK_PUBLIC gmssl)
add_executable(x509_oidtest tests/x509_oidtest.c)
target_link_libraries (x509_oidtest LINK_PUBLIC gmssl)
add_executable(x509_algtest tests/x509_algtest.c)
target_link_libraries (x509_algtest LINK_PUBLIC gmssl)
add_executable(x509_strtest tests/x509_strtest.c)
target_link_libraries (x509_strtest LINK_PUBLIC gmssl)
add_executable(x509_reqtest tests/x509_reqtest.c)
target_link_libraries (x509_reqtest LINK_PUBLIC gmssl)
add_executable(x509_crltest tests/x509_crltest.c)
target_link_libraries (x509_crltest LINK_PUBLIC gmssl)
#add_executable(x509_exttest tests/x509_exttest.c)
#target_link_libraries (x509_exttest LINK_PUBLIC gmssl)

add_executable(zuctest tests/zuctest.c)
target_link_libraries (zuctest LINK_PUBLIC gmssl)

add_executable(tlstest tests/tlstest.c)
target_link_libraries (tlstest LINK_PUBLIC gmssl)


enable_testing()
add_test(NAME aes		COMMAND aestest)
add_test(NAME asn1		COMMAND asn1test)
add_test(NAME base64		COMMAND base64test)
add_test(NAME block_cipher	COMMAND block_ciphertest)
add_test(NAME chacha20		COMMAND chacha20test)
add_test(NAME cms		COMMAND cmstest)
add_test(NAME des		COMMAND destest)
add_test(NAME digest		COMMAND digesttest)
add_test(NAME ec		COMMAND ectest)
add_test(NAME gcm		COMMAND gcmtest)
add_test(NAME gf128		COMMAND gf128test)
add_test(NAME hash_drbg		COMMAND hash_drbgtest)
add_test(NAME hkdf		COMMAND hkdftest)
add_test(NAME hex		COMMAND hextest)
add_test(NAME hmac		COMMAND hmactest)
add_test(NAME md5		COMMAND md5test)
add_test(NAME pbkdf2		COMMAND pbkdf2test)
add_test(NAME pem		COMMAND pemtest)
add_test(NAME pkcs8		COMMAND pkcs8test)
add_test(NAME rc4		COMMAND rc4test)
add_test(NAME sha1		COMMAND sha1test)
add_test(NAME sha224		COMMAND sha224test)
add_test(NAME sha256		COMMAND sha256test)
add_test(NAME sha384		COMMAND sha384test)
add_test(NAME sha512		COMMAND sha512test)
add_test(NAME sm2		COMMAND sm2test)
add_test(NAME sm3		COMMAND sm3test)
add_test(NAME sm4		COMMAND sm4test)
add_test(NAME tls		COMMAND tlstest)
add_test(NAME x509		COMMAND x509test)
add_test(NAME x509_oid		COMMAND x509_oidtest)
add_test(NAME x509_alg		COMMAND x509_algtest)
add_test(NAME x509_str		COMMAND x509_strtest)
add_test(NAME x509_req		COMMAND x509_reqtest)
add_test(NAME x509_crl		COMMAND x509_crltest)
#add_test(NAME x509_ext		COMMAND x509_exttest)
add_test(NAME zuc		COMMAND zuctest)


INSTALL(TARGETS gmssl ARCHIVE DESTINATION lib  LIBRARY DESTINATION lib)
INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/gmssl DESTINATION include)
INSTALL(TARGETS gmssl-bin RUNTIME DESTINATION bin)
