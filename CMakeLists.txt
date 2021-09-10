cmake_minimum_required(VERSION 2.8.11)
project(GmSSL)

set(CMAKE_MACOSX_RPATH 1)
SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

option(NO_RC4 "Option For Not Compile RC4" OFF)
option(NO_MD5 "Option For Not Compile RC4" OFF)
option(NO_AES "Option For Not Compile RC4" OFF)
option(NO_DES "Option For Not Compile RC4" OFF)
option(NO_CHACHA20 "Option For Not Compile RC4" OFF)
option(NO_SHA1 "Option For Not Compile RC4" OFF)
option(NO_SHA2 "Option For Not Compile RC4" OFF)

if (NO_RC4)
add_definitions(-DNO_RC4)
endif()

if (NO_MD5)
add_definitions(-DNO_MD5)
endif()

if (NO_AES)
add_definitions(-DNO_AES)
endif()

if (NO_DES)
add_definitions(-DNO_DES)
endif()

if (NO_CHACHA20)
add_definitions(-DNO_CHACHA20)
endif()

if (NO_SHA1)
add_definitions(-DNO_SHA1)
endif()

if (NO_SHA2)
add_definitions(-DNO_SHA2)
endif()

include_directories(include)

add_library(
  gmssl

  SHARED

  src/hex.c
  src/debug.c
  src/rand.c

  # default sm algors
  src/sm2_algo.c
  src/sm2_lib.c
  src/sm2_asn1.c
  src/sm2_prn.c
  src/sm3.c
  src/sm3_hmac.c
  src/sm4_common.c
  src/sm4_setkey.c
  src/sm4_enc.c
  src/sm4_modes.c

  # optional sm algors
  src/sm9_math.c
  src/zuc_core.c
  src/zuc_eea.c
  src/zuc_eia.c

  # optional nist algors
  src/aes.c
  src/aes_modes.c
  src/chacha20.c
  src/sha256.c
  src/sha512.c

  # legacy algors
  src/rc4.c
  src/des.c
  src/md5.c
  src/sha1.c

  # schemes
  src/hash_drbg.c
  src/hmac.c

  # abstract
  src/digest.c
  src/block_cipher.c

  # pkix
  src/oid.c
  src/asn1.c
  src/base64.c
  src/pem.c
  src/pbkdf2.c
  src/pkcs8.c
  src/x509_lib.c
  src/x509_asn1.c
  src/x509_ext.c
  src/x509_algor.c
  src/cms.c

  # for tls 1.3
  src/hkdf.c
  src/gf128.c
  src/gcm.c

  # ssl/tls/tlcp
  src/tls.c
  src/tls_trace.c
  src/tls12.c
  src/tlcp.c
  src/tls13.c

)
SET_TARGET_PROPERTIES(gmssl PROPERTIES VERSION 3.0 SOVERSION 3)


# tools

add_executable (sm2keygen tools/sm2keygen.c)
target_link_libraries (sm2keygen LINK_PUBLIC gmssl)
add_executable (sm2sign tools/sm2sign.c)
target_link_libraries (sm2sign LINK_PUBLIC gmssl)
add_executable (sm2verify tools/sm2verify.c)
target_link_libraries (sm2verify LINK_PUBLIC gmssl)
add_executable (sm2encrypt tools/sm2encrypt.c)
target_link_libraries (sm2encrypt LINK_PUBLIC gmssl)
add_executable (sm2decrypt tools/sm2decrypt.c)
target_link_libraries (sm2decrypt LINK_PUBLIC gmssl)

add_executable (sm3 tools/sm3.c)
target_link_libraries (sm3 LINK_PUBLIC gmssl)
add_executable (sm3hmac tools/sm3hmac.c)
target_link_libraries (sm3hmac LINK_PUBLIC gmssl)

add_executable (reqgen tools/reqgen.c)
target_link_libraries (reqgen LINK_PUBLIC gmssl)
add_executable (reqparse tools/reqparse.c)
target_link_libraries (reqparse LINK_PUBLIC gmssl)

add_executable (certgen tools/certgen.c)
target_link_libraries (certgen LINK_PUBLIC gmssl)
add_executable (certparse tools/certparse.c)
target_link_libraries (certparse LINK_PUBLIC gmssl)
add_executable (certverify tools/certverify.c)
target_link_libraries (certverify LINK_PUBLIC gmssl)

add_executable (tlcp_client tools/tlcp_client.c)
target_link_libraries (tlcp_client LINK_PUBLIC gmssl)
add_executable (tlcp_server tools/tlcp_server.c)
target_link_libraries (tlcp_server LINK_PUBLIC gmssl)
add_executable (tls12_client tools/tls12_client.c)
target_link_libraries (tls12_client LINK_PUBLIC gmssl)
add_executable (tls12_server tools/tls12_server.c)
target_link_libraries (tls12_server LINK_PUBLIC gmssl)
add_executable (tls13_client tools/tls13_client.c)
target_link_libraries (tls13_client LINK_PUBLIC gmssl)
add_executable (tls13_server tools/tls13_server.c)
target_link_libraries (tls13_server LINK_PUBLIC gmssl)



# tests
enable_testing()


add_executable(sm2test tests/sm2test.c)
target_link_libraries (sm2test LINK_PUBLIC gmssl)

add_executable(sm2asn1test tests/sm2asn1test.c)
target_link_libraries (sm2asn1test LINK_PUBLIC gmssl)

add_executable(sm3test tests/sm3test.c)
target_link_libraries (sm3test LINK_PUBLIC gmssl)

if (!NO_MD5)
add_executable(md5test tests/md5test.c)
target_link_libraries (md5test LINK_PUBLIC gmssl)
endif()

if (!NO_SHA1)
add_executable(sha1test tests/sha1test.c)
target_link_libraries (sha1test LINK_PUBLIC gmssl)
endif()


if (!NO_SHA2)
add_executable(sha224test tests/sha224test.c)
target_link_libraries (sha224test LINK_PUBLIC gmssl)

add_executable(sha256test tests/sha256test.c)
target_link_libraries (sha256test LINK_PUBLIC gmssl)

add_executable(sha384test tests/sha384test.c)
target_link_libraries (sha384test LINK_PUBLIC gmssl)

add_executable(sha512test tests/sha512test.c)
target_link_libraries (sha512test LINK_PUBLIC gmssl)
endif()


add_executable(hmactest tests/hmactest.c)
target_link_libraries (hmactest LINK_PUBLIC gmssl)

add_executable(hkdftest tests/hkdftest.c)
target_link_libraries (hkdftest LINK_PUBLIC gmssl)

add_executable(digesttest tests/digesttest.c)
target_link_libraries (digesttest LINK_PUBLIC gmssl)

add_executable(sm4test tests/sm4test.c)
target_link_libraries (sm4test LINK_PUBLIC gmssl)
add_executable(sm4cbctest tests/sm4cbctest.c)
target_link_libraries (sm4cbctest LINK_PUBLIC gmssl)

add_executable(zuctest tests/zuctest.c)
target_link_libraries (zuctest LINK_PUBLIC gmssl)

if (!NO_AES)
add_executable(aestest tests/aestest.c)
target_link_libraries (aestest LINK_PUBLIC gmssl)
endif()

if (!NO_RC4)
add_executable(rc4test tests/rc4test.c)
target_link_libraries (rc4test LINK_PUBLIC gmssl)
endif()

if (!NO_CHACHA20)
add_executable(chacha20test tests/chacha20test.c)
target_link_libraries (chacha20test LINK_PUBLIC gmssl)
endif()

add_executable(hash_drbgtest tests/hash_drbgtest.c)
target_link_libraries (hash_drbgtest LINK_PUBLIC gmssl)

if (!NO_SHA1)
add_executable(pbkdf2test tests/pbkdf2test.c)
target_link_libraries (pbkdf2test LINK_PUBLIC gmssl)

add_executable(pkcs8test tests/pkcs8test.c)
target_link_libraries (pkcs8test LINK_PUBLIC gmssl)
endif()


add_executable(oidtest tests/oidtest.c)
target_link_libraries (oidtest LINK_PUBLIC gmssl)

add_executable(asn1test tests/asn1test.c)
target_link_libraries (asn1test LINK_PUBLIC gmssl)

add_executable(base64test tests/base64test.c)
target_link_libraries (base64test LINK_PUBLIC gmssl)

add_executable(x509test tests/x509test.c)
target_link_libraries (x509test LINK_PUBLIC gmssl)

add_executable(cmstest tests/cmstest.c)
target_link_libraries (cmstest LINK_PUBLIC gmssl)


enable_testing()
add_test(NAME aes		COMMAND aestest)
add_test(NAME asn1		COMMAND asn1test)
add_test(NAME base64		COMMAND base64test)
add_test(NAME block_cipher	COMMAND block_ciphertext)
add_test(NAME chacha20		COMMAND chacha20test)
add_test(NAME cms		COMMAND cmstest)
add_test(NAME ctr		COMMAND ctrtest)
add_test(NAME des		COMMAND destest)
add_test(NAME digest		COMMAND digesttest)
add_test(NAME gcm		COMMAND gcmtest)
add_test(NAME gf128		COMMAND gf128test)
add_test(NAME hash_drbg		COMMAND hash_drbgtest)
add_test(NAME hkdf		COMMAND hkdftest)
add_test(NAME hmac		COMMAND hmactest)
add_test(NAME md5		COMMAND md5test)
add_test(NAME oid		COMMAND oidtest)
add_test(NAME pbkdf2		COMMAND pbkdf2test)
add_test(NAME pkcs8		COMMAND pkcs8test)
add_test(NAME rc4		COMMAND rc4test)
add_test(NAME sha1		COMMAND sha1test)
add_test(NAME sha224		COMMAND sha224test)
add_test(NAME sha256		COMMAND sha256test)
add_test(NAME sha384		COMMAND sha384test)
add_test(NAME sha512		COMMAND sha512test)
add_test(NAME sm2asn1		COMMAND sm2asn1test)
add_test(NAME sm2		COMMAND sm2test)
add_test(NAME sm3		COMMAND sm3test)
add_test(NAME sm4cbc		COMMAND sm4cbctest)
add_test(NAME sm4		COMMAND sm4test)
add_test(NAME tls		COMMAND tlstest)
add_test(NAME u128		COMMAND u128test)
add_test(NAME x509		COMMAND x509test)
add_test(NAME zuc		COMMAND zuctest)


INSTALL(TARGETS certparse certgen certverify reqgen sm3 sm2keygen sm2sign sm2verify sm2encrypt sm2decrypt tlcp_client tlcp_server tls12_client tls12_server tls13_client tls13_server
        RUNTIME DESTINATION bin)
INSTALL(TARGETS gmssl LIBRARY DESTINATION lib)
INSTALL(DIRECTORY ${CMAKE_SOURCE_DIR}/include/gmssl DESTINATION include)

