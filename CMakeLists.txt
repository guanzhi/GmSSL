if (CMAKE_VERSION VERSION_LESS "3.0")
	cmake_minimum_required(VERSION 2.8)
else()
	cmake_minimum_required(VERSION 3.10)
endif()
project(GmSSL C)

SET(CMAKE_PROJECT_HOMEPAGE_URL "http://gmssl.org")

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories(include)

if(MSVC)
	#add_compile_options(/O2) # conflict with CI /0d (not optimized)
else()
	add_compile_options(-O3)
endif()

set(GMSSL_TARGET_PROCESSOR "${CMAKE_SYSTEM_PROCESSOR}")
if (APPLE AND CMAKE_OSX_ARCHITECTURES)
	list(LENGTH CMAKE_OSX_ARCHITECTURES GMSSL_OSX_ARCH_COUNT)
	if (GMSSL_OSX_ARCH_COUNT EQUAL 1)
		list(GET CMAKE_OSX_ARCHITECTURES 0 GMSSL_TARGET_PROCESSOR)
	else()
		set(GMSSL_TARGET_PROCESSOR "")
	endif()
endif()
string(TOLOWER "${GMSSL_TARGET_PROCESSOR}" GMSSL_TARGET_PROCESSOR)

set(GMSSL_DEFAULT_ENABLE_SM2_ARM64 OFF)
set(GMSSL_DEFAULT_ENABLE_SM3_ARM64 OFF)
set(GMSSL_DEFAULT_ENABLE_SM4_ARM64 OFF)
set(GMSSL_DEFAULT_ENABLE_SM4_CE OFF)
set(GMSSL_DEFAULT_ENABLE_SM2_NEON OFF)
set(GMSSL_DEFAULT_ENABLE_SM4_AVX2 OFF)
set(GMSSL_DEFAULT_ENABLE_SM4_AESNI OFF)
set(GMSSL_DEFAULT_ENABLE_SM2_AMD64 OFF)
set(GMSSL_DEFAULT_ENABLE_SM3_SSE OFF)
set(GMSSL_DEFAULT_ENABLE_LMS_CL OFF)
set(GMSSL_DEFAULT_ENABLE_XMSS_CL OFF)

if (NOT MSVC)
	if (GMSSL_TARGET_PROCESSOR MATCHES "^(aarch64|arm64)$")
		set(GMSSL_DEFAULT_ENABLE_SM2_ARM64 ON)
		set(GMSSL_DEFAULT_ENABLE_SM3_ARM64 ON)
		set(GMSSL_DEFAULT_ENABLE_SM4_ARM64 ON)
	elseif (GMSSL_TARGET_PROCESSOR MATCHES "^(x86_64|amd64|x64)$")
		set(GMSSL_DEFAULT_ENABLE_SM2_AMD64 ON)
		if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang" AND NOT CMAKE_CROSSCOMPILING)
			include(CheckCSourceCompiles)
			set(GMSSL_CMAKE_REQUIRED_FLAGS_SAVE "${CMAKE_REQUIRED_FLAGS}")
			set(CMAKE_REQUIRED_FLAGS "-march=native")
			check_c_source_compiles(
				"#include <immintrin.h>
				int main(void) { __m128i x = _mm_setzero_si128(); x = _mm_shuffle_epi8(x, x); return _mm_cvtsi128_si32(x); }"
				GMSSL_HAVE_NATIVE_SSSE3)
			check_c_source_compiles(
				"#include <x86intrin.h>
				int main(void) { __m128i x = _mm_setzero_si128(); x = _mm_aesenclast_si128(x, x); x = _mm_shuffle_epi8(x, x); return _mm_cvtsi128_si32(x); }"
				GMSSL_HAVE_NATIVE_AESNI)
			check_c_source_compiles(
				"#include <immintrin.h>
				int main(void) { __m256i x = _mm256_setzero_si256(); x = _mm256_shuffle_epi8(x, x); return _mm256_extract_epi32(x, 0); }"
				GMSSL_HAVE_NATIVE_AVX2)
			set(CMAKE_REQUIRED_FLAGS "${GMSSL_CMAKE_REQUIRED_FLAGS_SAVE}")
			if (GMSSL_HAVE_NATIVE_SSSE3)
				set(GMSSL_DEFAULT_ENABLE_SM3_SSE ON)
			endif()
			if (DEFINED ENABLE_SM4_AVX2 AND ENABLE_SM4_AVX2)
				set(GMSSL_DEFAULT_ENABLE_SM4_AESNI OFF)
			elseif (DEFINED ENABLE_SM4_AESNI AND ENABLE_SM4_AESNI)
				set(GMSSL_DEFAULT_ENABLE_SM4_AVX2 OFF)
			elseif (GMSSL_HAVE_NATIVE_AVX2)
				set(GMSSL_DEFAULT_ENABLE_SM4_AVX2 ON)
			elseif (GMSSL_HAVE_NATIVE_AESNI)
				set(GMSSL_DEFAULT_ENABLE_SM4_AESNI ON)
			endif()
		endif()
	elseif (GMSSL_TARGET_PROCESSOR MATCHES "^arm")
		include(CheckCSourceCompiles)
		check_c_source_compiles(
			"#include <arm_neon.h>
			int main(void) { uint64x2_t x = vmovq_n_u64(0); return (int)vgetq_lane_u64(x, 0); }"
			GMSSL_HAVE_ARM_NEON)
		if (GMSSL_HAVE_ARM_NEON)
			set(GMSSL_DEFAULT_ENABLE_SM2_NEON ON)
		endif()
	endif()
endif()

if (APPLE)
	include(CheckCSourceCompiles)
	set(GMSSL_CMAKE_REQUIRED_LIBRARIES_SAVE "${CMAKE_REQUIRED_LIBRARIES}")
	set(CMAKE_REQUIRED_LIBRARIES "-framework OpenCL")
	check_c_source_compiles(
		"#include <OpenCL/OpenCL.h>
		int main(void) { cl_uint n = 0; clGetPlatformIDs(0, 0, &n); return 0; }"
		GMSSL_HAVE_MACOS_OPENCL)
	set(CMAKE_REQUIRED_LIBRARIES "${GMSSL_CMAKE_REQUIRED_LIBRARIES_SAVE}")
	if (GMSSL_HAVE_MACOS_OPENCL)
		set(GMSSL_DEFAULT_ENABLE_LMS_CL ON)
		set(GMSSL_DEFAULT_ENABLE_XMSS_CL ON)
	endif()
endif()

option(ENABLE_TEST_SPEED "Enable test speed" OFF)
option(ENABLE_SLOW_TEST "Enable slow tests" OFF)



option(ENABLE_SM2_ARM64 "Enable SM2_Z256 ARMv8 assembly" ${GMSSL_DEFAULT_ENABLE_SM2_ARM64})
option(ENABLE_SM3_ARM64 "Enable SM3 Arm Neon implementation (10% faster on Apple M2)" ${GMSSL_DEFAULT_ENABLE_SM3_ARM64})
option(ENABLE_SM4_ARM64 "Enable SM4 AARCH64 assembly implementation" ${GMSSL_DEFAULT_ENABLE_SM4_ARM64})
option(ENABLE_SM4_CE "Enable SM4 ARM CE assembly implementation" ${GMSSL_DEFAULT_ENABLE_SM4_CE})
option(ENABLE_SM2_NEON "Enable SM2_Z256 Arm Neon implementation" ${GMSSL_DEFAULT_ENABLE_SM2_NEON})
option(ENABLE_SM9_ARM64 "Enable SM9_Z256 ARMv8 assembly" OFF)
option(ENABLE_GMUL_ARM64 "Enable GF(2^128) Multiplication AArch64 assembly" OFF)

option(ENABLE_SM2_LOONGARCH64 "Enable SM2_Z256 LoongArch assembly" OFF)

option(ENABLE_SM4_AVX2 "Enable SM4 AVX2 8x implementation" ${GMSSL_DEFAULT_ENABLE_SM4_AVX2})
option(ENABLE_SM4_AESNI "Enable SM4 AES-NI (4x) implementation" ${GMSSL_DEFAULT_ENABLE_SM4_AESNI})
option(ENABLE_SM2_AMD64 "Enable SM2_Z256 X86_64 assembly" ${GMSSL_DEFAULT_ENABLE_SM2_AMD64})


option(ENABLE_SM3_SSE "Enable SM3 SSE assembly implementation" ${GMSSL_DEFAULT_ENABLE_SM3_SSE})

option(ENABLE_SM4_CTR_AESNI_AVX "Enable SM4 CTR AESNI+AVX assembly implementation" OFF)
option(ENABLE_SM4_CL "Enable SM4 OpenCL" OFF)
option(ENABLE_LMS_CL "Enable LMS OpenCL" ${GMSSL_DEFAULT_ENABLE_LMS_CL})
option(ENABLE_XMSS_CL "Enable XMSS OpenCL" ${GMSSL_DEFAULT_ENABLE_XMSS_CL})


option(ENABLE_INTEL_RDRAND "Enable Intel RDRAND instructions" OFF)
option(ENABLE_INTEL_RDSEED "Enable Intel RDSEED instructions" OFF)

option(ENABLE_SM4_ECB "Enable SM4 ECB mode" ON)
option(ENABLE_SM4_OFB "Enable SM4 OFB mode" ON)
option(ENABLE_SM4_CFB "Enable SM4 CFB mode" ON)
option(ENABLE_SM4_CCM "Enable SM4 CCM mode" ON)
option(ENABLE_SM4_XTS "Enable SM4 XTS mode" ON)
option(ENABLE_SM4_CBC_MAC "Enable SM4-CBC-MAC" ON)
option(ENABLE_SM4_FF1 "Enable SM4 FF1 format-preserving encryption" ON)

option(ENABLE_SM9 "Enable SM9" ON)
option(ENABLE_CMS "Enable CMS" ON)

option(ENABLE_SECP256R1 "Enable ECDH/ECDSA on curve secp256r1" ON)
option(ENABLE_SECP384R1 "Enable curve secp384r1" ON)

option(ENABLE_LMS "Enable LMS/HSS signature" ON)
option(ENABLE_XMSS "Enable XMSS/XMSS^MT signature" ON)
option(ENABLE_SPHINCS "Enable SPHINCS+ signature" ON)
option(ENABLE_KYBER "Enable Kyber" ON)

option(ENABLE_SHA1 "Enable SHA1" ON)
option(ENABLE_SHA2 "Enable SHA2" ON)
option(ENABLE_AES "Enable AES" ON)
option(ENABLE_AES_CCM "Enable AES CCM mode" ON)
option(ENABLE_ZUC "Enable ZUC" ON)
option(ENABLE_GHASH "Enable standalone GHASH command and test" ON)

option(ENABLE_SKF "Enable SKF module" ON)
option(ENABLE_SDF "Enable SDF module" ON)

option(ENABLE_ASM_UNDERSCORE_PREFIX "Add prefix `_` to assembly symbols" ON)

option(ENABLE_TLS "Enable TLS and TLCP protocol support" ON)
option(ENABLE_QUIC "Enable QUIC support" ON)
option(ENABLE_TLS_DEBUG "Enable TLS and TLCP print debug message" OFF)

option (ENABLE_SM2_ENC_PRE_COMPUTE "Enable SM2 encryption precomputing" ON)

set(src
	src/version.c
	src/debug.c
	src/sm4.c
	src/sm4_cbc.c
	src/sm4_ctr.c
	src/sm4_gcm.c
	src/sm3.c
	src/sm3_hmac.c
	src/sm3_kdf.c
	src/sm3_pbkdf2.c
	src/sm2_z256.c
	src/sm2_z256_table.c
	src/sm2_key.c
	src/sm2_sign.c
	src/sm2_enc.c
	src/sm2_exch.c
	src/block_cipher.c
	src/digest.c
	src/hmac.c
	src/hkdf.c
	src/pbkdf2.c
	src/gf128.c
	src/ghash.c
	src/pkcs8.c
	src/ec.c
	src/asn1.c
	src/hex.c
	src/base64.c
	src/pem.c
	src/x509_alg.c
	src/x509_cer.c
	src/x509_ext.c
	src/x509_vrf.c
	src/x509_req.c
	src/x509_crl.c
	src/x509_new.c
	src/ocsp.c
	src/x509_key.c
	src/rsa.c
	src/socket.c
	src/file.c
	src/passwd.c
)

set(tools
	tools/gmssl.c
	tools/passwd.c
	tools/version.c
#	tools/sm4.c
	tools/sm4_cbc.c
	tools/sm4_ctr.c
	tools/sm4_gcm.c
	tools/sm3.c
	tools/sm3_hmac.c
	tools/sm3_pbkdf2.c
	tools/sm2keygen.c
	tools/sm2sign.c
	tools/sm2verify.c
	tools/sm2encrypt.c
	tools/sm2decrypt.c
	tools/sm2exch.c
	tools/rand.c
	tools/certgen.c
	tools/certparse.c
	tools/certverify.c
	tools/certrevoke.c
	tools/ocspreq.c
	tools/ocspget.c
	tools/ocspsign.c
	tools/ocspverify.c
	tools/reqgen.c
	tools/reqparse.c
	tools/reqsign.c
	tools/crlgen.c
	tools/crlget.c
	tools/crlparse.c
	tools/crlverify.c
)

set(tests
	sm4
	sm4_cbc
	sm4_ctr
	sm4_gcm
	sm3
	sm3_hmac
	sm3_hkdf
	sm2_z256
	sm2_key
	sm2_sign
	sm2_enc
	sm2_exch
	block_cipher
	digest
	hkdf
	pbkdf2
	gf128
	pkcs8
	ec
	asn1
	hex
	base64
	pem
	x509
	x509_oid
	x509_alg
	x509_str
	x509_ext
	x509_vrf
	x509_req
	x509_crl
	x509_key
	ocsp
)




include(CheckSymbolExists)


option(ENABLE_SMALL_FOOTPRINT "Enable small code size" OFF)
if (ENABLE_SMALL_FOOTPRINT)
	message(STATUS "ENABLE_SMALL_FOOTPRINT is ON")
	add_definitions(-DENABLE_SMALL_FOOTPRINT)
endif()



if (ENABLE_TEST_SPEED)
	message(STATUS "ENABLE_TEST_SPEED is ON")
	add_definitions(-DENABLE_TEST_SPEED)
endif()

if (ENABLE_SLOW_TEST)
	message(STATUS "ENABLE_SLOW_TEST is ON")
	add_definitions(-DENABLE_SLOW_TEST)
endif()


option(ENABLE_SM2_ALGOR_ID_ENCODE_NULL "Enable AlgorithmIdenifier with algorithm sm2sign_with_sm3 encode a NULL object as parameters" OFF)
if (ENABLE_SM2_ALGOR_ID_ENCODE_NULL)
	message(STATUS "ENABLE_SM2_ALGOR_ID_ENCODE_NULL is ON")
	add_definitions(-DENABLE_SM2_ALGOR_ID_ENCODE_NULL)
endif()

if (ENABLE_ASM_UNDERSCORE_PREFIX)
	message(STATUS "ENABLE_ASM_UNDERSCORE_PREFIX is ON")
	add_definitions(-DENABLE_ASM_UNDERSCORE_PREFIX)
endif()

if (ENABLE_GMUL_ARM64)
	message(STATUS "ENABLE_GMUL_ARM64 is ON")
	add_definitions(-DENABLE_GMUL_ARM64)
	enable_language(ASM)
	list(APPEND src src/gf128_arm64.c)
endif()



if (ENABLE_SM2_ARM64)
	message(STATUS "ENABLE_SM2_ARM64 is ON")
	add_definitions(-DENABLE_SM2_ARM64)
	enable_language(ASM)
	list(APPEND src src/sm2_z256_arm64.S)
endif()

if (ENABLE_SM2_AMD64)
	message(STATUS "ENABLE_SM2_AMD64 is ON")
	add_definitions(-DENABLE_SM2_AMD64)
	enable_language(ASM)
	list(APPEND src src/sm2_z256_amd64.S)
endif()

if (ENABLE_SM2_LOONGARCH64)
	message(STATUS "ENABLE_SM2_LOONGARCH64 is ON")
	add_definitions(-DENABLE_SM2_LOONGARCH64)
	enable_language(ASM)
	list(APPEND src src/sm2_z256_loong64.S)
endif()

if (ENABLE_SM2_NEON)
	message(STATUS "ENABLE_SM2_NEON is ON")
	add_definitions(-DENABLE_SM2_Z256_NEON)
endif()

if (ENABLE_SM9_ARM64)
	if (NOT ENABLE_SM9)
		message(FATAL_ERROR "ENABLE_SM9_ARM64 requires ENABLE_SM9")
	endif()
	message(STATUS "ENABLE_SM9_ARM64 is ON")
	add_definitions(-DENABLE_SM9_ARM64)
	enable_language(ASM)
	list(APPEND src src/sm9_z256_arm64.S)
endif()


if (ENABLE_TLS_DEBUG)
	message(STATUS "ENABLE_TLS_DEBUG is ON")
	add_definitions(-DENABLE_TLS_DEBUG)
endif()

if (ENABLE_SM3_SSE)
	message(STATUS "ENABLE_SM3_SSE is ON")
	list(FIND src src/sm3.c sm3_index)
	list(REMOVE_AT src ${sm3_index})
	list(INSERT src ${sm3_index} src/sm3_sse.c)
	if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
		set_source_files_properties(src/sm3_sse.c PROPERTIES COMPILE_OPTIONS "-march=native")
	endif()
endif()

if (ENABLE_SM3_ARM64)
	message(STATUS "ENABLE_SM3_ARM64 is ON")
	list(FIND src src/sm3.c index)
	list(REMOVE_AT src ${index})
	list(INSERT src ${index} src/sm3_arm64.c)
endif()

if (ENABLE_SM4_ARM64)
	message(STATUS "ENABLE_SM4_ARM64 is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_arm64.c)
	enable_language(ASM)
endif()

if (ENABLE_SM4_AVX2)
	message(STATUS "ENABLE_SM4_AVX2 is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_avx2.c)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()

if (ENABLE_SM4_AESNI)
	message(STATUS "ENABLE_SM4_AESNI is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_aesni.c)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()




if (ENABLE_SM4_CE)
	message(STATUS "ENABLE_SM4_CE is ON")
	list(FIND src src/sm4.c sm4_index)
	list(REMOVE_AT src ${sm4_index})
	list(INSERT src ${sm4_index} src/sm4_ce.c)
	set_source_files_properties(src/sm4_ce.c PROPERTIES COMPILE_OPTIONS "-march=armv8.2-a+sm4")
endif()


if (ENABLE_SM4_CTR_AESNI_AVX)
	message(STATUS "ENABLE_SM4_CTR_AESNI_AVX is ON")
	list(FIND src src/sm4_ctr.c sm4_ctr_index)
	list(REMOVE_AT src ${sm4_ctr_index})
	list(INSERT src ${sm4_ctr_index} src/sm4_ctr_aesni_avx.c)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
endif()



if (ENABLE_SM4_CL)
	message(STATUS "ENABLE_SM4_CL is ON")
	add_definitions(-DENABLE_SM4_CL)
	if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
		add_definitions(-DMACOS) # to include <OpenCL/OpenCL.h>
	endif()
	list(APPEND src src/sm4_cl.c)
	list(APPEND tests sm4_cl)
endif()

if (ENABLE_SM4_ECB)
	message(STATUS "ENABLE_SM4_ECB is ON")
	add_definitions(-DENABLE_SM4_ECB)
	list(APPEND src src/sm4_ecb.c)
	list(APPEND tools tools/sm4_ecb.c)
	list(APPEND tests sm4_ecb)
endif()

if (ENABLE_SM4_OFB)
	message(STATUS "ENABLE_SM4_OFB is ON")
	add_definitions(-DENABLE_SM4_OFB)
	list(APPEND src src/sm4_ofb.c)
	list(APPEND tools tools/sm4_ofb.c)
	list(APPEND tests sm4_ofb)
endif()

if (ENABLE_SM4_CFB)
	message(STATUS "ENABLE_SM4_CFB is ON")
	add_definitions(-DENABLE_SM4_CFB)
	list(APPEND src src/sm4_cfb.c)
	list(APPEND tools tools/sm4_cfb.c)
	list(APPEND tests sm4_cfb)
endif()

if (ENABLE_SM4_CCM)
	message(STATUS "ENABLE_SM4_CCM is ON")
	set(ENABLE_SM4_CBC_MAC ON)
	add_definitions(-DENABLE_SM4_CCM)
	list(APPEND src src/sm4_ccm.c)
	list(APPEND tools tools/sm4_ccm.c)
	list(APPEND tests sm4_ccm)
endif()

if (ENABLE_SM4_XTS)
	message(STATUS "ENABLE_SM4_XTS is ON")
	add_definitions(-DENABLE_SM4_XTS)
	list(APPEND src src/sm4_xts.c)
	list(APPEND tools tools/sm4_xts.c)
	list(APPEND tests sm4_xts)
endif()

if (ENABLE_SM4_FF1)
	message(STATUS "ENABLE_SM4_FF1 is ON")
	add_definitions(-DENABLE_SM4_FF1)
	list(APPEND src src/sm4_ff1.c)
	list(APPEND tools tools/sm4_ff1.c)
	list(APPEND tests sm4_ff1)
endif()


if (ENABLE_SM9)
	message(STATUS "ENABLE_SM9 is ON")
	add_definitions(-DENABLE_SM9)
	list(APPEND src
		src/sm9_z256.c
		src/sm9_z256_table.c
		src/sm9_key.c
		src/sm9_sign.c
		src/sm9_enc.c
		src/sm9_exch.c
		src/sm9_cms.c)
	list(APPEND tools
		tools/sm9setup.c
		tools/sm9keygen.c
		tools/sm9sign.c
		tools/sm9verify.c
		tools/sm9encrypt.c
		tools/sm9decrypt.c
		tools/sm9exch.c)
	list(APPEND tests sm9)
endif()


if (ENABLE_CMS)
	message(STATUS "ENABLE_CMS is ON")
	add_definitions(-DENABLE_CMS)
	list(APPEND src src/cms.c)
	list(APPEND tools
		tools/cmssign.c
		tools/cmsverify.c
		tools/cmsencrypt.c
		tools/cmsdecrypt.c
		tools/cmsparse.c)
	list(APPEND tests cms)
endif()


if (ENABLE_SECP256R1)
	message(STATUS "ENABLE_SECP256R1 is ON")
	if (NOT ENABLE_SHA2)
		message(STATUS "ENABLE_SECP256R1 requires ENABLE_SHA2; enabling ENABLE_SHA2")
		set(ENABLE_SHA2 ON)
	endif()
	add_definitions(-DENABLE_SECP256R1)
	list(APPEND src src/bn.c src/secp256r1.c)
	list(APPEND tools tools/p256keygen.c)
	list(APPEND tests bn secp256r1 secp256r1_key ecdsa)
endif()

if (ENABLE_SECP384R1)
	message(STATUS "ENABLE_SECP384R1 is ON")
	if (NOT ENABLE_SHA2)
		message(STATUS "ENABLE_SECP384R1 requires ENABLE_SHA2; enabling ENABLE_SHA2")
		set(ENABLE_SHA2 ON)
	endif()
	add_definitions(-DENABLE_SECP384R1)
	if (NOT ENABLE_SECP256R1)
		list(APPEND src src/bn.c)
	endif()
	list(APPEND src src/secp384r1.c)
	list(APPEND tests secp384r1 secp384r1_key secp384r1_ecdsa)
endif()

if (ENABLE_LMS)
	message(STATUS "ENABLE_LMS is ON")
	add_definitions(-DENABLE_LMS)
	list(APPEND src src/lms.c)
	list(APPEND tools tools/lmskeygen.c tools/lmssign.c tools/lmsverify.c)
	list(APPEND tools tools/hsskeygen.c tools/hsssign.c tools/hssverify.c)
	list(APPEND tests lms)
endif()

if (ENABLE_LMS_CL)
	if (NOT ENABLE_LMS)
		message(FATAL_ERROR "ENABLE_LMS_CL requires ENABLE_LMS")
	endif()
	message(STATUS "ENABLE_LMS_CL is ON")
	add_definitions(-DENABLE_LMS_CL)
	if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
		add_definitions(-DMACOS) # to include <OpenCL/OpenCL.h>
	endif()
	list(APPEND src src/lms_cl.c)
	list(APPEND tests lms_cl)
endif()


if (ENABLE_XMSS)
	message(STATUS "ENABLE_XMSS is ON")
	add_definitions(-DENABLE_XMSS)
	list(APPEND src src/xmss.c)
	list(APPEND tools tools/xmsskeygen.c tools/xmsssign.c tools/xmssverify.c)
	list(APPEND tools tools/xmssmtkeygen.c tools/xmssmtsign.c tools/xmssmtverify.c)
	list(APPEND tests xmss)
endif()

if (ENABLE_XMSS_CL)
	if (NOT ENABLE_XMSS)
		message(FATAL_ERROR "ENABLE_XMSS_CL requires ENABLE_XMSS")
	endif()
	message(STATUS "ENABLE_XMSS_CL is ON")
	add_definitions(-DENABLE_XMSS_CL)
	if (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
		add_definitions(-DMACOS) # to include <OpenCL/OpenCL.h>
	endif()
	list(APPEND src src/xmss_cl.c)
	list(APPEND tests xmss_cl)
endif()


if (ENABLE_SPHINCS)
	message(STATUS "ENABLE_SPHINCS is ON")
	add_definitions(-DENABLE_SPHINCS)
	list(APPEND src src/sphincs.c)
	list(APPEND tools tools/sphincskeygen.c tools/sphincssign.c tools/sphincsverify.c)
	list(APPEND tests sphincs)
endif()

if (ENABLE_SM4_CL OR ENABLE_LMS_CL OR ENABLE_XMSS_CL)
	list(APPEND src src/cl.c)
endif()

if (ENABLE_LMS_CL OR ENABLE_XMSS_CL)
	list(APPEND src src/sm3_cl.c)
endif()


if (ENABLE_KYBER)
	message(STATUS "ENABLE_KYBER is ON")
	add_definitions(-DENABLE_KYBER)
	list(APPEND src src/sha3.c src/kyber.c)
	list(APPEND tools tools/kyberkeygen.c tools/kyberencap.c tools/kyberdecap.c)
	list(APPEND tests kyber)
endif()


if (ENABLE_SHA1)
	message(STATUS "ENABLE_SHA1 is ON")
	add_definitions(-DENABLE_SHA1)
	list(APPEND src src/sha1.c)
	list(APPEND tests sha1)
endif()


if (ENABLE_SHA2)
	message(STATUS "ENABLE_SHA2 is ON")
	add_definitions(-DENABLE_SHA2)
	list(APPEND src src/sha2.c)
	list(APPEND tests sha224 sha256 sha384 sha512 hmac)
endif()

if (ENABLE_AES)
	message(STATUS "ENABLE_AES is ON")
	add_definitions(-DENABLE_AES)
	list(APPEND src src/aes.c)
	list(APPEND tests aes)
endif()

if (ENABLE_AES_CCM)
	if (NOT ENABLE_AES)
		message(FATAL_ERROR "ENABLE_AES_CCM requires ENABLE_AES")
	endif()
	message(STATUS "ENABLE_AES_CCM is ON")
	add_definitions(-DENABLE_AES_CCM)
endif()


if (ENABLE_ZUC)
	message(STATUS "ENABLE_ZUC is ON")
	add_definitions(-DENABLE_ZUC)
	list(APPEND src src/zuc.c src/zuc_modes.c)
	list(APPEND tools
		tools/zuc.c
		tools/zuc256.c
		tools/zuc_128_eea3.c
		tools/zuc_128_eia3.c)
	list(APPEND tests zuc)
endif()

if (ENABLE_GHASH)
	message(STATUS "ENABLE_GHASH is ON")
	add_definitions(-DENABLE_GHASH)
	list(APPEND tools tools/ghash.c)
	list(APPEND tests ghash)
endif()

if (ENABLE_TLS)
	message(STATUS "ENABLE_TLS is ON")
	message(STATUS "TLS ECDHE-ECDSA cipher suites require ENABLE_AES, ENABLE_SHA2 and ENABLE_SECP256R1")
	add_definitions(-DENABLE_TLS)
	list(APPEND src
		src/tls.c
		src/tls_cert.c
		src/tls_alpn.c
		src/tls_ext.c
		src/tls_psk.c
		src/tls_sni.c
		src/sct.c
		src/tls_sct.c
		src/tls_ocsp.c
		src/tls_cookie.c
		src/tls_trace.c
		src/tls_vrf.c
		src/tlcp.c
		src/tls12.c
		src/tls13.c)
	list(APPEND tools
		tools/tlcp_client.c
		tools/tlcp_server.c
		tools/tls12_client.c
		tools/tls12_server.c
		tools/tls13_client.c
		tools/tls13_server.c
		tools/sctverify.c)
	list(APPEND tests tls tls13 tls_ocsp)
endif()

if (ENABLE_QUIC)
	if (ENABLE_TLS AND ENABLE_SHA2)
		message(STATUS "ENABLE_QUIC is ON")
		add_definitions(-DENABLE_QUIC)
		list(APPEND src src/quic.c)
		list(APPEND tools
			tools/quic_client.c
			tools/quic_server.c)
		list(APPEND tests quic)
	else()
		message(STATUS "ENABLE_QUIC requires ENABLE_TLS and ENABLE_SHA2; disabled")
	endif()
endif()


if (ENABLE_INTEL_RDRAND)
	include(CheckSourceCompiles)
	set(CMAKE_REQUIRED_FLAGS "-rdrand")
	check_source_compiles(C
		"#include <immintrin.h> int main(void) { unsigned long long val; _rdrand64_step(&val); return 0; }"
		HAVE_INTEL_RDRAND)
	if (HAVE_INTEL_RDRAND)
		message(STATUS "ENABLE_INTEL_RDRAND")
		add_definitions(-DENABLE_INTEL_RDRAND)
		list(APPEND src src/rdrand.c)
		set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mrdrnd")
	endif()
	if (ENABLE_INTEL_RDSEED)
		set(CMAKE_REQUIRED_FLAGS "-rdseed")
		check_source_compiles(C
			"#include <immintrin.h> int main(void) { unsigned long long val; _rdseed64_step(&val); return 0; }"
			HAVE_INTEL_RDSEED)
		if (HAVE_INTEL_RDSEED)
			message(STATUS "ENABLE_INTEL_RDSEED")
			add_definitions(-DENABLE_INTEL_RDSEED)
			set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mrdseed")
		endif()
	endif()
endif()


if (ENABLE_SM4_CBC_MAC)
	message(STATUS "ENABLE_SM4_CBC_MAC is ON")
	add_definitions(-DENABLE_SM4_CBC_MAC)
	list(APPEND src src/sm4_cbc_mac.c)
	list(APPEND tools tools/sm4_cbc_mac.c)
	list(APPEND tests sm4_cbc_mac)
endif()


check_symbol_exists(getentropy "unistd.h" HAVE_GETENTROPY)
if (WIN32)
	add_definitions(-D_WINSOCK_DEPRECATED_NO_WARNINGS)
	list(APPEND src src/rand_win.c src/http_win.c)
elseif (APPLE)
	list(APPEND src src/rand_apple.c src/http.c)
elseif (HAVE_GETENTROPY)
	list(APPEND src src/rand_unix.c src/http.c)
	message(STATUS "have getentropy")
else()
	list(APPEND src src/rand.c src/http.c)
endif()


if (ENABLE_SKF)
	message(STATUS "ENABLE_SKF is ON")
	add_definitions(-DENABLE_SKF)
	list(APPEND src
		src/skf/skf.c
		src/skf/skf_lib.c
		src/skf/skf_meth.c
		src/skf/skf_ext.c
		src/skf/skf_prn.c
		src/skf/skf_wisec.c)
	list(APPEND tools tools/skfutil.c)
	add_library(skf_dummy SHARED src/skf/skf_dummy.c)
	set_target_properties(skf_dummy PROPERTIES VERSION 3.3 SOVERSION 3)
endif()

if (ENABLE_SDF)
	message(STATUS "ENABLE_SDF is ON")
	add_definitions(-DENABLE_SDF)
	list(APPEND src
		src/sdf/sdf.c
		src/sdf/sdf_lib.c
		src/sdf/sdf_meth.c
		src/sdf/sdf_ext.c
		src/sdf/sdf_sansec.c)
	list(APPEND tools tools/sdfinfo.c tools/sdfdigest.c tools/sdfexport.c tools/sdfsign.c tools/sdfencrypt.c tools/sdfdecrypt.c tools/sdftest.c)
endif()


option(ENABLE_HTTP_TESTS "Enable HTTP GET/POST related tests" OFF)
if (ENABLE_HTTP_TESTS)
	message(STATUS "ENABLE_HTTP_TESTS")
	list(APPEND tests http http_crl)
endif()


option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
	message(STATUS "CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS")
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON) # set before add_library
endif()

add_library(gmssl ${src})





if (WIN32)
	target_link_libraries(gmssl PRIVATE Ws2_32)
elseif (APPLE)
	if (ENABLE_SDF)
		target_link_libraries(gmssl dl)
	endif()
	target_link_libraries(gmssl "-framework Security")
	#target_link_libraries(gmssl "-framework CoreFoundation") # rand_apple.c CFRelease()
elseif (MINGW)
	target_link_libraries(gmssl PRIVATE wsock32)
else()
	if (ENABLE_SDF)
		target_link_libraries(gmssl dl)
	endif()
endif()

if (ENABLE_SM4_CL OR ENABLE_LMS_CL OR ENABLE_XMSS_CL)
	if (APPLE)
		target_link_libraries(gmssl "-framework OpenCL")
	else()
		find_package(OpenCL REQUIRED)
		target_include_directories(gmssl PRIVATE ${OpenCL_INCLUDE_DIRS})
		target_link_libraries(gmssl ${OpenCL_LIBRARIES})
	endif()
endif()


set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")

SET_TARGET_PROPERTIES(gmssl PROPERTIES VERSION 3.3 SOVERSION 3)


install(TARGETS gmssl ARCHIVE DESTINATION lib LIBRARY DESTINATION lib RUNTIME DESTINATION bin)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/gmssl DESTINATION include)

if(UNIX AND NOT APPLE AND BUILD_SHARED_LIBS)
	install(CODE [[
		message(STATUS "GmSSL shared library installed to: ${CMAKE_INSTALL_PREFIX}/lib")
		message(STATUS "If gmssl or external applications cannot find libgmssl.so, configure the runtime library path manually.")
		message(STATUS "For a temporary shell: export LD_LIBRARY_PATH=${CMAKE_INSTALL_PREFIX}/lib:$LD_LIBRARY_PATH")
		message(STATUS "For a system-wide setup: echo ${CMAKE_INSTALL_PREFIX}/lib | sudo tee /etc/ld.so.conf.d/gmssl.conf && sudo ldconfig")
	]])
endif()


if (NOT ${CMAKE_SYSTEM_NAME} STREQUAL "iOS")
	add_executable(gmssl-bin ${tools})
	target_link_libraries(gmssl-bin LINK_PUBLIC gmssl)
	set_target_properties(gmssl-bin PROPERTIES RUNTIME_OUTPUT_NAME gmssl)
	if (WIN32)
		target_link_libraries(gmssl-bin PRIVATE Ws2_32)
	endif()

	enable_testing()
	foreach(name ${tests})
		add_test(NAME ${name} COMMAND ${name}test)
		add_executable(${name}test tests/${name}test.c)
		target_link_libraries (${name}test LINK_PUBLIC gmssl)
	endforeach()

	install(TARGETS gmssl-bin RUNTIME DESTINATION bin)
endif()

if (CMAKE_C_COMPILER_ID MATCHES "MSVC")
	set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT gmssl-bin)
	set(CMAKE_INSTALL_PREFIX "C:/Program Files/GmSSL") # change by `cmake -DCMAKE_INSTALL_PREFIX=C:\path\to\install`
	# run `set path=%path%;C:\Program Files\GmSSL\bin`
	add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

	target_compile_options(gmssl PRIVATE /utf-8)
	target_compile_options(gmssl-bin PRIVATE /utf-8)

#	target_compile_options(gmssl PRIVATE /wd4996)
#	target_compile_options(gmssl-bin PRIVATE /wd4996)
endif()


add_test(NAME tool_sm3 COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_sm3.cmake")
add_test(NAME tool_sm2 COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_sm2.cmake")
add_test(NAME tool_rand COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_rand.cmake")
add_test(NAME tool_sm4 COMMAND ${CMAKE_COMMAND}
	-DENABLE_SM4_ECB=${ENABLE_SM4_ECB}
	-DENABLE_SM4_CFB=${ENABLE_SM4_CFB}
	-DENABLE_SM4_OFB=${ENABLE_SM4_OFB}
	-DENABLE_SM4_CCM=${ENABLE_SM4_CCM}
	-DENABLE_SM4_XTS=${ENABLE_SM4_XTS}
	-DENABLE_SM4_CBC_MAC=${ENABLE_SM4_CBC_MAC}
	-DENABLE_SM4_FF1=${ENABLE_SM4_FF1}
	-P "${CMAKE_SOURCE_DIR}/cmake/tool_sm4.cmake")
if(ENABLE_ZUC)
	add_test(NAME tool_zuc COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_zuc.cmake")
endif()
if(ENABLE_GHASH)
	add_test(NAME tool_ghash COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_ghash.cmake")
endif()
if(ENABLE_SM9)
	add_test(NAME tool_sm9 COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_sm9.cmake")
endif()
if(ENABLE_LMS OR ENABLE_XMSS OR ENABLE_SPHINCS OR ENABLE_KYBER)
	add_test(NAME tool_pqc COMMAND ${CMAKE_COMMAND}
		-DENABLE_LMS=${ENABLE_LMS}
		-DENABLE_XMSS=${ENABLE_XMSS}
		-DENABLE_SPHINCS=${ENABLE_SPHINCS}
		-DENABLE_KYBER=${ENABLE_KYBER}
		-P "${CMAKE_SOURCE_DIR}/cmake/tool_pqc.cmake")
endif()
add_test(NAME tool_cert COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_cert.cmake")
set_tests_properties(tool_cert PROPERTIES FIXTURES_SETUP gmssl_cert_files)
add_test(NAME tool_crl COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_crl.cmake")
add_test(NAME tool_ocsp COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_ocsp.cmake")
set_tests_properties(tool_crl tool_ocsp PROPERTIES FIXTURES_REQUIRED gmssl_cert_files)
if(ENABLE_CMS)
	add_test(NAME tool_cms COMMAND ${CMAKE_COMMAND} -P "${CMAKE_SOURCE_DIR}/cmake/tool_cms.cmake")
	set_tests_properties(tool_cms PROPERTIES FIXTURES_REQUIRED gmssl_cert_files)
endif()
if(ENABLE_TLS AND NOT WIN32)
	find_program(OPENSSL_EXECUTABLE openssl)
	set(GMSSL_OPENSSL_INTEROP_ENABLED OFF)
	if(ENABLE_AES AND ENABLE_SHA2 AND ENABLE_SECP256R1)
		set(GMSSL_OPENSSL_INTEROP_ENABLED ON)
	else()
		message(STATUS "OpenSSL TLS interop tests require ENABLE_AES=ON, ENABLE_SHA2=ON and ENABLE_SECP256R1=ON; skipping")
	endif()
	add_test(NAME tool_tlcp_sm4_gcm_sni COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tlcp_sm4_gcm_sni -P "${CMAKE_SOURCE_DIR}/cmake/tlcp_commands.cmake")
	add_test(NAME tool_tlcp_sm4_cbc_sni COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tlcp_sm4_cbc_sni -P "${CMAKE_SOURCE_DIR}/cmake/tlcp_commands.cmake")
	add_test(NAME tool_tlcp_sm4_gcm_client_cert COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tlcp_sm4_gcm_client_cert -P "${CMAKE_SOURCE_DIR}/cmake/tlcp_commands.cmake")
	add_test(NAME tool_tlcp_ecdhe_sm4_cbc_client_cert COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tlcp_ecdhe_sm4_cbc_client_cert -P "${CMAKE_SOURCE_DIR}/cmake/tlcp_commands.cmake")
	add_test(NAME tool_tlcp_ecdhe_sm4_gcm_client_cert COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tlcp_ecdhe_sm4_gcm_client_cert -P "${CMAKE_SOURCE_DIR}/cmake/tlcp_commands.cmake")
	add_test(NAME tool_tls12_sm4_gcm_sni COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls12_sm4_gcm_sni -P "${CMAKE_SOURCE_DIR}/cmake/tls12_commands.cmake")
	add_test(NAME tool_tls12_sm4_cbc_sni COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls12_sm4_cbc_sni -P "${CMAKE_SOURCE_DIR}/cmake/tls12_commands.cmake")
	add_test(NAME tool_tls12_sm4_gcm_client_cert COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls12_sm4_gcm_client_cert -P "${CMAKE_SOURCE_DIR}/cmake/tls12_commands.cmake")
	add_test(NAME tool_tls12_sm4_gcm_renegotiation_info COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls12_sm4_gcm_renegotiation_info -P "${CMAKE_SOURCE_DIR}/cmake/tls12_commands.cmake")
	add_test(NAME tool_tls12_sm4_gcm_renegotiation_info_scsv COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls12_sm4_gcm_renegotiation_info_scsv -P "${CMAKE_SOURCE_DIR}/cmake/tls12_commands.cmake")
	add_test(NAME tool_tls12_client_reject_renegotiation_info_both
		COMMAND bash -c "bin/gmssl tls12_client -host 127.0.0.1 -renegotiation_info -renegotiation_info_scsv > tls12_client_reject_renegotiation_info_both.log 2>&1; test $? -ne 0 && grep -q 'should not be used together' tls12_client_reject_renegotiation_info_both.log")
	add_test(NAME tool_tls13_sm4_gcm_sni COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls13_sm4_gcm_sni -P "${CMAKE_SOURCE_DIR}/cmake/tls13_commands.cmake")
	add_test(NAME tool_tls13_sm4_gcm_client_cert COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls13_sm4_gcm_client_cert -P "${CMAKE_SOURCE_DIR}/cmake/tls13_commands.cmake")
	add_test(NAME tool_tls13_hrr_sm4_gcm COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls13_hrr_sm4_gcm -P "${CMAKE_SOURCE_DIR}/cmake/tls13_commands.cmake")
	add_test(NAME tool_tls13_psk_dhe_sm4_gcm COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls13_psk_dhe_sm4_gcm -P "${CMAKE_SOURCE_DIR}/cmake/tls13_commands.cmake")
	add_test(NAME tool_tls13_psk_only_sm4_gcm COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls13_psk_only_sm4_gcm -P "${CMAKE_SOURCE_DIR}/cmake/tls13_commands.cmake")
	add_test(NAME tool_tls13_early_data_sm4_gcm COMMAND ${CMAKE_COMMAND} -DTEST_CASE=tls13_early_data_sm4_gcm -P "${CMAKE_SOURCE_DIR}/cmake/tls13_commands.cmake")
	set_tests_properties(
		tool_tlcp_sm4_gcm_sni
		tool_tlcp_sm4_cbc_sni
		tool_tlcp_sm4_gcm_client_cert
		tool_tlcp_ecdhe_sm4_cbc_client_cert
		tool_tlcp_ecdhe_sm4_gcm_client_cert
		tool_tls12_sm4_gcm_sni
		tool_tls12_sm4_cbc_sni
		tool_tls12_sm4_gcm_client_cert
		tool_tls12_sm4_gcm_renegotiation_info
		tool_tls12_sm4_gcm_renegotiation_info_scsv
		tool_tls13_sm4_gcm_sni
		tool_tls13_sm4_gcm_client_cert
		tool_tls13_hrr_sm4_gcm
		tool_tls13_psk_dhe_sm4_gcm
		tool_tls13_psk_only_sm4_gcm
		tool_tls13_early_data_sm4_gcm
		PROPERTIES FIXTURES_REQUIRED gmssl_cert_files)
	if(OPENSSL_EXECUTABLE AND GMSSL_OPENSSL_INTEROP_ENABLED)
		add_test(NAME tool_tls12_openssl_server COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls12_openssl_server -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls12_openssl_server_renegotiation_info COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls12_openssl_server_renegotiation_info -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls12_openssl_server_renegotiation_info_scsv COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls12_openssl_server_renegotiation_info_scsv -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls12_openssl_client COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls12_openssl_client -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls13_openssl_server COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls13_openssl_server -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls13_openssl_client COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls13_openssl_client -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls13_hrr_openssl_client COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls13_hrr_openssl_client -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls13_psk_dhe_openssl_server COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls13_psk_dhe_openssl_server -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls13_psk_dhe_openssl_client COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls13_psk_dhe_openssl_client -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls13_psk_only_openssl_server COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls13_psk_only_openssl_server -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		add_test(NAME tool_tls13_psk_only_openssl_client COMMAND ${CMAKE_COMMAND} -DOPENSSL_EXECUTABLE=${OPENSSL_EXECUTABLE} -DTEST_CASE=tls13_psk_only_openssl_client -P "${CMAKE_SOURCE_DIR}/cmake/openssl_interop_commands.cmake")
		set_tests_properties(
			tool_tls12_openssl_server
			tool_tls12_openssl_server_renegotiation_info
			tool_tls12_openssl_server_renegotiation_info_scsv
			tool_tls12_openssl_client
			tool_tls13_openssl_server
			tool_tls13_openssl_client
			tool_tls13_hrr_openssl_client
			tool_tls13_psk_dhe_openssl_server
			tool_tls13_psk_dhe_openssl_client
			tool_tls13_psk_only_openssl_server
			tool_tls13_psk_only_openssl_client
			PROPERTIES FIXTURES_REQUIRED gmssl_cert_files)
	elseif(NOT OPENSSL_EXECUTABLE)
		message(STATUS "openssl executable not found; skipping OpenSSL TLS interop tests")
	endif()
endif()

# Generate install package with cpack
#	cpack -G TGZ
#	cpack -G STGZ
#	cpack -G NSIS64 # Windows only
#
# Install the STGZ package
#	./GmSSL-<version>-Linux.sh --prefix=/usr/local
#
set(CPACK_PACKAGE_NAME "GmSSL")
set(CPACK_PACKAGE_VENDOR "GmSSL develop team")
set(CPACK_PACKAGE_VERSION "3.3.0-dev.1182")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${PROJECT_SOURCE_DIR}/README.md)
set(CPACK_NSIS_MODIFY_PATH ON)
include(CPack)
