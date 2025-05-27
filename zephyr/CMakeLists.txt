if(CONFIG_GMSSL)
  zephyr_interface_library_named(GmSSL)

  zephyr_library()
  
  # Core sources - always included
  zephyr_library_sources(
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/version.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/debug.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_cbc.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_ctr.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_gcm.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm3.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm3_hmac.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm3_kdf.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm3_pbkdf2.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm3_digest.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_z256.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_z256_table.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_key.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_sign.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_enc.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_exch.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm9_z256.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm9_z256_table.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm9_key.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm9_sign.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm9_enc.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm9_exch.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/zuc.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/zuc_modes.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/block_cipher.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/digest.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/hmac.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/hkdf.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/gf128.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/ghash.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_cbc_sm3_hmac.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_ctr_sm3_hmac.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/pkcs8.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/ec.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/rsa.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/asn1.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/hex.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/base64.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/pem.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/x509_alg.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/x509_cer.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/x509_ext.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/x509_req.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/x509_crl.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/x509_new.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/cms.c
    ${ZEPHYR_CURRENT_MODULE_DIR}/src/file.c
  )

  # TLS and networking sources - only include if needed
  if(CONFIG_GMSSL_TLS)
    zephyr_library_sources(
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/socket.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/tls.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/tls_ext.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/tls_trace.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/tlcp.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/tls12.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/tls13.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/http.c
    )
  endif()

  # Include file.c separately since it's duplicated
  if(NOT CONFIG_GMSSL_TLS)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/file.c)
  endif()

  # Platform-specific random sources
  if(CONFIG_SOC_FAMILY_NRF)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/rand.c)
  else()
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/rand.c)
  endif()

  # Conditional sources based on Kconfig
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SM4_ECB ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_ecb.c)
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SM4_OFB ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_ofb.c)
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SM4_CFB ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_cfb.c)
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SM4_CCM ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_ccm.c)
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SM4_XTS ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_xts.c)
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SM4_CBC_MAC ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm4_cbc_mac.c)
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SM3_XMSS ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm3_xmss.c)
  zephyr_library_sources_ifdef(CONFIG_GMSSL_SHA1 ${ZEPHYR_CURRENT_MODULE_DIR}/src/sha1.c)
  
  if(CONFIG_GMSSL_SHA2)
    zephyr_library_sources(
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sha256.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sha512.c
    )
  endif()
  
  if(CONFIG_GMSSL_AES)
    zephyr_library_sources(
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/aes.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/aes_modes.c
    )
  endif()
  
  zephyr_library_sources_ifdef(CONFIG_GMSSL_CHACHA20 ${ZEPHYR_CURRENT_MODULE_DIR}/src/chacha20.c)
  
  if(CONFIG_GMSSL_SDF)
    zephyr_library_sources(
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sdf/sdf.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sdf/sdf_lib.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sdf/sdf_meth.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sdf/sdf_ext.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sdf/sdf_sansec.c
    )
  endif()

  if(CONFIG_GMSSL_SM2_EXTS)
    zephyr_library_sources(
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_key_share.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_recover.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_blind.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_ring.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_elgamal.c
      ${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_commit.c
    )
  endif()

  # Architecture-specific optimizations
  if(CONFIG_GMSSL_SM2_ARM64)
    enable_language(ASM)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_z256_arm64.S)
  endif()

  if(CONFIG_GMSSL_SM9_ARM64)
    enable_language(ASM)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/sm9_z256_arm64.S)
  endif()

  if(CONFIG_GMSSL_GMUL_ARM64)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/gf128_arm64.c)
  endif()

  if(CONFIG_GMSSL_SM2_AMD64)
    enable_language(ASM)
    zephyr_library_sources(${ZEPHYR_CURRENT_MODULE_DIR}/src/sm2_z256_amd64.S)
  endif()

  # Compiler definitions based on Kconfig
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SMALL_FOOTPRINT ENABLE_SMALL_FOOTPRINT)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_TEST_SPEED ENABLE_TEST_SPEED)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM2_ALGOR_ID_ENCODE_NULL ENABLE_SM2_ALGOR_ID_ENCODE_NULL)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_ASM_UNDERSCORE_PREFIX ENABLE_ASM_UNDERSCORE_PREFIX)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_TLS_DEBUG ENABLE_TLS_DEBUG)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM2_ENC_PRE_COMPUTE ENABLE_SM2_ENC_PRE_COMPUTE)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM2_ARM64 ENABLE_SM2_ARM64)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM3_ARM64 ENABLE_SM3_ARM64)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_ARM64 ENABLE_SM4_ARM64)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_CE ENABLE_SM4_CE)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM9_ARM64 ENABLE_SM9_ARM64)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_GMUL_ARM64 ENABLE_GMUL_ARM64)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_AVX2 ENABLE_SM4_AVX2)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_AESNI ENABLE_SM4_AESNI)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM2_AMD64 ENABLE_SM2_AMD64)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM3_SSE ENABLE_SM3_SSE)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_CTR_AESNI_AVX ENABLE_SM4_CTR_AESNI_AVX)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_ECB ENABLE_SM4_ECB)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_OFB ENABLE_SM4_OFB)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_CFB ENABLE_SM4_CFB)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_CCM ENABLE_SM4_CCM)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SM4_XTS ENABLE_SM4_XTS)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SHA1 ENABLE_SHA1)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SHA2 ENABLE_SHA2)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_AES ENABLE_AES)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_CHACHA20 ENABLE_CHACHA20)
  zephyr_compile_definitions_ifdef(CONFIG_GMSSL_SDF ENABLE_SDF)

  # Include directories
  zephyr_include_directories(${ZEPHYR_CURRENT_MODULE_DIR}/include)

  target_link_libraries(GmSSL INTERFACE zephyr_interface)

endif()
