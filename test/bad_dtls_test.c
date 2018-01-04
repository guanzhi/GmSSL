/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Unit test for Cisco DTLS1_BAD_VER session resume, as used by
 * AnyConnect VPN protocol.
 *
 * This is designed to exercise the code paths in
 * http://git.infradead.org/users/dwmw2/openconnect.git/blob/HEAD:/dtls.c
 * which have frequently been affected by regressions in DTLS1_BAD_VER
 * support.
 *
 * Note that unlike other SSL tests, we don't test against our own SSL
 * server method. Firstly because we don't have one; we *only* support
 * DTLS1_BAD_VER as a client. And secondly because even if that were
 * fixed up it's the wrong thing to test against — because if changes
 * are made in generic DTLS code which don't take DTLS1_BAD_VER into
 * account, there's plenty of scope for making those changes such that
 * they break *both* the client and the server in the same way.
 *
 * So we handle the server side manually. In a session resume there isn't
 * much to be done anyway.
 */
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include "../ssl/packet_locl.h"
#include "../e_os.h" /* for OSSL_NELEM() */

/* For DTLS1_BAD_VER packets the MAC doesn't include the handshake header */
#define MAC_OFFSET (DTLS1_RT_HEADER_LENGTH + DTLS1_HM_HEADER_LENGTH)

static unsigned char client_random[SSL3_RANDOM_SIZE];
static unsigned char server_random[SSL3_RANDOM_SIZE];

/* These are all generated locally, sized purely according to our own whim */
static unsigned char session_id[32];
static unsigned char master_secret[48];
static unsigned char cookie[20];

/* We've hard-coded the cipher suite; we know it's 104 bytes */
static unsigned char key_block[104];
#define mac_key (key_block + 20)
#define dec_key (key_block + 40)
#define enc_key (key_block + 56)

static EVP_MD_CTX *handshake_md;

static int do_PRF(const void *seed1, int seed1_len,
                  const void *seed2, int seed2_len,
                  const void *seed3, int seed3_len,
                  unsigned char *out, int olen)
{
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    size_t outlen = olen;

    /* No error handling. If it all screws up, the test will fail anyway */
    EVP_PKEY_derive_init(pctx);
#if !defined(OPENSSL_NO_MD5) && !defined(OPENSSL_NO_SHA1)
    EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_md5_sha1());
#elif !defined(OPENSSL_NO_SM3)
    EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sm3());
#else
# error "no avaiable digest"
#endif
    EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, master_secret, sizeof(master_secret));
    EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, seed1_len);
    EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, seed2_len);
    EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, seed3_len);
    EVP_PKEY_derive(pctx, out, &outlen);
    EVP_PKEY_CTX_free(pctx);
    return 1;
}

static SSL_SESSION *client_session(void)
{
    static unsigned char session_asn1[] = {
        0x30, 0x5F,              /* SEQUENCE, length 0x5F */
        0x02, 0x01, 0x01,        /* INTEGER, SSL_SESSION_ASN1_VERSION */
        0x02, 0x02, 0x01, 0x00,  /* INTEGER, DTLS1_BAD_VER */
        0x04, 0x02, 0x00, 0x2F,  /* OCTET_STRING, AES128-SHA */
        0x04, 0x20,              /* OCTET_STRING, session id */
#define SS_SESSID_OFS 15 /* Session ID goes here */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x30,              /* OCTET_STRING, master secret */
#define SS_SECRET_OFS 49 /* Master secret goes here */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    const unsigned char *p = session_asn1;

    /* Copy the randomly-generated fields into the above ASN1 */
    memcpy(session_asn1 + SS_SESSID_OFS, session_id, sizeof(session_id));
    memcpy(session_asn1 + SS_SECRET_OFS, master_secret, sizeof(master_secret));

    return d2i_SSL_SESSION(NULL, &p, sizeof(session_asn1));
}

/* Returns 1 for initial ClientHello, 2 for ClientHello with cookie */
static int validate_client_hello(BIO *wbio)
{
    PACKET pkt, pkt2;
    long len;
    unsigned char *data;
    int cookie_found = 0;
    unsigned int u;

    len = BIO_get_mem_data(wbio, (char **)&data);
    if (!PACKET_buf_init(&pkt, data, len))
        return 0;

    /* Check record header type */
    if (!PACKET_get_1(&pkt, &u) || u != SSL3_RT_HANDSHAKE)
        return 0;
    /* Version */
    if (!PACKET_get_net_2(&pkt, &u) || u != DTLS1_BAD_VER)
        return 0;
    /* Skip the rest of the record header */
    if (!PACKET_forward(&pkt, DTLS1_RT_HEADER_LENGTH - 3))
        return 0;

    /* Check it's a ClientHello */
    if (!PACKET_get_1(&pkt, &u) || u != SSL3_MT_CLIENT_HELLO)
        return 0;
    /* Skip the rest of the handshake message header */
    if (!PACKET_forward(&pkt, DTLS1_HM_HEADER_LENGTH - 1))
        return 0;

    /* Check client version */
    if (!PACKET_get_net_2(&pkt, &u) || u != DTLS1_BAD_VER)
        return 0;

    /* Store random */
    if (!PACKET_copy_bytes(&pkt, client_random, SSL3_RANDOM_SIZE))
        return 0;

    /* Check session id length and content */
    if (!PACKET_get_length_prefixed_1(&pkt, &pkt2) ||
        !PACKET_equal(&pkt2, session_id, sizeof(session_id)))
        return 0;

    /* Check cookie */
    if (!PACKET_get_length_prefixed_1(&pkt, &pkt2))
        return 0;
    if (PACKET_remaining(&pkt2)) {
        if (!PACKET_equal(&pkt2, cookie, sizeof(cookie)))
            return 0;
        cookie_found = 1;
    }

    /* Skip ciphers */
    if (!PACKET_get_net_2(&pkt, &u) || !PACKET_forward(&pkt, u))
        return 0;

    /* Skip compression */
    if (!PACKET_get_1(&pkt, &u) || !PACKET_forward(&pkt, u))
        return 0;

    /* Skip extensions */
    if (!PACKET_get_net_2(&pkt, &u) || !PACKET_forward(&pkt, u))
        return 0;

    /* Now we are at the end */
    if (PACKET_remaining(&pkt))
        return 0;

    /* Update handshake MAC for second ClientHello (with cookie) */
    if (cookie_found && !EVP_DigestUpdate(handshake_md, data + MAC_OFFSET,
                                          len - MAC_OFFSET))
            printf("EVP_DigestUpdate() failed\n");

    (void)BIO_reset(wbio);

    return 1 + cookie_found;
}

static int send_hello_verify(BIO *rbio)
{
    static unsigned char hello_verify[] = {
        0x16, /* Handshake */
        0x01, 0x00, /* DTLS1_BAD_VER */
        0x00, 0x00, /* Epoch 0 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Seq# 0 */
        0x00, 0x23, /* Length */
        0x03, /* Hello Verify */
        0x00, 0x00, 0x17, /* Length */
        0x00, 0x00, /* Seq# 0 */
        0x00, 0x00, 0x00, /* Fragment offset */
        0x00, 0x00, 0x17, /* Fragment length */
        0x01, 0x00, /* DTLS1_BAD_VER */
        0x14, /* Cookie length */
#define HV_COOKIE_OFS 28 /* Cookie goes here */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    memcpy(hello_verify + HV_COOKIE_OFS, cookie, sizeof(cookie));

    BIO_write(rbio, hello_verify, sizeof(hello_verify));

    return 1;
}

static int send_server_hello(BIO *rbio)
{
    static unsigned char server_hello[] = {
        0x16, /* Handshake */
        0x01, 0x00, /* DTLS1_BAD_VER */
        0x00, 0x00, /* Epoch 0 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, /* Seq# 1 */
        0x00, 0x52, /* Length */
        0x02, /* Server Hello */
        0x00, 0x00, 0x46, /* Length */
        0x00, 0x01, /* Seq# */
        0x00, 0x00, 0x00, /* Fragment offset */
        0x00, 0x00, 0x46, /* Fragment length */
        0x01, 0x00, /* DTLS1_BAD_VER */
#define SH_RANDOM_OFS 27 /* Server random goes here */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x20, /* Session ID length */
#define SH_SESSID_OFS 60 /* Session ID goes here */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x2f, /* Cipher suite AES128-SHA */
        0x00, /* Compression null */
    };
    static unsigned char change_cipher_spec[] = {
        0x14, /* Change Cipher Spec */
        0x01, 0x00, /* DTLS1_BAD_VER */
        0x00, 0x00, /* Epoch 0 */
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, /* Seq# 2 */
        0x00, 0x03, /* Length */
        0x01, 0x00, 0x02, /* Message */
    };

    memcpy(server_hello + SH_RANDOM_OFS, server_random, sizeof(server_random));
    memcpy(server_hello + SH_SESSID_OFS, session_id, sizeof(session_id));

    if (!EVP_DigestUpdate(handshake_md, server_hello + MAC_OFFSET,
                          sizeof(server_hello) - MAC_OFFSET))
        printf("EVP_DigestUpdate() failed\n");

    BIO_write(rbio, server_hello, sizeof(server_hello));
    BIO_write(rbio, change_cipher_spec, sizeof(change_cipher_spec));

    return 1;
}

/* Create header, HMAC, pad, encrypt and send a record */
static int send_record(BIO *rbio, unsigned char type, unsigned long seqnr,
                       const void *msg, size_t len)
{
    /* Note that the order of the record header fields on the wire,
     * and in the HMAC, is different. So we just keep them in separate
     * variables and handle them individually. */
    static unsigned char epoch[2] = { 0x00, 0x01 };
    static unsigned char seq[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    static unsigned char ver[2] = { 0x01, 0x00 }; /* DTLS1_BAD_VER */
    unsigned char lenbytes[2];
    HMAC_CTX *ctx;
    EVP_CIPHER_CTX *enc_ctx;
    unsigned char iv[16];
    unsigned char pad;
    unsigned char *enc;

#ifdef SIXTY_FOUR_BIT_LONG
    seq[0] = (seqnr >> 40) & 0xff;
    seq[1] = (seqnr >> 32) & 0xff;
#endif
    seq[2] = (seqnr >> 24) & 0xff;
    seq[3] = (seqnr >> 16) & 0xff;
    seq[4] = (seqnr >> 8) & 0xff;
    seq[5] = seqnr & 0xff;

    pad = 15 - ((len + SHA_DIGEST_LENGTH) % 16);
    enc = OPENSSL_malloc(len + SHA_DIGEST_LENGTH + 1 + pad);
    if (enc == NULL)
        return 0;

    /* Copy record to encryption buffer */
    memcpy(enc, msg, len);

    /* Append HMAC to data */
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, mac_key, 20, EVP_sha1(), NULL);
    HMAC_Update(ctx, epoch, 2);
    HMAC_Update(ctx, seq, 6);
    HMAC_Update(ctx, &type, 1);
    HMAC_Update(ctx, ver, 2); /* Version */
    lenbytes[0] = len >> 8;
    lenbytes[1] = len & 0xff;
    HMAC_Update(ctx, lenbytes, 2); /* Length */
    HMAC_Update(ctx, enc, len); /* Finally the data itself */
    HMAC_Final(ctx, enc + len, NULL);
    HMAC_CTX_free(ctx);

    /* Append padding bytes */
    len += SHA_DIGEST_LENGTH;
    do {
        enc[len++] = pad;
    } while (len % 16);

    /* Generate IV, and encrypt */
    RAND_bytes(iv, sizeof(iv));
    enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(enc_ctx, EVP_aes_128_cbc(), NULL, enc_key, iv, 1);
    EVP_Cipher(enc_ctx, enc, enc, len);
    EVP_CIPHER_CTX_free(enc_ctx);

    /* Finally write header (from fragmented variables), IV and encrypted record */
    BIO_write(rbio, &type, 1);
    BIO_write(rbio, ver, 2);
    BIO_write(rbio, epoch, 2);
    BIO_write(rbio, seq, 6);
    lenbytes[0] = (len + sizeof(iv)) >> 8;
    lenbytes[1] = (len + sizeof(iv)) & 0xff;
    BIO_write(rbio, lenbytes, 2);

    BIO_write(rbio, iv, sizeof(iv));
    BIO_write(rbio, enc, len);

    OPENSSL_free(enc);
    return 1;
}

static int send_finished(SSL *s, BIO *rbio)
{
    static unsigned char finished_msg[DTLS1_HM_HEADER_LENGTH +
                                      TLS1_FINISH_MAC_LENGTH] = {
        0x14, /* Finished */
        0x00, 0x00, 0x0c, /* Length */
        0x00, 0x03, /* Seq# 3 */
        0x00, 0x00, 0x00, /* Fragment offset */
        0x00, 0x00, 0x0c, /* Fragment length */
        /* Finished MAC (12 bytes) */
    };
    unsigned char handshake_hash[EVP_MAX_MD_SIZE];

    /* Derive key material */
    do_PRF(TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
           server_random, SSL3_RANDOM_SIZE,
           client_random, SSL3_RANDOM_SIZE,
           key_block, sizeof(key_block));

    /* Generate Finished MAC */
    if (!EVP_DigestFinal_ex(handshake_md, handshake_hash, NULL))
        printf("EVP_DigestFinal_ex() failed\n");

    do_PRF(TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
           handshake_hash, EVP_MD_CTX_size(handshake_md),
           NULL, 0,
           finished_msg + DTLS1_HM_HEADER_LENGTH, TLS1_FINISH_MAC_LENGTH);

    return send_record(rbio, SSL3_RT_HANDSHAKE, 0,
                       finished_msg, sizeof(finished_msg));
}

static int validate_ccs(BIO *wbio)
{
    PACKET pkt;
    long len;
    unsigned char *data;
    unsigned int u;

    len = BIO_get_mem_data(wbio, (char **)&data);
    if (!PACKET_buf_init(&pkt, data, len))
        return 0;

    /* Check record header type */
    if (!PACKET_get_1(&pkt, &u) || u != SSL3_RT_CHANGE_CIPHER_SPEC)
        return 0;
    /* Version */
    if (!PACKET_get_net_2(&pkt, &u) || u != DTLS1_BAD_VER)
        return 0;
    /* Skip the rest of the record header */
    if (!PACKET_forward(&pkt, DTLS1_RT_HEADER_LENGTH - 3))
        return 0;

    /* Check ChangeCipherSpec message */
    if (!PACKET_get_1(&pkt, &u) || u != SSL3_MT_CCS)
        return 0;
    /* A DTLS1_BAD_VER ChangeCipherSpec also contains the
     * handshake sequence number (which is 2 here) */
    if (!PACKET_get_net_2(&pkt, &u) || u != 0x0002)
        return 0;

    /* Now check the Finished packet */
    if (!PACKET_get_1(&pkt, &u) || u != SSL3_RT_HANDSHAKE)
        return 0;
    if (!PACKET_get_net_2(&pkt, &u) || u != DTLS1_BAD_VER)
        return 0;

    /* Check epoch is now 1 */
    if (!PACKET_get_net_2(&pkt, &u) || u != 0x0001)
        return 0;

    /* That'll do for now. If OpenSSL accepted *our* Finished packet
     * then it's evidently remembered that DTLS1_BAD_VER doesn't
     * include the handshake header in the MAC. There's not a lot of
     * point in implementing decryption here, just to check that it
     * continues to get it right for one more packet. */

    return 1;
}

#define NODROP(x) { x##UL, 0 }
#define DROP(x)   { x##UL, 1 }

static struct {
    unsigned long seq;
    int drop;
} tests[] = {
    NODROP(1), NODROP(3), NODROP(2),
    NODROP(0x1234), NODROP(0x1230), NODROP(0x1235),
    NODROP(0xffff), NODROP(0x10001), NODROP(0xfffe), NODROP(0x10000),
    DROP(0x10001), DROP(0xff), NODROP(0x100000), NODROP(0x800000), NODROP(0x7fffe1),
    NODROP(0xffffff), NODROP(0x1000000), NODROP(0xfffffe), DROP(0xffffff), NODROP(0x1000010),
    NODROP(0xfffffd), NODROP(0x1000011), DROP(0x12), NODROP(0x1000012),
    NODROP(0x1ffffff), NODROP(0x2000000), DROP(0x1ff00fe), NODROP(0x2000001),
    NODROP(0x20fffff), NODROP(0x2105500), DROP(0x20ffffe), NODROP(0x21054ff),
    NODROP(0x211ffff), DROP(0x2110000), NODROP(0x2120000)
    /* The last test should be NODROP, because a DROP wouldn't get tested. */
};

int main(int argc, char *argv[])
{
    SSL_SESSION *sess;
    SSL_CTX *ctx;
    SSL *con;
    BIO *rbio;
    BIO *wbio;
    BIO *err;
    time_t now = 0;
    int testresult = 0;
    int ret;
    int i;

    err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_bytes(session_id, sizeof(session_id));
    RAND_bytes(master_secret, sizeof(master_secret));
    RAND_bytes(cookie, sizeof(cookie));
    RAND_bytes(server_random + 4, sizeof(server_random) - 4);

    now = time(NULL);
    memcpy(server_random, &now, sizeof(now));

    sess = client_session();
    if (sess == NULL) {
        printf("Failed to generate SSL_SESSION\n");
        goto end;
    }

    handshake_md = EVP_MD_CTX_new();
    if (handshake_md == NULL ||
        !EVP_DigestInit_ex(handshake_md, EVP_md5_sha1(), NULL)) {
        printf("Failed to initialise handshake_md\n");
        goto end;
    }

    ctx = SSL_CTX_new(DTLS_client_method());
    if (ctx == NULL) {
        printf("Failed to allocate SSL_CTX\n");
        goto end_md;
    }
    if (!SSL_CTX_set_min_proto_version(ctx, DTLS1_BAD_VER)) {
        printf("SSL_CTX_set_min_proto_version() failed\n");
        goto end_ctx;
    }
    if (!SSL_CTX_set_max_proto_version(ctx, DTLS1_BAD_VER)) {
        printf("SSL_CTX_set_max_proto_version() failed\n");
        goto end_ctx;
    }

    if (!SSL_CTX_set_cipher_list(ctx, "AES128-SHA")) {
        printf("SSL_CTX_set_cipher_list() failed\n");
        goto end_ctx;
    }

    con = SSL_new(ctx);
    if (!SSL_set_session(con, sess)) {
        printf("SSL_set_session() failed\n");
        goto end_con;
    }
    SSL_SESSION_free(sess);

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());

    BIO_set_nbio(rbio, 1);
    BIO_set_nbio(wbio, 1);

    SSL_set_bio(con, rbio, wbio);
    SSL_set_connect_state(con);

    /* Send initial ClientHello */
    ret = SSL_do_handshake(con);
    if (ret > 0 || SSL_get_error(con, ret) != SSL_ERROR_WANT_READ) {
        printf("Unexpected handshake result at initial call!\n");
        goto end_con;
    }

    if (validate_client_hello(wbio) != 1) {
        printf("Initial ClientHello failed validation\n");
        goto end_con;
    }
    if (send_hello_verify(rbio) != 1) {
        printf("Failed to send HelloVerify\n");
        goto end_con;
    }
    ret = SSL_do_handshake(con);
    if (ret > 0 || SSL_get_error(con, ret) != SSL_ERROR_WANT_READ) {
        printf("Unexpected handshake result after HelloVerify!\n");
        goto end_con;
    }
    if (validate_client_hello(wbio) != 2) {
        printf("Second ClientHello failed validation\n");
        goto end_con;
    }
    if (send_server_hello(rbio) != 1) {
        printf("Failed to send ServerHello\n");
        goto end_con;
    }
    ret = SSL_do_handshake(con);
    if (ret > 0 || SSL_get_error(con, ret) != SSL_ERROR_WANT_READ) {
        printf("Unexpected handshake result after ServerHello!\n");
        goto end_con;
    }
    if (send_finished(con, rbio) != 1) {
        printf("Failed to send Finished\n");
        goto end_con;
    }
    ret = SSL_do_handshake(con);
    if (ret < 1) {
        printf("Handshake not successful after Finished!\n");
        goto end_con;
    }
    if (validate_ccs(wbio) != 1) {
        printf("Failed to validate client CCS/Finished\n");
        goto end_con;
    }

    /* While we're here and crafting packets by hand, we might as well do a
       bit of a stress test on the DTLS record replay handling. Not Cisco-DTLS
       specific but useful anyway for the general case. It's been broken
       before, and in fact was broken even for a basic 0, 2, 1 test case
       when this test was first added.... */
    for (i = 0; i < (int)OSSL_NELEM(tests); i++) {
        unsigned long recv_buf[2];

        if (send_record(rbio, SSL3_RT_APPLICATION_DATA, tests[i].seq,
                        &tests[i].seq, sizeof(unsigned long)) != 1) {
            printf("Failed to send data seq #0x%lx (%d)\n",
                   tests[i].seq, i);
            goto end_con;
        }

        if (tests[i].drop)
            continue;

        ret = SSL_read(con, recv_buf, 2 * sizeof(unsigned long));
        if (ret != sizeof(unsigned long)) {
            printf("SSL_read failed or wrong size on seq#0x%lx (%d)\n",
                   tests[i].seq, i);
            goto end_con;
        }
        if (recv_buf[0] != tests[i].seq) {
            printf("Wrong data packet received (0x%lx not 0x%lx) at packet %d\n",
                   recv_buf[0], tests[i].seq, i);
            goto end_con;
        }
    }
    if (tests[i-1].drop) {
        printf("Error: last test cannot be DROP()\n");
        goto end_con;
    }
    testresult=1;

 end_con:
    SSL_free(con);
 end_ctx:
    SSL_CTX_free(ctx);
 end_md:
    EVP_MD_CTX_free(handshake_md);
 end:
    ERR_print_errors_fp(stderr);

    if (!testresult) {
        printf("Cisco BadDTLS test: FAILED\n");
    }


#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(err) <= 0)
        testresult = 0;
#endif
    BIO_free(err);

    return testresult?0:1;
}
