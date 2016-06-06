#
# OpenSSL/crypto/skf/Makefile
#

DIR=	skf
TOP=	../..
CC=	cc
INCLUDES=
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= skf_dev.c skf_token.c skf_dgst.c skf_ec.c skf_enc.c \
	skf_err.c skf_errstr.c skf_handle.c skf_mac.c skf_rand.c \
	skf_rsa.c skf_sesskey.c
LIBOBJ= skf_dev.o skf_token.o skf_dgst.o skf_ec.o skf_enc.o \
	skf_err.o skf_errstr.o skf_handle.o skf_mac.o skf_rand.o \
	skf_rsa.o skf_sesskey.o

SRC= $(LIBSRC)

EXHEADER= skf.h skf_ex.h
HEADER= skf_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl Makefile >> $(TOP)/MINFO

links:
	@$(PERL) $(TOP)/util/mklink.pl ../../include/openssl $(EXHEADER)
	@$(PERL) $(TOP)/util/mklink.pl ../../test $(TEST)
	@$(PERL) $(TOP)/util/mklink.pl ../../apps $(APPS)

install:
	@[ -n "$(INSTALLTOP)" ] # should be set by top Makefile...
	@headerlist="$(EXHEADER)"; for i in $$headerlist ; \
	do  \
	(cp $$i $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i; \
	chmod 644 $(INSTALL_PREFIX)$(INSTALLTOP)/include/openssl/$$i ); \
	done;

tags:
	ctags $(SRC)

tests:

lint:
	lint -DLINT $(INCLUDES) $(SRC)>fluff

update: depend

depend:
	@[ -n "$(MAKEDEPEND)" ] # should be set by upper Makefile...
	$(MAKEDEPEND) -- $(CFLAG) $(INCLUDES) $(DEPFLAG) -- $(PROGS) $(LIBSRC)

dclean:
	$(PERL) -pe 'if (/^# DO NOT DELETE THIS LINE/) {print; exit(0);}' $(MAKEFILE) >Makefile.new
	mv -f Makefile.new $(MAKEFILE)

clean:
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff a.out

# DO NOT DELETE THIS LINE -- make depend depends on it.

skf_dev.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_dev.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_dev.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_dev.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_dev.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_dev.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_dev.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_dev.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_dev.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
skf_dev.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
skf_dev.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
skf_dev.o: ../../include/openssl/skf.h ../../include/openssl/skf_ex.h
skf_dev.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
skf_dev.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
skf_dev.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
skf_dev.o: skf_dev.c skf_lcl.h
skf_dgst.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_dgst.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_dgst.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_dgst.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_dgst.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_dgst.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_dgst.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_dgst.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_dgst.o: ../../include/openssl/opensslconf.h
skf_dgst.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
skf_dgst.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
skf_dgst.o: ../../include/openssl/sha.h ../../include/openssl/skf.h
skf_dgst.o: ../../include/openssl/skf_ex.h ../../include/openssl/sm2.h
skf_dgst.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
skf_dgst.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
skf_dgst.o: ../../include/openssl/x509_vfy.h skf_dgst.c skf_lcl.h
skf_ec.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_ec.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_ec.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_ec.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_ec.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_ec.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_ec.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_ec.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_ec.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
skf_ec.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
skf_ec.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
skf_ec.o: ../../include/openssl/skf.h ../../include/openssl/skf_ex.h
skf_ec.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
skf_ec.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
skf_ec.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
skf_ec.o: skf_ec.c skf_lcl.h
skf_enc.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_enc.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_enc.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_enc.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_enc.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_enc.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
skf_enc.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
skf_enc.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
skf_enc.o: ../../include/openssl/skf.h ../../include/openssl/skf_ex.h
skf_enc.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
skf_enc.o: ../../include/openssl/sms4.h ../../include/openssl/stack.h
skf_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
skf_enc.o: ../../include/openssl/x509_vfy.h skf_enc.c skf_lcl.h
skf_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_err.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_err.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_err.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_err.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_err.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
skf_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
skf_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
skf_err.o: ../../include/openssl/skf.h ../../include/openssl/skf_ex.h
skf_err.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
skf_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
skf_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
skf_err.o: skf_err.c
skf_errstr.o: ../../include/openssl/skf.h skf_errstr.c
skf_handle.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_handle.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_handle.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_handle.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_handle.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_handle.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_handle.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_handle.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_handle.o: ../../include/openssl/opensslconf.h
skf_handle.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
skf_handle.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
skf_handle.o: ../../include/openssl/sha.h ../../include/openssl/skf.h
skf_handle.o: ../../include/openssl/skf_ex.h ../../include/openssl/sm2.h
skf_handle.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
skf_handle.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
skf_handle.o: ../../include/openssl/x509_vfy.h skf_handle.c skf_lcl.h
skf_mac.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_mac.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_mac.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_mac.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_mac.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_mac.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_mac.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_mac.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_mac.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
skf_mac.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
skf_mac.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
skf_mac.o: ../../include/openssl/skf.h ../../include/openssl/skf_ex.h
skf_mac.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
skf_mac.o: ../../include/openssl/sms4.h ../../include/openssl/stack.h
skf_mac.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
skf_mac.o: ../../include/openssl/x509_vfy.h skf_lcl.h skf_mac.c
skf_rand.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_rand.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_rand.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_rand.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_rand.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_rand.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_rand.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_rand.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_rand.o: ../../include/openssl/opensslconf.h
skf_rand.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
skf_rand.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
skf_rand.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
skf_rand.o: ../../include/openssl/skf.h ../../include/openssl/skf_ex.h
skf_rand.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
skf_rand.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
skf_rand.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
skf_rand.o: skf_lcl.h skf_rand.c
skf_rsa.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_rsa.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_rsa.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_rsa.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_rsa.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_rsa.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_rsa.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_rsa.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_rsa.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
skf_rsa.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
skf_rsa.o: ../../include/openssl/rsa.h ../../include/openssl/safestack.h
skf_rsa.o: ../../include/openssl/sha.h ../../include/openssl/skf.h
skf_rsa.o: ../../include/openssl/skf_ex.h ../../include/openssl/sm2.h
skf_rsa.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
skf_rsa.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
skf_rsa.o: ../../include/openssl/x509_vfy.h skf_lcl.h skf_rsa.c
skf_sesskey.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
skf_sesskey.o: ../../include/openssl/buffer.h ../../include/openssl/cbcmac.h
skf_sesskey.o: ../../include/openssl/cmac.h ../../include/openssl/crypto.h
skf_sesskey.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
skf_sesskey.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
skf_sesskey.o: ../../include/openssl/err.h ../../include/openssl/evp.h
skf_sesskey.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
skf_sesskey.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
skf_sesskey.o: ../../include/openssl/opensslconf.h
skf_sesskey.o: ../../include/openssl/opensslv.h
skf_sesskey.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
skf_sesskey.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
skf_sesskey.o: ../../include/openssl/skf.h ../../include/openssl/skf_ex.h
skf_sesskey.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
skf_sesskey.o: ../../include/openssl/sms4.h ../../include/openssl/stack.h
skf_sesskey.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
skf_sesskey.o: ../../include/openssl/x509_vfy.h skf_lcl.h skf_sesskey.c
skf_token.o: ../../include/openssl/skf.h skf_token.c
