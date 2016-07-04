#
# crypto/sm2/Makefile
#

DIR=	sm2
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=sm2test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	sm2_lib.c sm2_asn1.c sm2_err.c sm2_sign.c sm2_enc.c sm2_kap.c
LIBOBJ=	sm2_lib.o sm2_asn1.o sm2_err.o sm2_sign.o sm2_enc.o sm2_kap.o

SRC= $(LIBSRC)

EXHEADER= sm2.h
HEADER=	 $(EXHEADER)

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
	@headerlist="$(EXHEADER)"; for i in $$headerlist; \
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
	rm -f *.o */*.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

sm2_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
sm2_asn1.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
sm2_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm2_asn1.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
sm2_asn1.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
sm2_asn1.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
sm2_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
sm2_asn1.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
sm2_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm2_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
sm2_asn1.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
sm2_asn1.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
sm2_asn1.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
sm2_asn1.o: ../../include/openssl/x509_vfy.h sm2_asn1.c
sm2_enc.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sm2_enc.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
sm2_enc.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm2_enc.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
sm2_enc.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
sm2_enc.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
sm2_enc.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
sm2_enc.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
sm2_enc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm2_enc.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
sm2_enc.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
sm2_enc.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
sm2_enc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sm2_enc.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
sm2_enc.o: ../o_str.h sm2_enc.c
sm2_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sm2_err.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
sm2_err.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
sm2_err.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
sm2_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
sm2_err.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
sm2_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
sm2_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
sm2_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
sm2_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
sm2_err.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
sm2_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sm2_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
sm2_err.o: sm2_err.c
sm2_kap.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sm2_kap.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
sm2_kap.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
sm2_kap.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
sm2_kap.o: ../../include/openssl/err.h ../../include/openssl/evp.h
sm2_kap.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
sm2_kap.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
sm2_kap.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
sm2_kap.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
sm2_kap.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
sm2_kap.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
sm2_kap.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sm2_kap.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h sm2.h
sm2_kap.o: sm2_kap.c
sm2_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sm2_lib.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
sm2_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm2_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
sm2_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
sm2_lib.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
sm2_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
sm2_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
sm2_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm2_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
sm2_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
sm2_lib.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
sm2_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sm2_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
sm2_lib.o: sm2_lib.c
sm2_sign.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sm2_sign.o: ../../include/openssl/bn.h ../../include/openssl/buffer.h
sm2_sign.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm2_sign.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
sm2_sign.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
sm2_sign.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
sm2_sign.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
sm2_sign.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
sm2_sign.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm2_sign.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
sm2_sign.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
sm2_sign.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
sm2_sign.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sm2_sign.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
sm2_sign.o: sm2_sign.c
