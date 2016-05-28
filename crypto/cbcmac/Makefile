#
# OpenSSL/crypto/cbcmac/Makefile
#

DIR=	cbcmac
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
LIBSRC=cbcmac.c cbcmac_err.c cbcm_ameth.c cbcm_pmeth.c
LIBOBJ=cbcmac.o cbcmac_err.o cbcm_ameth.o cbcm_pmeth.o

SRC= $(LIBSRC)

EXHEADER= cbcmac.h
HEADER=	$(EXHEADER)

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
	rm -f *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

cbcm_ameth.o: ../../e_os.h ../../include/openssl/asn1.h
cbcm_ameth.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cbcm_ameth.o: ../../include/openssl/cbcmac.h ../../include/openssl/crypto.h
cbcm_ameth.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
cbcm_ameth.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cbcm_ameth.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cbcm_ameth.o: ../../include/openssl/opensslconf.h
cbcm_ameth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cbcm_ameth.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cbcm_ameth.o: ../../include/openssl/symhacks.h ../asn1/asn1_locl.h
cbcm_ameth.o: ../cryptlib.h cbcm_ameth.c
cbcm_pmeth.o: ../../e_os.h ../../include/openssl/asn1.h
cbcm_pmeth.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cbcm_pmeth.o: ../../include/openssl/cbcmac.h ../../include/openssl/conf.h
cbcm_pmeth.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cbcm_pmeth.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cbcm_pmeth.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cbcm_pmeth.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cbcm_pmeth.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cbcm_pmeth.o: ../../include/openssl/objects.h
cbcm_pmeth.o: ../../include/openssl/opensslconf.h
cbcm_pmeth.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cbcm_pmeth.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cbcm_pmeth.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cbcm_pmeth.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cbcm_pmeth.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cbcm_pmeth.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cbcm_pmeth.o: ../cryptlib.h ../evp/evp_locl.h cbcm_pmeth.c
cbcmac.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cbcmac.o: ../../include/openssl/cbcmac.h ../../include/openssl/crypto.h
cbcmac.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
cbcmac.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cbcmac.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cbcmac.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cbcmac.o: ../../include/openssl/ossl_typ.h ../../include/openssl/safestack.h
cbcmac.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cbcmac.o: cbcmac.c
cbcmac_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cbcmac_err.o: ../../include/openssl/cbcmac.h ../../include/openssl/crypto.h
cbcmac_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
cbcmac_err.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
cbcmac_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cbcmac_err.o: ../../include/openssl/opensslconf.h
cbcmac_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cbcmac_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
cbcmac_err.o: ../../include/openssl/symhacks.h cbcmac_err.c
