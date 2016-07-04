#
# crypto/ecies/Makefile
#

DIR=	ecies
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=eciestest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	ecies_lib.c ecies_asn1.c ecies_err.c
LIBOBJ=	ecies_lib.o ecies_asn1.o ecies_err.o

SRC= $(LIBSRC)

EXHEADER= ecies.h
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

ecies_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
ecies_asn1.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
ecies_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ecies_asn1.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ecies_asn1.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
ecies_asn1.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
ecies_asn1.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecies_asn1.o: ../../include/openssl/objects.h
ecies_asn1.o: ../../include/openssl/opensslconf.h
ecies_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecies_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ecies_asn1.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
ecies_asn1.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
ecies_asn1.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ecies_asn1.o: ../../include/openssl/x509_vfy.h ecies.h ecies_asn1.c
ecies_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
ecies_err.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
ecies_err.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
ecies_err.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
ecies_err.o: ../../include/openssl/ecies.h ../../include/openssl/err.h
ecies_err.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
ecies_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecies_err.o: ../../include/openssl/objects.h
ecies_err.o: ../../include/openssl/opensslconf.h
ecies_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecies_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
ecies_err.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
ecies_err.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
ecies_err.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
ecies_err.o: ../../include/openssl/x509_vfy.h ecies_err.c
ecies_lib.o: ../../include/openssl/aes.h ../../include/openssl/asn1.h
ecies_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
ecies_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
ecies_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
ecies_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/ecies.h
ecies_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
ecies_lib.o: ../../include/openssl/hmac.h ../../include/openssl/kdf.h
ecies_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
ecies_lib.o: ../../include/openssl/objects.h
ecies_lib.o: ../../include/openssl/opensslconf.h
ecies_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
ecies_lib.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
ecies_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
ecies_lib.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
ecies_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
ecies_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
ecies_lib.o: ../o_str.h ecies_lib.c
