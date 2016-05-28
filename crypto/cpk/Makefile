#
# crypto/cpk/Makefile
#

DIR=	cpk
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=cpktest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	cpk_lib.c cpk_map.c cpk_kap.c cpk_asn1.c cpk_prn.c cpk_err.c
LIBOBJ=	cpk_lib.o cpk_map.o cpk_kap.o cpk_asn1.o cpk_prn.o cpk_err.o

SRC= $(LIBSRC)

EXHEADER= cpk.h
HEADER= $(EXHEADER)

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

cpk_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cpk_asn1.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cpk_asn1.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cpk_asn1.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cpk_asn1.o: ../../include/openssl/ecdsa.h ../../include/openssl/ecies.h
cpk_asn1.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cpk_asn1.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cpk_asn1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cpk_asn1.o: ../../include/openssl/opensslconf.h
cpk_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cpk_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cpk_asn1.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cpk_asn1.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cpk_asn1.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cpk_asn1.o: ../../include/openssl/x509_vfy.h cpk.h cpk_asn1.c
cpk_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cpk_err.o: ../../include/openssl/buffer.h ../../include/openssl/cpk.h
cpk_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cpk_err.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cpk_err.o: ../../include/openssl/ecdsa.h ../../include/openssl/ecies.h
cpk_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cpk_err.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cpk_err.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cpk_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cpk_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cpk_err.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cpk_err.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cpk_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cpk_err.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cpk_err.o: cpk_err.c
cpk_kap.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cpk_kap.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
cpk_kap.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cpk_kap.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cpk_kap.o: ../../include/openssl/ecies.h ../../include/openssl/err.h
cpk_kap.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cpk_kap.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cpk_kap.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cpk_kap.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cpk_kap.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cpk_kap.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cpk_kap.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cpk_kap.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cpk_kap.o: ../../include/openssl/x509_vfy.h cpk.h cpk_kap.c
cpk_lib.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cpk_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cpk_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cpk_lib.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cpk_lib.o: ../../include/openssl/ecdsa.h ../../include/openssl/ecies.h
cpk_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cpk_lib.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cpk_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cpk_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cpk_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pkcs7.h
cpk_lib.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
cpk_lib.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cpk_lib.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cpk_lib.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cpk_lib.o: ../../include/openssl/x509_vfy.h cpk.h cpk_lib.c
cpk_map.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cpk_map.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
cpk_map.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cpk_map.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cpk_map.o: ../../include/openssl/ecies.h ../../include/openssl/err.h
cpk_map.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cpk_map.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cpk_map.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cpk_map.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cpk_map.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cpk_map.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cpk_map.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cpk_map.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cpk_map.o: ../../include/openssl/x509_vfy.h cpk.h cpk_map.c
cpk_prn.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cpk_prn.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
cpk_prn.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cpk_prn.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cpk_prn.o: ../../include/openssl/ecies.h ../../include/openssl/err.h
cpk_prn.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cpk_prn.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cpk_prn.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cpk_prn.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cpk_prn.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cpk_prn.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cpk_prn.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cpk_prn.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cpk_prn.o: ../../include/openssl/x509_vfy.h cpk.h cpk_prn.c
