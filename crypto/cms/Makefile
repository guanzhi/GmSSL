#
# OpenSSL/crypto/cms/Makefile
#

DIR=	cms
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC= cms_lib.c cms_asn1.c cms_att.c cms_io.c cms_smime.c cms_err.c \
	cms_sd.c cms_dd.c cms_cd.c cms_env.c cms_enc.c cms_ess.c \
	cms_pwri.c cms_kari.c
LIBOBJ= cms_lib.o cms_asn1.o cms_att.o cms_io.o cms_smime.o cms_err.o \
	cms_sd.o cms_dd.o cms_cd.o cms_env.o cms_enc.o cms_ess.o \
	cms_pwri.o cms_kari.o

SRC= $(LIBSRC)

EXHEADER=  cms.h
HEADER=	cms_lcl.h $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

test:

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

cms_asn1.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_asn1.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_asn1.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_asn1.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_asn1.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_asn1.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_asn1.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_asn1.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_asn1.o: ../../include/openssl/opensslconf.h
cms_asn1.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_asn1.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_asn1.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_asn1.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cms_asn1.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cms_asn1.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_asn1.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_asn1.o: cms.h cms_asn1.c cms_lcl.h
cms_att.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_att.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_att.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_att.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_att.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_att.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_att.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_att.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_att.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_att.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_att.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_att.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_att.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cms_att.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_att.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_att.o: ../../include/openssl/x509v3.h cms.h cms_att.c cms_lcl.h
cms_cd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_cd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_cd.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_cd.o: ../../include/openssl/comp.h ../../include/openssl/conf.h
cms_cd.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_cd.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_cd.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_cd.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cms_cd.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_cd.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_cd.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_cd.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_cd.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_cd.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cms_cd.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cms_cd.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_cd.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_cd.o: ../cryptlib.h cms_cd.c cms_lcl.h
cms_dd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_dd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_dd.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_dd.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_dd.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_dd.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_dd.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_dd.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_dd.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_dd.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_dd.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_dd.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_dd.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_dd.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cms_dd.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_dd.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_dd.o: ../../include/openssl/x509v3.h ../cryptlib.h cms_dd.c cms_lcl.h
cms_enc.o: ../../e_os.h ../../include/openssl/asn1.h
cms_enc.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_enc.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_enc.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_enc.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_enc.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_enc.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_enc.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_enc.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_enc.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_enc.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_enc.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_enc.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
cms_enc.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cms_enc.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cms_enc.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_enc.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_enc.o: ../cryptlib.h cms_enc.c cms_lcl.h
cms_env.o: ../../e_os.h ../../include/openssl/aes.h
cms_env.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_env.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_env.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_env.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_env.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_env.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_env.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cms_env.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_env.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_env.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_env.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_env.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_env.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_env.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cms_env.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_env.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_env.o: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_env.o: cms_env.c cms_lcl.h
cms_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
cms_err.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_err.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_err.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_err.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cms_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_err.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_err.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cms_err.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cms_err.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_err.o: ../../include/openssl/x509_vfy.h cms_err.c
cms_ess.o: ../../e_os.h ../../include/openssl/asn1.h
cms_ess.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_ess.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_ess.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_ess.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_ess.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_ess.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_ess.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_ess.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_ess.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_ess.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_ess.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_ess.o: ../../include/openssl/rand.h ../../include/openssl/safestack.h
cms_ess.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cms_ess.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cms_ess.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_ess.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_ess.o: ../cryptlib.h cms_ess.c cms_lcl.h
cms_io.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_io.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_io.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_io.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_io.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_io.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cms_io.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_io.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_io.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_io.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_io.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_io.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cms_io.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cms_io.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_io.o: ../../include/openssl/x509_vfy.h cms.h cms_io.c cms_lcl.h
cms_kari.o: ../../e_os.h ../../include/openssl/aes.h
cms_kari.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_kari.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_kari.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_kari.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_kari.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_kari.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_kari.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cms_kari.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_kari.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_kari.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_kari.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_kari.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_kari.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_kari.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cms_kari.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_kari.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_kari.o: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_kari.o: cms_kari.c cms_lcl.h
cms_lib.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_lib.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_lib.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_lib.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_lib.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_lib.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_lib.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_lib.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_lib.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_lib.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cms_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_lib.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_lib.o: ../../include/openssl/x509v3.h cms.h cms_lcl.h cms_lib.c
cms_pwri.o: ../../e_os.h ../../include/openssl/aes.h
cms_pwri.o: ../../include/openssl/asn1.h ../../include/openssl/asn1t.h
cms_pwri.o: ../../include/openssl/bio.h ../../include/openssl/buffer.h
cms_pwri.o: ../../include/openssl/cms.h ../../include/openssl/conf.h
cms_pwri.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
cms_pwri.o: ../../include/openssl/ec.h ../../include/openssl/ecdh.h
cms_pwri.o: ../../include/openssl/ecdsa.h ../../include/openssl/err.h
cms_pwri.o: ../../include/openssl/evp.h ../../include/openssl/kdf.h
cms_pwri.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
cms_pwri.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
cms_pwri.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_pwri.o: ../../include/openssl/pem.h ../../include/openssl/pem2.h
cms_pwri.o: ../../include/openssl/pkcs7.h ../../include/openssl/rand.h
cms_pwri.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_pwri.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cms_pwri.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_pwri.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_pwri.o: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_pwri.o: cms_lcl.h cms_pwri.c
cms_sd.o: ../../e_os.h ../../include/openssl/asn1.h
cms_sd.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_sd.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_sd.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_sd.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_sd.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_sd.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_sd.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_sd.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_sd.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
cms_sd.o: ../../include/openssl/ossl_typ.h ../../include/openssl/pem.h
cms_sd.o: ../../include/openssl/pem2.h ../../include/openssl/pkcs7.h
cms_sd.o: ../../include/openssl/safestack.h ../../include/openssl/sha.h
cms_sd.o: ../../include/openssl/sm2.h ../../include/openssl/sm3.h
cms_sd.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
cms_sd.o: ../../include/openssl/x509.h ../../include/openssl/x509_vfy.h
cms_sd.o: ../../include/openssl/x509v3.h ../asn1/asn1_locl.h ../cryptlib.h
cms_sd.o: cms_lcl.h cms_sd.c
cms_smime.o: ../../e_os.h ../../include/openssl/asn1.h
cms_smime.o: ../../include/openssl/asn1t.h ../../include/openssl/bio.h
cms_smime.o: ../../include/openssl/buffer.h ../../include/openssl/cms.h
cms_smime.o: ../../include/openssl/conf.h ../../include/openssl/crypto.h
cms_smime.o: ../../include/openssl/e_os2.h ../../include/openssl/ec.h
cms_smime.o: ../../include/openssl/ecdh.h ../../include/openssl/ecdsa.h
cms_smime.o: ../../include/openssl/err.h ../../include/openssl/evp.h
cms_smime.o: ../../include/openssl/kdf.h ../../include/openssl/lhash.h
cms_smime.o: ../../include/openssl/obj_mac.h ../../include/openssl/objects.h
cms_smime.o: ../../include/openssl/opensslconf.h
cms_smime.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
cms_smime.o: ../../include/openssl/pkcs7.h ../../include/openssl/safestack.h
cms_smime.o: ../../include/openssl/sha.h ../../include/openssl/sm2.h
cms_smime.o: ../../include/openssl/sm3.h ../../include/openssl/stack.h
cms_smime.o: ../../include/openssl/symhacks.h ../../include/openssl/x509.h
cms_smime.o: ../../include/openssl/x509_vfy.h ../../include/openssl/x509v3.h
cms_smime.o: ../asn1/asn1_locl.h ../cryptlib.h cms_lcl.h cms_smime.c
