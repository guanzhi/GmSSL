#
# OpenSSL/crypto/sm3/Makefile
#

DIR=    otp
TOP=    ../..
CC=     cc
CPP=    $(CC) -E
INCLUDES=-I.. -I$(TOP) -I../../include
CFLAG=-g
MAKEFILE=       Makefile
AR=             ar r

SM3_ASM_OBJ=

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=otptest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=otp.c otp_err.c
LIBOBJ=otp.o otp_err.o

SRC= $(LIBSRC)

EXHEADER= otp.h
HEADER= $(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:    lib

lib:    $(LIBOBJ)
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
	rm -f *.s *.o *.obj lib tags core .pure .nfs* *.old *.bak fluff

# DO NOT DELETE THIS LINE -- make depend depends on it.

otp.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
otp.o: ../../include/openssl/cbcmac.h ../../include/openssl/crypto.h
otp.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
otp.o: ../../include/openssl/evp.h ../../include/openssl/lhash.h
otp.o: ../../include/openssl/modes.h ../../include/openssl/obj_mac.h
otp.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
otp.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
otp.o: ../../include/openssl/otp.h ../../include/openssl/safestack.h
otp.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
otp.o: ../modes/modes_lcl.h otp.c
otp_err.o: ../../include/openssl/bio.h ../../include/openssl/crypto.h
otp_err.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
otp_err.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
otp_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
otp_err.o: ../../include/openssl/otp.h ../../include/openssl/safestack.h
otp_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
otp_err.o: otp_err.c
