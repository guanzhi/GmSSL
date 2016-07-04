#
# OpenSSL/crypto/sm9/Makefile
#

DIR=    sm9
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
TEST=sm9test.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=sm9_lib.c sm9_err.c
LIBOBJ=sm9_lib.o sm9_err.o

SRC= $(LIBSRC)

EXHEADER= sm9.h
HEADER= sm9_lcl.h $(EXHEADER)

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

sm9_err.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sm9_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm9_err.o: ../../include/openssl/err.h ../../include/openssl/evp.h
sm9_err.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
sm9_err.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
sm9_err.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm9_err.o: ../../include/openssl/safestack.h ../../include/openssl/sm9.h
sm9_err.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sm9_err.o: sm9_err.c
sm9_lib.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
sm9_lib.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
sm9_lib.o: ../../include/openssl/err.h ../../include/openssl/evp.h
sm9_lib.o: ../../include/openssl/lhash.h ../../include/openssl/obj_mac.h
sm9_lib.o: ../../include/openssl/objects.h ../../include/openssl/opensslconf.h
sm9_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sm9_lib.o: ../../include/openssl/safestack.h ../../include/openssl/sm9.h
sm9_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h sm9.h
sm9_lib.o: sm9_lcl.h sm9_lib.c
