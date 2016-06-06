#
# OpenSSL/crypto/paillier/Makefile
#

DIR=    paillier
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
TEST=pailliertest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=pai_lib.c pai_err.c
LIBOBJ=pai_lib.o pai_err.o

SRC= $(LIBSRC)

EXHEADER= paillier.h
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

pai_err.o: ../../include/openssl/bio.h ../../include/openssl/bn.h
pai_err.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
pai_err.o: ../../include/openssl/err.h ../../include/openssl/lhash.h
pai_err.o: ../../include/openssl/opensslconf.h ../../include/openssl/opensslv.h
pai_err.o: ../../include/openssl/ossl_typ.h ../../include/openssl/paillier.h
pai_err.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
pai_err.o: ../../include/openssl/symhacks.h pai_err.c
pai_lib.o: ../../include/openssl/bn.h ../../include/openssl/crypto.h
pai_lib.o: ../../include/openssl/e_os2.h ../../include/openssl/opensslconf.h
pai_lib.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
pai_lib.o: ../../include/openssl/paillier.h ../../include/openssl/safestack.h
pai_lib.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
pai_lib.o: pai_lib.c
