#
# OpenSSL/crypto/zuc/Makefile
#

DIR=zuc
TOP=../..
CC=cc
CPP=$(CC) -E
INCLUDES=
CFLAG=-g
AR=ar r


ZUC_ENC=zuc.o

CFLAGS= $(INCLUDES) $(CFLAG)
ASFLAGS= $(INCLUDES) $(ASFLAG)
AFLAGS= $(ASFLAGS)

GENERAL=Makefile
TEST=
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=zuc.c
LIBOBJ=$(ZUC_ENC)

SRC= $(LIBSRC)

EXHEADER=zuc.h
HEADER=$(EXHEADER)

ALL=    $(GENERAL) $(SRC) $(HEADER)

top:
	(cd ../..; $(MAKE) DIRS=crypto SDIRS=$(DIR) sub_all)

all:	lib

lib:	$(LIBOBJ)
	$(AR) $(LIB) $(LIBOBJ)
	$(RANLIB) $(LIB) || echo Never mind.
	@touch lib

files:
	$(PERL) $(TOP)/util/files.pl "RC4_ENC=$(RC4_ENC)" Makefile >> $(TOP)/MINFO

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




zuc.o: ../../e_os.h ../../include/openssl/bio.h
zuc.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
zuc.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
zuc.o: ../../include/openssl/lhash.h ../../include/openssl/opensslconf.h
zuc.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
zuc.o: ../../include/openssl/rc4.h ../../include/openssl/safestack.h
zuc.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
zuc.o: ../cryptlib.h zuc.c zuc.h
