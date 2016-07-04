#
# OpenSSL/crypto/sms4/Makefile
#

DIR=	sms4
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
LIBSRC=sms4_cbc.c sms4_cfb.c sms4_ecb.c sms4_ofb.c sms4_ctr.c sms4_wrap.c sms4_common.c sms4_setkey.c sms4_enc.c
LIBOBJ=sms4_cbc.o sms4_cfb.o sms4_ecb.o sms4_ofb.o sms4_ctr.o sms4_wrap.o sms4_common.o sms4_setkey.o sms4_enc.o

SRC= $(LIBSRC)

EXHEADER= sms4.h
HEADER=	../../include/openssl/modes.h sms4_lcl.h $(EXHEADER)

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

sms4_cbc.o: ../../include/openssl/modes.h ../../include/openssl/sms4.h
sms4_cbc.o: sms4_cbc.c
sms4_cfb.o: ../../include/openssl/modes.h ../../include/openssl/sms4.h
sms4_cfb.o: sms4_cfb.c
sms4_common.o: sms4_common.c sms4_lcl.h
sms4_ctr.o: ../../include/openssl/modes.h ../../include/openssl/sms4.h
sms4_ctr.o: sms4_ctr.c
sms4_ecb.o: ../../include/openssl/modes.h ../../include/openssl/sms4.h
sms4_ecb.o: sms4_ecb.c
sms4_enc.o: sms4.h sms4_enc.c sms4_lcl.h
sms4_ofb.o: ../../include/openssl/modes.h ../../include/openssl/sms4.h
sms4_ofb.o: sms4_ofb.c
sms4_setkey.o: sms4.h sms4_lcl.h sms4_setkey.c
sms4_wrap.o: ../../e_os.h ../../include/openssl/bio.h
sms4_wrap.o: ../../include/openssl/buffer.h ../../include/openssl/crypto.h
sms4_wrap.o: ../../include/openssl/e_os2.h ../../include/openssl/err.h
sms4_wrap.o: ../../include/openssl/lhash.h ../../include/openssl/modes.h
sms4_wrap.o: ../../include/openssl/opensslconf.h
sms4_wrap.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
sms4_wrap.o: ../../include/openssl/safestack.h ../../include/openssl/sms4.h
sms4_wrap.o: ../../include/openssl/stack.h ../../include/openssl/symhacks.h
sms4_wrap.o: ../cryptlib.h sms4_wrap.c
