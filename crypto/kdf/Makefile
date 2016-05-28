#
# crypto/kdf/Makefile
#

DIR=	kdf
TOP=	../..
CC=	cc
INCLUDES= -I.. -I$(TOP) -I../../include
CFLAG=-g -Wall
MAKEFILE=	Makefile
AR=		ar r

CFLAGS= $(INCLUDES) $(CFLAG)

GENERAL=Makefile
TEST=kdftest.c
APPS=

LIB=$(TOP)/libcrypto.a
LIBSRC=	kdf_x9_63.c
LIBOBJ=	kdf_x9_63.o

SRC= $(LIBSRC)

EXHEADER= kdf.h
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

kdf_x9_63.o: ../../include/openssl/asn1.h ../../include/openssl/bio.h
kdf_x9_63.o: ../../include/openssl/crypto.h ../../include/openssl/e_os2.h
kdf_x9_63.o: ../../include/openssl/evp.h ../../include/openssl/obj_mac.h
kdf_x9_63.o: ../../include/openssl/objects.h
kdf_x9_63.o: ../../include/openssl/opensslconf.h
kdf_x9_63.o: ../../include/openssl/opensslv.h ../../include/openssl/ossl_typ.h
kdf_x9_63.o: ../../include/openssl/safestack.h ../../include/openssl/stack.h
kdf_x9_63.o: ../../include/openssl/symhacks.h kdf.h kdf_x9_63.c
