#!/bin/bash

./Configure darwin64-x86_64-cc --prefix=/usr/local --openssldir=/usr/local/openssl
make
sudo make install



# build libp11
# $ ./bootstrap
# $ LIBP11_CFLAGS='-I/usr/local/include'; export LIBP11_CFLAGS 
# $ LIBP11_LIBS='-L/usr/local/lib -lp11'; export LIBP11_LIBS 
# $ ./configure

