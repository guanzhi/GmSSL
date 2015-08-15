#!/bin/bash

./Configure darwin64-x86_64-cc no-asm --prefix=/usr/local --openssldir=/usr/local/openssl
make
sudo make install
