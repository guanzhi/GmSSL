#!/bin/bash

PIN=123456
PUK=654321
P11LIB=/usr/local/lib/opensc-pkcs11.so

pkcs11-tool --list-token-slots --module $P11LIB
pkcs11-tool --list-objects		\
	--module $P11LIB		\
	--login --pin $PIN

