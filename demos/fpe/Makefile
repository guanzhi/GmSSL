all:
	gcc fpe-encrypt.c -L /usr/local/lib -lcrypto -o fpe-encrypt
	gcc fpe-decrypt.c -L /usr/local/lib -lcrypto -o fpe-decrypt

test:
	./fpe-encrypt 0123456789012345 secretkey tweak001
	./fpe-decrypt 6492610187935136 secretkey tweak001

clean:
	rm -fr a.out
	rm -fr fpe-encrypt
	rm -fr fpe-decrypt
