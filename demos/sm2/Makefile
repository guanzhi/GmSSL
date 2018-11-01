all:
	gcc sm2-keygen.c -L /usr/local/lib -lcrypto -o sm2-keygen
	gcc sm2-keygen.c -DENCRYPT_KEY -DNO_PROMPT -L /usr/local/lib -lcrypto -o sm2-keygen-enc
	gcc sm2-keygen.c -DENCRYPT_KEY -L /usr/local/lib -lcrypto -o sm2-keygen-enc-prompt
	gcc sm2-sign.c -L /usr/local/lib -lcrypto -o sm2-sign
	gcc sm2-encrypt.c -L /usr/local/lib -lcrypto -o sm2-encrypt

test:
	./sm2-keygen
	echo
	./sm2-keygen-enc
	echo
	#./sm2-keygen-enc-prompt
	./sm2-sign
	echo
	./sm2-encrypt
	echo

clean:
	rm -fr a.out
	rm -fr sm2-keygen
	rm -fr sm2-keygen-enc
	rm -fr sm2-keygen-enc-prompt
	rm -fr sm2-sign
	rm -fr sm2-encrypt
