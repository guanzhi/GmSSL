all:
	gcc keygen.c -L /usr/local/lib -lcrypto -o keygen
	gcc keygen.c -DENCRYPT_KEY -DNO_PROMPT -L /usr/local/lib -lcrypto -o keygen-enc
	gcc keygen.c -DENCRYPT_KEY -L /usr/local/lib -lcrypto -o keygen-enc-prompt

test:
	./keygen
	./keygen-enc
	./keygen-enc-prompt

clean:
	rm -fr a.out
	rm -fr keygen
	rm -fr keygen-enc
	rm -fr keygen-enc-prompt
