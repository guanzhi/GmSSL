all:
	gcc sm9-setup.c ../../libcrypto.a -o sm9-setup
	gcc sm9-keygen.c ../../libcrypto.a -o sm9-keygen
	gcc sm9-sign.c ../../libcrypto.a -o sm9-sign
	gcc sm9-verify.c ../../libcrypto.a -o sm9-verify
	gcc sm9-encrypt.c ../../libcrypto.a -o sm9-encrypt
	gcc sm9-decrypt.c ../../libcrypto.a -o sm9-decrypt

test:
	echo "hello world" > hello.txt
	./sm9-setup sm9sign sm9sign.mpk sm9sign.msk
	./sm9-keygen sm9sign.msk alice alice.ssk
	./sm9-setup sm9encrypt sm9enc.mpk sm9enc.msk
	./sm9-keygen sm9enc.msk bob bob.esk
	./sm9-sign hello.txt alice.ssk hello.sig
	./sm9-verify hello.txt hello.sig sm9sign.mpk alice
	./sm9-encrypt hello.txt hello.sm9 sm9enc.mpk bob
	./sm9-decrypt hello.sm9 hello.dec bob.esk

clean:
	rm -fr sm9-setup
	rm -fr sm9-keygen
	rm -fr sm9-sign
	rm -fr sm9-verify
	rm -fr sm9-encrypt
	rm -fr sm9-decrypt
	rm -fr *.mpk
	rm -fr *.msk
	rm -fr *.ssk
	rm -fr *.esk
	rm -fr hello.*
