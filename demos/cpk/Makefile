all:
	gcc cpk-setup.c -L/usr/local/lib -lcrypto -o cpk-setup
	gcc cpk-keygen.c -L/usr/local/lib -lcrypto -o cpk-keygen
	gcc cpk-sign.c -L/usr/local/lib -lcrypto -o cpk-sign
	gcc cpk-verify.c -L/usr/local/lib -lcrypto -o cpk-verify

test:
	./cpk-setup sign.mpk sign.msk
	./cpk-keygen sign.msk alice alice.ssk
	./cpk-sign cpk-setup alice alice.ssk cpk-setup-signed
	./cpk-verify cpk-setup-signed sign.mpk

clean:
	rm -fr cpk-setup
	rm -fr cpk-keygen
	rm -fr cpk-sign
	rm -fr cpk-verify
	rm -fr *.mpk
	rm -fr *.msk
	rm -fr *.sk
	rm -fr *.ssk
	rm -fr cpk-setup-signed

