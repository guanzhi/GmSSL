all:
	#gcc skf.c libskf.so -o skf
	gcc skf.c -DUSE_GMAPI -lcrypto -o skf-gmapi

test:
	#./skf
	./skf-gmapi

clean:
	rm -fr skf
	rm -fr skf-gmapi
