all:
	gcc sdf.c libsdf.so -o sdf
	gcc sdf.c -DUSE_GMAPI -L /usr/local/lib -lcrypto -o sdf-gmapi

test:
	./sdf-gmapi

clean:
	rm -fr sdf
	rm -fr sdf-gmaip
