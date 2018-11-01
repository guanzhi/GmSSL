all:
	gcc sms4.c -L /usr/local/lib -lcrypto -o sms4
	gcc sms4.c -DUSE_RANDOM -L /usr/local/lib -lcrypto -o sms4rnd
	gcc sms4evp.c -DMSG_LEN=20 -L /usr/local/lib -lcrypto -o sms4evp

test:
	./sms4
	./sms4rnd
	./sms4evp

clean:
	rm -fr sms4
	rm -fr sms4rnd
	rm -fr sms4evp
