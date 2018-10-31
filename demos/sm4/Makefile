all:
	gcc sms4.c -L /usr/local/lib -lcrypto -o sms4
	gcc sms4.c -DUSE_RANDOM -L /usr/local/lib -lcrypto -o sms4rnd

test:
	./sms4
	./sms4rnd

clean:
	rm -fr sms4
	rm -fr sms4rnd
