all:
	gcc sm3.c -L /usr/local/lib -lcrypto -o sm3
	gcc sm3evp.c -L /usr/local/lib -lcrypto -o sm3evp
	gcc sm3hmac.c -L /usr/local/lib -lcrypto -o sm3hmac

test:
	echo "hello" | ./sm3
	echo "hello" | ./sm3evp
	echo "hello" | ./sm3hmac

clean:
	rm -fr sm3
	rm -fr sm3evp
	rm -fr sm3hmac
