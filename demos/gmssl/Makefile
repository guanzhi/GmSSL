
all:
	cc -o ciphers -Wall ciphers.c -L/usr/local/lib -lcrypto
	cc -o sm3 -Wall sm3.c -L/usr/local/lib -lcrypto
	cc -o evpsm3 -Wall evpsm3.c -L/usr/local/lib -lcrypto
	cc -o hmacsm3 -Wall hmacsm3.c -L/usr/local/lib -lcrypto

clean:
	rm -fr a.out *.o
	rm -fr ciphers
	rm -fr sm3
	rm -fr evpsm3
	rm -fr hmacsm3

