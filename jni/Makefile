# maybe a config is required to cross platform


all: libgmssl.jnilib

libgmssl.jnilib: GmSSL.h
	gcc -shared -fPIC -Wall -I./jni/ GmSSL.c ../libcrypto.a -o libgmssl.jnilib

GmSSL.h: GmSSL.class
	javah -jni GmSSL

GmSSL.class:
	javac GmSSL.java

clean:
	rm -f GmSSL.h
	rm -f *.class
	rm -f *.jnilib
	rm -f *.o
	rm -f a.out

test:
	java -Djava.library.path=. GmSSL

