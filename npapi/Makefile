
.PHONY: all clean install

all:
	gcc -shared -Wall main.c PluginObject.c GmSSLObject.c -lcrypto -ldl -o libgmssl.so

clean:
	rm -f *.o
	rm -f *.so

install:
	cp libgmssl.so /usr/lib/mozilla/plugins/

