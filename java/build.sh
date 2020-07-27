cd /path/to/GmSSL/java
gcc -shared -fPIC -Wall -I./jni -I /path/to/gmssl/include -L /path/to/gmssl/lib GmSSL.c -lcrypto -o libgmssljni.so
java -Djava.library.path=/ GmSSL

