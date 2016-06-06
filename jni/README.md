## GmSSL Java Wrapper

Thi purpose of this module is to provide a simple Java API to access GmSSL
crypto library. To be simple, no key schedule or context is used. So the
functions will not be very efficient for processing large files or stream data.
And this module is not intend to be integrated with Java crypto frameworks such
as JCE.

The implementation is based on the Java Native Interface (JNI). The JNI header
files are also included, but you can replace them with version from you own
compiling environment.

