#  Vendor's SKF Implementation

This folder can be used to hold vendors' SKF libraries (.so) and header files.
For testing the GmSSL SKF ENGINE, a dummy SKF implementation is also provided.
This dummy implementation will always success with `SAR_OK` returned.
If there is a `HANDLE` need to be initialized, it will be pointed to a new
alloced memory. The application need to call `SKF_CloseHandle` to free this
small piece memory. If a `ULONG` length need to be returned such as the
ciphertext size in the `SKF_Encrypt`, this value will be assigned a non-zero
integer value. Some of these values might be correct, but dont check them :)
Normally dummy will do nothing to the output buffer, so the result will be
incorrect, and will not check NULL pointers.

