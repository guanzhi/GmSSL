/* +build cgo */

package gmssl

/*
#cgo darwin CFLAGS: -I/usr/local/include
#cgo darwin LDFLAGS: -L/usr/local/lib -lcrypto
*/
import "C"
