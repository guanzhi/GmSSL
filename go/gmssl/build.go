/* +build cgo */

package gmssl

/*
#cgo CFLAGS: -I../../include
#cgo LDFLAGS: -L../../ -lcrypto
*/
import "C"
