/* +build cgo */
package gosm2

/*

#cgo CFLAGS: -std=c99 -I../../include -g
#cgo LDFLAGS: -Llib -lcrypto -ldl -lpthread

*/
import "C"
