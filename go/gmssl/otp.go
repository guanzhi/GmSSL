/* +build cgo */
package gmssl

/*
#include <openssl/otp.h>
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

func GetOTPAlgors(aliases bool) []string {
	return []string{"sms4-cbc", "aes-128-cbc", "aes-256-cbc"}
}

func GenerateOTPKey() []byte {
}

func GenerateOneTimePassword() string {
}
