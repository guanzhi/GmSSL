/*
 * Copyright 2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

package gmssl

import (
	"hash"
)

type sm3 struct {
	ctx *DigestContext
}

func New() hash.Hash {
	d := new(sm3)
	ctx, err := NewDigestContext(SM3)
	if err != nil {
		return nil
	}
	d.ctx = ctx
	return d
}

func (d *sm3) BlockSize() int {
	ret, err := GetDigestBlockSize(SM3)
	if err != nil {
		return 0
	}
	return ret
}

func (d *sm3) Size() int {
	ret, err := GetDigestLength(SM3)
	if err != nil {
		return 0
	}
	return ret
}

func (d *sm3) Reset() {
	err := d.ctx.Reset()
	PanicError(err)
}

func (d *sm3) Write(p []byte) (int, error) {
	err := d.ctx.Update(p)
	return len(p), err
}

func (d *sm3) Sum(in []byte) []byte {
	err := d.ctx.Update(in)
	if err != nil {
		return nil
	}
	ret, err := d.ctx.Final()
	if err != nil {
		return nil
	}
	return ret
}
