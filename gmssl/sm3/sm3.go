/*
 * Copyright 2020 The Hyperledger-TWGC Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

package sm3

import (
	"github.com/Hyperledger-TWGC/Gm-Go/gmssl"
	"hash"
)

type digest struct {
	ctx *gmssl.DigestContext
}

func New() hash.Hash {
	d := new(digest)
	ctx, err := gmssl.NewDigestContext("SM3")
	if err != nil {
		return nil
	}
	d.ctx = ctx
	return d
}

func (d *digest) BlockSize() int {
	ret, err := gmssl.GetDigestBlockSize("SM3")
	if err != nil {
		return 0
	}
	return ret
}

func (d *digest) Size() int {
	ret, err := gmssl.GetDigestLength("SM3")
	if err != nil {
		return 0
	}
	return ret
}

func (d *digest) Reset() {
	_ = d.ctx.Reset()
}

func (d *digest) Write(p []byte) (int, error) {
	err := d.ctx.Update(p)
	return len(p), err
}

func (d *digest) Sum(in []byte) []byte {
	d.ctx.Update(in)
	ret, err := d.ctx.Final()
	if err != nil {
		return nil
	}
	return ret
}
