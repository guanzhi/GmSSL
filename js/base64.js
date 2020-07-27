/*
 * Copyright (c) 2014 - 2020 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */


const BASE64_MAP = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

function base64_encode(bytes) {
	var i = 0; j = 0;
	var append = bytes.length % 3 > 0 ? 3 - bytes.length % 3 : 0;
	for (i = 0; i < append; i++) {
		bytes[bytes.length] = 0;
	}
	var b64 = "";
	for (i = 0; j < bytes.length; j += 3) {
		if (j > 0 && j % 57 == 0) {
			b64 += '\n';
		}
		b64 += BASE64_MAP[bytes[j] >> 2]
			+ BASE64_MAP[(bytes[j] & 3) << 4 | bytes[j+1] >> 4]
			+ BASE64_MAP[(bytes[j+1] & 15) << 2 | bytes[j+2] >> 6]
			+ BASE64_MAP[bytes[j+2] & 63];
	}
	for (i = 0; i < append; i++) {
		b64 += '=';
	}
	return b64;
}

function base64_decode(input) {
	var i = 0, j = 0;
	input = input.replace(/[^A-Za-z0-9\+\/\=]/g, "");
	var append = input.length % 4;
	if (append > 2) {
		return null;
	}
	for (i = 0; i < append; i++) {
		if (input.charAt(input.length - i - 1) != '=') {
			return null;
		}
	}
	var output = new Array((input.length - append) * 3 / 4);
	var enc1, enc2, enc3, enc4;
	for (i = 0, j = 0; j < output.length;) {
		enc1 = BASE64_MAP.indexOf(input.charAt(i++));
		enc2 = BASE64_MAP.indexOf(input.charAt(i++));
		enc3 = BASE64_MAP.indexOf(input.charAt(i++));
		enc4 = BASE64_MAP.indexOf(input.charAt(i++));
		output[j++] = (enc1 << 2) | (enc2 >> 4);
		output[j++] = ((enc2 & 15) << 4) | (enc3 >> 2);
		output[j++] = ((enc3 & 3) << 6) | enc4;
	}
	for (i = 0; i < append; i++) {
		if (output.pop() != 0) {
			return null;
		}
	}
	return output;
}

function base64_test() {
	var bin = [1, 2, 3, 4, 5];
	var b64 = base64_encode(bin);
	var buf = base64_decode(b64);
	console.log(b64);
	console.log(buf);
}
