/* ====================================================================
 * Copyright (c) 2015 - 2017 The GmSSL Project.  All rights reserved.
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
 * ====================================================================
 */

public class GmSSL {

	public native String getVersion(int type);
	public native byte [] generateRandom(int length);
	public native String [] getCiphers(boolean aliases);
	public native int getCipherIVLength(String cipher);
	public native int getCipherKeyLength(String cipher);
	public native int getCipherBlockSize(String cipher);
	public native byte [] symmetricEncrypt(String cipher, int flag, byte [] in, byte [] key, byte [] iv);
	public native byte [] symmetricDecrypt(String cipher, int flag, byte [] in, byte [] key, byte [] iv);
	public native String [] getDigests(boolean aliases);
	public native int getDigestLength(String digestAlgor);
	public native int getDigestBlockSize(String digestAlgor);
	public native byte [] digest(String algor, int flag, byte [] data);
	public native String [] getMacs(boolean aliases);
	public native String [] getMacLength(String algor);
	public native byte [] mac(String algor, int flag, byte [] data, byte [] key);
	public native String [] getSignAlgorithms(boolean aliases);
	public native byte [] sign(String algor, int flag, byte [] data, byte [] privateKey);
	public native int verify(String algor, int flag, byte [] digest, byte [] signature, byte [] publicKey);
	public native String [] getPublicKeyEncryptions(boolean aliases);
	public native byte [] publicKeyEncrypt(String algor, int flag, byte [] in, byte [] publicKey);
	public native byte [] privateKeyDecrypt(String algor, int falg, byte [] in, byte [] privateKey);
	public native String [] getDeriveKeyAlgorithms(boolean aliases);
	public native byte [] deriveKey(String algor, int flag, int keyLength, byte [] peerPublicKey, byte [] privateKey);
	public native String getErrorString();

	public static void main(String[] args) {
		final GmSSL gmssl = new GmSSL();
		System.out.println(gmssl.getVersion(0));
		System.out.println("IV length = " + gmssl.getCipherIVLength("aes-128-cbc"));
	}

	static {
		System.loadLibrary("gmssl");
	}
}

