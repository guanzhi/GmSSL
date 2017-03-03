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

public class SOF {








	//public native long initCertAppPolicy(String PolicyName);


	public native boolean getCertTrustList(String ctlAltName, String ctlContent);
	public native String getCertTrustListAltNames();
	public native String getCertTrustList(String ctrlAltName);
	public native long delCertTrustList(String ctlAltName);
	public native String getInstance(String policyName);
	public native long setSignMethod(long SignMethod);
	public native long getSignMethod();
	public native long setEncryptMethod(long EncryptMethod);
	public native long getEncryptMethod();
	public native getServerCertificate();
	public native getServerCertificateByUsage(short certUsage);
	public native String genRandom(short randomLen);
	public native String getCertInfo(String base64EncodeCert, int type);
	public native String getCertInfoByOid(String base64EncodeCert, String oid);
	public native long validateCert(String base64EncodeCert);
	public native String signData(byte [] inData);
	public native boolean verifySignedData(String Base64EncodeCert, String InData, String SignValue);
	public native String signFile(String ContainerName, String InFile);
	public native boolean verifySignedFile(String Base64EncodeCert, String InFile, String SignValue);
	public native String encryptData(String Base64EncodeCert, String InData);
	public native String decryptData(String ContainerName, String InData);
	public native boolean encryptFile(String Base64EncodeCert, String InFile, String OutFile);
	public native boolean decryptFile(String ContainerName, String InFile, String OutFile);
	public native String signMessage(short flag, String ContainerName, String InData);
	public native boolean verifySignedMessage(String MessageData, String InData);
	public native String getInfoFromSignedMessage(String SignedMessage, short Type);
	public native boolean signMessageDetach();
	public native boolean verifySignedMessageDetach();
	public native String signDataXML(String ContainerName, String InData);
	public native boolean verifySignedDataXML(String InData);
	public native String getXMLSignatureInfo(String XMLSignedData, short Type);
	public native String createTimeStampRequest(String InData);
	public native String createTimeStampResponse(String TimeStampRequest);
	public native long verifyTimeStamp(String InData, String tsResponseData);
	public native String getTimeStampInfo(String tsResponseData, short type);
	public native long getLastError(void);

	public static void main(String[] args) {
		final GmSSL gmssl = new GmSSL();
		System.out.println(gmssl.getVersion(0));
		System.out.println("IV length = " + gmssl.getCipherIVLength("aes-128-cbc"));
	}

	static {
		System.loadLibrary("gmsof");
	}
}

