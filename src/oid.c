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


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <gmssl/oid.h>
#include <gmssl/asn1.h>
#include <gmssl/error.h>


/*
  asn1_type_from_octets 函数有三种返回值

 	* -1	说明编码的前缀错误，也就是不属于本类型的字节点
	*  0	即 OID_undef，说明前缀是匹配的，但是我们不识别这个 OID
	* >=1	一个被识别出来的 OID

  asn1_type_from_octets 函数不识别 type 的编码，如 asn1_sm_oid_from_octets 不识别 DER_sm
  但是返回值为 OID_undef，而不是 -1
*/

static uint8_t DER_sm[]			= { 0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01 };
static uint8_t DER_sm1[]		= { 0x66 };
static uint8_t DER_ssf33[]		= { 0x67 };
static uint8_t DER_sm4[]		= { 0x68 };
static uint8_t DER_zuc[]		= { 0x86, 0x20 };
static uint8_t DER_sm2[]		= { 0x82, 0x2D };
static uint8_t DER_sm2sign[]		= { 0x82, 0x2D, 0x01 };
static uint8_t DER_sm2keyagreement[]	= { 0x82, 0x2D, 0x02 };
static uint8_t DER_sm2encrypt[]		= { 0x82, 0x2D, 0x03 };
static uint8_t DER_sm9[]		= { 0x82, 0x2E };
static uint8_t DER_sm9sign[]		= { 0x82, 0x2E, 0x01 };
static uint8_t DER_sm9keyagreement[] 	= { 0x82, 0x2E, 0x02 };
static uint8_t DER_sm9encrypt[]		= { 0x82, 0x2E, 0x03 };
static uint8_t DER_sm3[]		= { 0x83, 0x11 };
static uint8_t DER_sm3_keyless[]	= { 0x83, 0x11, 0x01 };
static uint8_t DER_hmac_sm3[]		= { 0x83, 0x11, 0x02 };
static uint8_t DER_sm2sign_with_sm3[]	= { 0x83, 0x75 };
static uint8_t DER_rsasign_with_sm3[]	= { 0x83, 0x78 };

static const struct {
	uint8_t *der;
	size_t derlen;
	char *name;
	char *desc;
} sm_oids[] = {
	{ DER_sm1, 1, "sm1", "SM1" },
	{ DER_ssf33, 1, "ssf33", "SSF33" },
	{ DER_sm4, 1, "sm4", "SM4" },
	{ DER_zuc, 2, "zuc", "ZUC" },
	{ DER_sm2, 2, "sm2p256v1", "SM2" },
	{ DER_sm2sign, 3, "sm2sign", "SM2 Signature Scheme" },
	{ DER_sm2keyagreement, 3, "sm2keyagreement", "SM2 Key Agreement" },
	{ DER_sm2encrypt, 3, "sm2encrypt", "SM2 Encryption" },
	{ DER_sm9, 2,  "sm9", "SM9" },
	{ DER_sm9sign, 3, "sm9sign", "SM9 Signature Scheme" },
	{ DER_sm9keyagreement, 3, "sm9keyagreement", "SM9 Key Agreement" },
	{ DER_sm9encrypt, 3, "sm9encrypt", "SM9 Encrpytion" },
	{ DER_sm3, 2, "sm3", "SM3" },
	{ DER_sm3_keyless, 3, "sm3-keyless", "SM3 without Key" },
	{ DER_hmac_sm3, 3, "hmac-sm3", "HMAC-SM3" },
	{ DER_sm2sign_with_sm3, 2, "sm2sign-with-sm3", "SM2 Signature with SM3" },
	{ DER_rsasign_with_sm3, 2, "rsasign-with-sm3", "RSA Signature with SM3" },
};

const char *asn1_sm_oid_name(int oid)
{
	assert(OID_sm1 <= oid && oid <= OID_rsasign_with_sm3);
	return sm_oids[oid - OID_sm1].name;
}

const char *asn1_sm_oid_description(int oid)
{
	assert(oid >= OID_sm1 && oid <= OID_rsasign_with_sm3);
	return sm_oids[oid - OID_sm1].desc;
}

void asn1_sm_oid_to_octets(int oid, uint8_t *out, size_t *outlen)
{
	int i = oid - OID_sm1;
	assert(i >= 0 && i < sizeof(sm_oids)/sizeof(sm_oids[0]));
	if (out) {
		memcpy(out, DER_sm, sizeof(DER_sm));
		out += sizeof(DER_sm);
		memcpy(out, sm_oids[i].der, sm_oids[i].derlen);
		out += sm_oids[i].derlen;
	}
	*outlen = sizeof(DER_sm) + sm_oids[i].derlen;
}

int asn1_sm_oid_from_octets(const uint8_t *in, size_t inlen)
{
	int i;

	if (inlen < sizeof(DER_sm)
		|| memcmp(in, DER_sm, sizeof(DER_sm)) != 0) {
		return -1;
	}
	in += sizeof(DER_sm);
	inlen -= sizeof(DER_sm);

	for (i = 0; i < sizeof(sm_oids)/sizeof(sm_oids[0]); i++) {
		if (sm_oids[i].derlen == inlen
			&& memcmp(sm_oids[i].der, in, inlen) == 0) {
			return OID_sm1 + i;
		}
	}
	return OID_undef;
}

int asn1_sm_oid_from_name(const char *name)
{
	size_t i;
	for (i = 0; i < sizeof(sm_oids)/sizeof(sm_oids[0]); i++) {
		if (strcmp(name, sm_oids[i].name) == 0) {
			return OID_sm1 + i;
		}
	}
	return OID_undef;
}


// FIXME: 支持所有的公钥类型				
static const uint8_t DER_x9_62_ecPublicKey[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };


const char *asn1_pkey_oid_name(int oid)
{
	switch (oid) {
	case OID_x9_62_ecPublicKey: return "x9_62_ecPublicKey";
	}
	return NULL;
}

const char *asn1_pkey_oid_description(int oid)
{
	switch (oid) {
	case OID_x9_62_ecPublicKey: return "x9_62_ecPublicKey";
	}
	return NULL;
}

void asn1_pkey_oid_to_octets(int oid, uint8_t *out, size_t *outlen)
{
	assert(oid == OID_x9_62_ecPublicKey);
	if (out) {
		memcpy(out, DER_x9_62_ecPublicKey, sizeof(DER_x9_62_ecPublicKey));
	}
	*outlen = sizeof(DER_x9_62_ecPublicKey);
}

int asn1_pkey_oid_from_octets(const uint8_t *in, size_t inlen)
{
	if (inlen == sizeof(DER_x9_62_ecPublicKey)
		&& memcmp(DER_x9_62_ecPublicKey, in, inlen) == 0) {
		return OID_x9_62_ecPublicKey;
	}
	return 0;
}

int asn1_pkey_oid_from_name(const char *name)
{
	if (strcmp(name, "x9_62_ecPublicKey") == 0) {
		return OID_x9_62_ecPublicKey;
	}
	return 0;
}


// 本组函数不支持 OID_x9_62_ecPublicKey 的 DER 编解码
// 这个类型应该归为公钥类型，还包括RSA、DSA、DH等公钥类型
// 这个错误， 03 01 是 curves prime ,而不是x9_62_ecPublicKey
// x9_62_ecPublicKey 是 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
static const uint8_t DER_x9_62_curve_prime[] = { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01 };

static const struct {
	uint8_t der;
	char *name;
} x9_62_curve_oids[] = {
	{ 1, "prime192v1" },
	{ 2, "prime192v2" },
	{ 3, "prime192v3" },
	{ 4, "prime239v1" },
	{ 5, "prime239v2" },
	{ 6, "prime239v3" },
	{ 7, "prime256v1" },
};

const char *asn1_x9_62_curve_oid_name(int oid)
{
	assert(OID_prime192v1 <= oid && oid <= OID_prime256v1);
	return x9_62_curve_oids[oid - OID_prime192v1].name;
}

const char *asn1_x9_62_curve_oid_description(int oid)
{
	return asn1_x9_62_curve_oid_name(oid);
}

void asn1_x9_62_curve_oid_to_octets(int oid, uint8_t *out, size_t *outlen)
{
	assert(OID_prime192v1 <= oid && oid <= OID_prime256v1);
	if (out) {
		memcpy(out, DER_x9_62_curve_prime, sizeof(DER_x9_62_curve_prime));
		out += sizeof(DER_x9_62_curve_prime);
		*out = x9_62_curve_oids[oid - OID_prime192v1].der;
	}
	(*outlen) = sizeof(DER_x9_62_curve_prime) + 1;
}

int asn1_x9_62_curve_oid_from_octets(const uint8_t *in, size_t inlen)
{
	if (inlen < sizeof(DER_x9_62_curve_prime)
		|| memcmp(in, DER_x9_62_curve_prime, sizeof(DER_x9_62_curve_prime)) != 0) {
		return -1;
	}
	in += sizeof(DER_x9_62_curve_prime);
	inlen -= sizeof(DER_x9_62_curve_prime);
	if (inlen == 1 && *in >= 1 && *in <= 7) {
		return OID_prime192v1 + *in - 1;
	}
	return OID_undef;
}

int asn1_x9_62_curve_oid_from_name(const char *name)
{
	int i;
	for (i = 0; i < sizeof(x9_62_curve_oids)/sizeof(x9_62_curve_oids[0]); i++) {
		if (strcmp(name, x9_62_curve_oids[i].name) == 0) {
			return OID_prime192v1 + i;
		}
	}
	return OID_undef;
}




static const uint8_t DER_secg_curve[] = { 0x2B, 0x81, 0x04, 0x00 };

static const struct {
	uint8_t der;
	int oid;
	char *name;
} secg_curve_oids[] = {
	{ 10, OID_secp256k1, "secp256k1" },
	{ 31, OID_secp192k1, "secp192k1" },
	{ 32, OID_secp224k1, "secp224k1" },
	{ 33, OID_secp224r1, "secp224r1" },
	{ 34, OID_secp384r1, "secp384r1" },
	{ 35, OID_secp521r1, "secp521r1" },
};

const char *asn1_secg_curve_oid_name(int oid)
{
	int i = oid - OID_secp256k1;

	if (i < 0 || i >= sizeof(secg_curve_oids)/sizeof(secg_curve_oids[0])) {
		fprintf(stderr, "%s %d: i = %d\n", __FILE__, __LINE__, i);
	}


	assert(i >= 0 && i < sizeof(secg_curve_oids)/sizeof(secg_curve_oids[0]));
	return secg_curve_oids[i].name;
}

const char *asn1_secg_curve_oid_description(int oid)
{
	return asn1_secg_curve_oid_name(oid);
}

void asn1_secg_curve_oid_to_octets(int oid, uint8_t *out, size_t *outlen)
{
	int i = oid - OID_secp256k1;
	if (out) {
		memcpy(out, DER_secg_curve, sizeof(DER_secg_curve));
		out += sizeof(DER_secg_curve);
		*out++ = secg_curve_oids[i].der;
	}
	*outlen = sizeof(DER_secg_curve) + 1;
}

int asn1_secg_curve_oid_from_octets(const uint8_t *in, size_t inlen)
{
	if (inlen < sizeof(DER_secg_curve)
		|| memcmp(in, DER_secg_curve, sizeof(DER_secg_curve)) != 0) {
		return -1;
	}
	in += sizeof(DER_secg_curve);
	inlen -= sizeof(DER_secg_curve);

	if (inlen == 1) {
		int i;
		for (i = 0; i < sizeof(secg_curve_oids)/sizeof(secg_curve_oids[0]); i++) {
			if (*in == secg_curve_oids[i].der) {
				return secg_curve_oids[i].oid;
			}
		}
	}
	return OID_undef;
}

int asn1_secg_curve_oid_from_name(const char *name)
{
	uint32_t a;
	if (strlen(name) != sizeof("secp256k1")-1
		|| *(uint32_t *)name != *(uint32_t *)"secp"
		|| name[8] != '1') {
		return OID_undef;
	}
	a = *(uint32_t *)(name + 4);
	if (a == *(uint32_t *)"256k") return OID_secp256k1;
	else if (a == *(uint32_t *)"192k") return OID_secp192k1;
	else if (a == *(uint32_t *)"224k") return OID_secp224k1;
	else if (a == *(uint32_t *)"224r") return OID_secp224r1;
	else if (a == *(uint32_t *)"384r") return OID_secp384r1;
	else if (a == *(uint32_t *)"521r") return OID_secp521r1;
	else return OID_undef;
}





static const uint8_t DER_x509[] = { 0x55, 0x04 };

static const struct {
	uint8_t der;
	char *name;
	char *desc;
} x509_oids[] = {
	{  3, "commonName", "Common Name" },
	{  4, "surname", "Surname" },
	{  5, "serialNumber", "Serial Number" },
	{  6, "countryName", "Country" },
	{  7, "localityName", "Locality" },
	{  8, "stateOrProvinceName", "State or Province" },
	{  9, "streetAddress", "Street Address" },
	{ 10, "organizationName", "Organization" },
	{ 11, "organizationalUnitName", "Organizational Unit" },
	{ 12, "title", "Title" },
	{ 13, "description", "Description" },
	{ 14, "searchGuide", "Search Guide" },
	{ 15, "businessCategory", "Business Category" },
	{ 16, "postalAddress", "Postal Address" },
	{ 17, "postalCode", "Postal Code" },
	{ 18, "postOfficeBox", "Post Office Box" },
	{ 19, "physicalDeliveryOfficeName", "Physical Delivery Office" },
	{ 20, "telephoneNumber", "Telephone Number" },
	{ 21, "telexNumber", "Telex Number" },
	{ 22, "teletexTerminalIdentifier", "Teletex Terminal Identifier" },
	{ 23, "facsimileTelephoneNumber", "Facsimile Telephone Number" },
	{ 24, "x121Address", "X121 Address" },
	{ 25, "internationaliSDNNumber", "InternationaliSDN Number" },
	{ 26, "registeredAddress", "Registered Address" },
	{ 27, "destinationIndicator", "Destination Indicator" },
	{ 28, "preferredDeliveryMethod", "Preferred Delivery Method" },
	{ 29, "presentationAddress", "Presentation Address" },
	{ 30, "supportedApplicationContext", "Supported ApplicationContext" },
	{ 31, "member", "Member" },
	{ 32, "owner", "Owner" },
	{ 33, "roleOccupant", "Role Occupant" },
	{ 34, "seeAlso", "See Also" },
	{ 35, "userPassword", "User Password" },
	{ 36, "userCertificate", "User Certificate" },
	{ 37, "caCertificate", "CA Certificate" },
	{ 38, "authorityRevocationList", "Authority Revocation List" },
	{ 39, "certificateRevocationList", "Certificate Revocation List" },
	{ 40, "crossCertificatePair", "Cros sCertificate Pair" },
	{ 41, "name", "Name" },
	{ 42, "givenName", "Given Name" },
	{ 43, "initials", "Initials" },
	{ 44, "generationQualifier", "Generation Qualifier" },
	{ 45, "x500UniqueIdentifier", "X500Unique Identifier" },
	{ 46, "dnQualifier", "DN Qualifier" },
	{ 47, "enhancedSearchGuide", "Enhanced Search Guide" },
	{ 48, "protocolInformation", "Protocol Information" },
	{ 49, "distinguishedName", "Distinguished Name" },
	{ 50, "uniqueMember", "Unique Member" },
	{ 51, "houseIdentifier", "House Identifier" },
	{ 52, "supportedAlgorithms", "Supported Algorithms" },
	{ 53, "deltaRevocationList", "Delta Revocation List" },
	{ 55, "dmdName", "DMD Name" },
	{ 65, "pseudonym", "Pseudonym" },
	{ 72, "role", "Role" },
};

const char *asn1_x509_oid_name(int oid)
{
	int i = oid - OID_at_commonName;

	assert(OID_at_role - OID_at_commonName + 1 == sizeof(x509_oids)/sizeof(x509_oids[0]));

	if (i < 0 || i >= sizeof(x509_oids)/sizeof(x509_oids[0])) {
		fprintf(stderr, "%s %d: oid = %d, i = %d\n", __FILE__, __LINE__, oid, i);
	}


	assert(i >= 0 && i < sizeof(x509_oids)/sizeof(x509_oids[0]));
	return x509_oids[i].name;
}

const char *asn1_x509_oid_description(int oid)
{
	int i = oid - OID_at_commonName;
	assert(i >= 0 && i < sizeof(x509_oids)/sizeof(x509_oids[0]));
	return x509_oids[i].desc;
}

void asn1_x509_oid_to_octets(int oid, uint8_t *out, size_t *outlen)
{
	int i = oid - OID_at_commonName;
	if (i < 0 || i >= sizeof(x509_oids)/sizeof(x509_oids[0])) {
		fprintf(stderr, "%s %d: oid = %d, i = %d\n", __FILE__, __LINE__, oid, i);
	}
	assert(i >= 0 && i < sizeof(x509_oids)/sizeof(x509_oids[0]));


	if (out) {
		memcpy(out, DER_x509, sizeof(DER_x509));
		out += sizeof(DER_x509);
		*out = x509_oids[i].der;
	}
	*outlen = sizeof(DER_x509) + 1;


}

int asn1_x509_oid_from_octets(const uint8_t *in, size_t inlen)
{
	if (inlen < sizeof(DER_x509)
		|| memcmp(in, DER_x509, sizeof(DER_x509)) != 0) {
		return -1;
	}
	in += sizeof(DER_x509);
	inlen -= sizeof(DER_x509);

	if (inlen == 1) {
		if (*in >= 3 && *in <= 53)
			return OID_at_commonName + *in - 3;
		else if (*in == 55)
			return OID_at_dmdName;
		else if (*in == 65)
			return OID_at_pseudonym;
		else if (*in == 72)
			return OID_at_role;
	}
	return OID_undef;
}

int asn1_x509_oid_from_name(const char *name)
{
	int i;
	for (i = 0; i < sizeof(x509_oids)/sizeof(x509_oids[0]); i++) {
		if (strcmp(name, x509_oids[i].name) == 0) {
			return OID_at_commonName + i;
		}
	}
	return OID_undef;
}


// OIDs for X.509 extension ExtKeyUsage
// kp means "key purpose"
static const uint8_t DER_x509_kp[] = { 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, };

static const struct {
	uint8_t der;
	char *name;
	char *desc;
} x509_kp_oids[] = {
	{ 1, "serverAuth", "TLS WWW server authentication" },
	{ 2, "clientAuth", "TLS WWW client authentication" },
	{ 3, "codeSigning", "Signing of downloadable executable code" },
	{ 4, "emailProtection", "Email protection" },
	{ 8, "timeStamping", "Binding the hash of an object to a time" },
	{ 9, "OCSPSigning", "Signing OCSP responses" },
};

const char *asn1_x509_kp_oid_name(int oid)
{
	int i = oid - OID_kp_serverAuth;
	assert(i >= 0 && i < sizeof(x509_kp_oids)/sizeof(x509_kp_oids[0]));
	return x509_kp_oids[i].name;
}

const char *asn1_x509_kp_oid_description(int oid)
{
	int i = oid - OID_kp_serverAuth;
	assert(i >= 0 && i < sizeof(x509_kp_oids)/sizeof(x509_kp_oids[0]));
	return x509_kp_oids[i].desc;
}

void asn1_x509_kp_oid_to_octets(int oid, uint8_t *out, size_t *outlen)
{
	int i = oid - OID_kp_serverAuth;
	assert(i >= 0 && i < sizeof(x509_kp_oids)/sizeof(x509_kp_oids[0]));
	if (out) {
		memcpy(out, DER_x509_kp, sizeof(DER_x509_kp));
		out += sizeof(DER_x509_kp);
		*out = x509_kp_oids[i].der;
	}
	*outlen = sizeof(DER_x509_kp) + 1;
}

int asn1_x509_kp_oid_from_octets(const uint8_t *in, size_t inlen)
{
	if (inlen < sizeof(DER_x509_kp)
		|| memcmp(in, DER_x509_kp, sizeof(DER_x509_kp)) != 0) {
		return -1;
	}
	in += sizeof(DER_x509_kp);
	inlen -= sizeof(DER_x509_kp);

	if (inlen == 1) {
		if (*in >= 1 && *in <= 4)
			return OID_kp_serverAuth + *in - 1;
		else if (*in == 8)
			return OID_kp_timeStamping;
		else if (*in == 9)
			return OID_kp_OCSPSigning;
	}
	return OID_undef;
}

int asn1_x509_kp_oid_from_name(const char *name)
{
	int i;
	for (i = 0; i < sizeof(x509_kp_oids)/sizeof(x509_kp_oids[0]); i++) {
		if (strcmp(name, x509_kp_oids[i].name) == 0) {
			return OID_kp_serverAuth + i;
		}
	}
	return OID_undef;
}

void asn1_oid_to_octets(int oid, uint8_t *out, size_t *outlen)
{
	if (oid <= OID_rsasign_with_sm3) {
		asn1_sm_oid_to_octets(oid, out, outlen);
	} else if (oid == OID_x9_62_ecPublicKey) {
		if (out) // 注意：这里必须验证 out == NULL ?
			memcpy(out, DER_x9_62_ecPublicKey, sizeof(DER_x9_62_ecPublicKey));
		*outlen = sizeof(DER_x9_62_ecPublicKey);
	} else if (oid <= OID_prime256v1) {
		asn1_x9_62_curve_oid_to_octets(oid, out, outlen);
	} else if (oid <= OID_secp521r1) {
		asn1_secg_curve_oid_to_octets(oid, out, outlen);
	} else if (oid <= OID_at_role) {
		asn1_x509_oid_to_octets(oid, out, outlen);
	} else {
		error_print();
		assert(0);
	}
}

// asn1_oid_from_octets 不返回错误值，只返回 OID_undef
// 但是数据编码仍可能是非法的
// 如果返回 OID_undef，需要通过 asn1_oid_nodes_from_octets 判断格式是否正确
int asn1_oid_from_octets(const uint8_t *in, size_t inlen)
{
	int ret = OID_undef;
	if (inlen == sizeof(DER_x9_62_ecPublicKey)
		&& memcmp(DER_x9_62_ecPublicKey, in, inlen) == 0) {
		return OID_x9_62_ecPublicKey;
	}

	if (inlen >= sizeof(DER_x9_62_ecPublicKey)
		&& memcmp(in, DER_x9_62_ecPublicKey, sizeof(DER_x9_62_ecPublicKey)) == 0) {
		if (inlen == sizeof(DER_x9_62_ecPublicKey))
			ret = OID_x9_62_ecPublicKey;
		else	ret = asn1_x9_62_curve_oid_from_octets(in, inlen);
	} else if (inlen > sizeof(DER_sm)
		&& memcmp(in, DER_sm, sizeof(DER_sm)) == 0) {
		ret = asn1_sm_oid_from_octets(in, inlen);
	} else if (inlen > sizeof(DER_secg_curve)
		&& memcmp(in, DER_secg_curve, sizeof(DER_secg_curve)) == 0) {
		ret = asn1_secg_curve_oid_from_octets(in, inlen);
	} else if (inlen > sizeof(DER_x509)
		&& memcmp(in, DER_x509, sizeof(DER_x509)) == 0) {
		ret = asn1_x509_oid_from_octets(in, inlen);
	} else {
		/*
		int i;
		error_print("unknown der\n");
		print_der(in, inlen);
		printf("\n");
		*/
		return OID_undef;
	}

	if (ret < 0) {
		error_print();
	}
	return ret;
}

// 输出长度不固定，并且被多次重复调用，因此提供 **out 形式的参数
static void uint_to_base128(uint32_t a, uint8_t **out, size_t *outlen)
{
	uint8_t buf[5];
	int n = 0;

	buf[n++] = a & 0x7f;
	a >>= 7;

	while (a) {
		buf[n++] = 0x80 | (a & 0x7f);
		a >>= 7;
	}

	while (n--) {
		if (out)
			*(*out)++ = buf[n];
		(*outlen)++;
	}
}

// 实际上我们在解析的时候是不知道具体在哪里结束的
// 解析是有可能出错的，如果没有发现最后一个0开头的字节就出错了
// 还有值太大也会出错，我们最多读取5个字节
// { 0x81, 0x82 }
// { 0x81, 0x82, 0x83, 0x84, 0x85, 0x06 }
static int uint_from_base128(uint32_t *a, const uint8_t **in, size_t *inlen)
{
	uint8_t buf[5];
	int n = 0;
	int i;

	for (;;) {
		if ((*inlen)-- < 1 || n >= 5) {
			return -1;
		}
		buf[n] = *(*in)++;
		if ((buf[n++] & 0x80) == 0) {
			break;
		}
	}

	// 32 - 7*4 = 4, so the first byte should be like 1000bbbb
	if (n == 5 && (buf[0] & 0x70)) {
		return -1;
	}

	*a = 0;
	for (i = 0; i < n; i++) {
		*a = ((*a) << 7) | (buf[i] & 0x7f);
	}

	return 1;
}

int asn1_oid_nodes_to_octets(const uint32_t *nodes, size_t nodes_count, uint8_t *out, size_t *outlen)
{
	if (nodes_count < 2 || nodes_count > 32) {
		return -1;
	}
	if (out)
		*out++ = (uint8_t)(nodes[0] * 40 + nodes[1]);
	(*outlen) = 1;
	nodes += 2;
	nodes_count -= 2;

	while (nodes_count--) {
		uint_to_base128(*nodes++, &out, outlen);
	}
	return 1;
}

// 因为这个函数总是被asn1函数调用的，因此给的输入数据长度是已知的
int asn1_oid_nodes_from_octets(uint32_t *nodes, size_t *nodes_count, const uint8_t *in, size_t inlen)
{
	size_t count = 0;
	const uint8_t *p = in;
	size_t len = inlen;

	if (!nodes || !nodes_count || !in || inlen <= 0) {
		error_print();
		return -1;
	}

	if (inlen < 1) {
		error_print();
		return -1;
	}

	// FIXME: 需要支持 nodes = NULL 吗？
	if (nodes) {
		*nodes++ = (*in) / 40;
		*nodes++ = (*in) % 40;
	}
	in++;
	inlen--;
	count += 2;

	while (inlen) {
		uint32_t val;
		if (count > 32) {
			return -1;
		}
		if (uint_from_base128(&val, &in, &inlen) < 0) {
			return -1;
		}
		if (nodes) {
			*nodes++ = val;
		}
		count++;
	}

	*nodes_count = count;
	return 1;
}

// 调用方应提供一个已知的 OID 名字，否则函数会返回错误，而非返回 OID_undef
int asn1_object_identifier_from_name(int *oid,  const char *name)
{
	if (!oid || !name) {
		return -1;
	}

	if ((*oid = asn1_sm_oid_from_name(name)) != OID_undef)
		return 1;
	if ((*oid = asn1_x9_62_curve_oid_from_name(name)) != OID_undef)
		return 1;
	if ((*oid = asn1_secg_curve_oid_from_name(name)) != OID_undef)
		return 1;
	if ((*oid = asn1_x509_oid_from_name(name)) != OID_undef)
		return 1;

	return 1;
}

const char *asn1_object_identifier_name(int oid)
{
	if (oid < 0) {
		return NULL;
	} else if (oid == OID_undef) {
		return "undef";
	} else if (oid <= OID_rsasign_with_sm3) {
		return asn1_sm_oid_name(oid);
	} else if (oid <= OID_x9_62_ecPublicKey) { // FIXME: 目前单独处理，后续应增加公钥类型 OID 集合
		return "x9_62_ecPublicKey";
	} else if (oid <= OID_prime256v1) {
		return asn1_x9_62_curve_oid_name(oid);
	} else if (oid <= OID_secp521r1) {
		return asn1_secg_curve_oid_name(oid);
	} else if (oid <= OID_at_role) {
		return asn1_x509_oid_name(oid);
	} else {
		// FIXME: 还有后续的一些X.509 OID没有支持
		return NULL;
	}
}

const char *asn1_object_identifier_description(int oid)
{
	if (oid < 0) {
		return NULL;
	} else if (oid == OID_undef) {
		return "<undef>";
	} else if (oid <= OID_rsasign_with_sm3) {
		return asn1_sm_oid_description(oid);
	} else if (oid <= OID_x9_62_ecPublicKey) { // FIXME: 目前单独处理，后续应增加公钥类型 OID 集合
		return "x9_62_ecPublicKey";
	} else if (oid <= OID_prime256v1) {
		return asn1_x9_62_curve_oid_description(oid);
	} else if (oid <= OID_secp521r1) {
		return asn1_secg_curve_oid_description(oid);
	} else if (oid <= OID_at_role) {
		return asn1_x509_oid_description(oid);
	}
	// FIXME: 还有后续的一些X.509 OID没有支持
	return NULL;
}


// FIXME: 这个测试函数都应该挪到测试目录中去
							


// 测试 oid_nodes 编解码是否正确
// FIXME: 还应该增加一些外部的测试用例
int test_asn1_oid_nodes(void)
{
	int oid;
	uint8_t octets[64];
	uint8_t buf[64];
	uint32_t nodes[32];
	size_t octetslen, buflen, nodes_count;

	for (oid = 1; oid <= OID_at_role; oid++) {
		int i;
		asn1_oid_to_octets(oid, octets, &octetslen);
		asn1_oid_nodes_from_octets(nodes, &nodes_count, octets, octetslen);
		asn1_oid_nodes_to_octets(nodes, nodes_count, buf, &buflen);
		if (buflen != octetslen || memcmp(octets, buf, buflen) != 0) {
			fprintf(stderr, "%s %d: oid = %d error\n", __FILE__, __LINE__, oid);
		}

		printf("%d : ", oid);
		for (i = 0; i < nodes_count; i++) {
			printf("%d ", (int)nodes[i]);
		}
		printf("\n");
	}

	return 1;
}

int test_asn1_oid(void)
{
	uint8_t buf[1024];
	uint8_t *p = buf;
	size_t len =0;
	int oid;
	int i;

	uint32_t nodes[32];
	size_t nodes_count;

	test_asn1_oid_nodes();

	for (i = 1; i <= OID_at_role; i++) {
		int j;
		asn1_oid_to_octets(i, buf, &len);
		oid = asn1_oid_from_octets(buf, len);
		printf("%d %s %s ", oid, asn1_object_identifier_name(oid), asn1_object_identifier_description(oid));

		asn1_oid_nodes_from_octets(nodes, &nodes_count, buf, len);
		for (j = 0; j < nodes_count; j++) {
			printf("%d.", nodes[j]);
		}
		printf("\n");
	}

	return 1;
}

int test_asn1_object_identifier_to_der(int oid)
{
	uint8_t buf[64] = {0};
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0, i;
	uint32_t nodes[32] = {0};
	size_t nodes_count;
	int roid;

	if (asn1_object_identifier_to_der(oid, NULL, 0, &p, &len) != 1) {
		error_print();
		return 0;
	}
	printf("%d : %s : ", oid, asn1_object_identifier_name(oid));
	print_der(buf, len);


	if (asn1_object_identifier_from_der(&roid, nodes, &nodes_count, &cp, &len) != 1) {
		error_print();
		return 0;
	}
	printf(" : ");
	print_nodes(nodes, nodes_count);
	printf("\n");

	if (roid != oid) {
		error_print();
		return -1;
	}
	if (len != 0) {
		error_print();
		return -1;
	}
	return 1;
}

int test_asn1_object_identifier(void)
{
	uint8_t buf[2048];
	const uint8_t *cp = buf;
	uint8_t *p = buf;
	size_t len = 0;
	uint32_t nodes[32] = {0};
	size_t nodes_count;
	int oid;
	int i;

	// 分别测试每个oid分别编解码是否正确
	for (oid = 1; oid <= OID_at_role; oid++) {
		if (test_asn1_object_identifier_to_der(oid) < 0) {
			error_print();
			return -1;
		}
	}

	// 将全部oid编码后再解码
	for (oid = 1; oid <= OID_at_role; oid++) {
		if (asn1_object_identifier_to_der(oid, NULL, 0, &p, &len) != 1) {
			error_print();
			return -1;
		}
	}
	printf("%s %d: All OIDs encoded length = %zu bytes\n", __FILE__, __LINE__, len);
	print_der(buf, len);
	printf("\n");

	while (len) {
		int ret;
		if (asn1_object_identifier_from_der(&oid, nodes, &nodes_count, &cp, &len) <= 0) {
			break;
		}
		printf("%d %s\n", oid, asn1_object_identifier_name(oid));
	}
	return 1;
}
