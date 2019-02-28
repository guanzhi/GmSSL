/* ====================================================================
 * Copyright (c) 2016 - 2019 The GmSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/is_gmssl.h>
#include "GmSSLObject.h"

/*
 * interface gmssl {
 *	readonly attribute DOMString version;
 *	DOMString encrypt(in DOMString algor, in DOMString plaintext, in DOMString public_key);
 *	DOMString decrypt(in DOMString algor, in DOMString ciphertext, in DOMString private_key);
 * };
 */

const char *prog = "gmssl";
static bool identifiersInitialized = false;

#define GMSSL_VERSION			"1.0"

#define GMSSL_PROPERTY_VERSION		0
#define GMSSL_NUM_PROPERTIES		1

static NPIdentifier gmsslPropertyIdentifiers[GMSSL_NUM_PROPERTIES];
static const NPUTF8 *gmsslPropertyNames[GMSSL_NUM_PROPERTIES] = {
	"version",
};

#define GMSSL_METHOD_KEYGEN		0
#define GMSSL_METHOD_ENCRYPT		1
#define GMSSL_METHOD_DECRYPT		2
#define GMSSL_NUM_METHODS		3

static NPIdentifier gmsslMethodIdentifiers[GMSSL_NUM_METHODS];
static const NPUTF8 *gmsslMethodNames[GMSSL_NUM_METHODS] = {
	"keygen",
	"encrypt",
	"decrypt",
};

static bool do_keygen(const NPVariant algor, NPVariant *result);
static bool do_encrypt(const NPVariant algor, const NPVariant plaintext, const NPVariant pubkey, NPVariant *result);
static bool do_decrypt(const NPVariant algor, const NPVariant ciphertext, const NPVariant privkey, NPVariant *result);


static NPObject *gmsslAllocate(NPP npp, NPClass *theClass)
{
	GmSSLObject *newInstance = (GmSSLObject *)malloc(sizeof(GmSSLObject));

	if (!identifiersInitialized) {

		browser->getstringidentifiers(gmsslPropertyNames,
			GMSSL_NUM_PROPERTIES, gmsslPropertyIdentifiers);

		browser->getstringidentifiers(gmsslMethodNames,
			GMSSL_NUM_METHODS, gmsslMethodIdentifiers);

		identifiersInitialized = true;
	}

	return &newInstance->header;
}

static void gmsslDeallocate(NPObject *obj)
{
	free(obj);
}

static void gmsslInvalidate(NPObject *obj)
{
}

static bool gmsslHasMethod(NPObject *obj, NPIdentifier name)
{
	int i;
	fprintf(stderr, "HashMethod(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < GMSSL_NUM_METHODS; i++) {
		if (name == gmsslMethodIdentifiers[i])
			return true;
		else
			fprintf(stderr, "HashMethod(%s)\n", browser->utf8fromidentifier(name));
	}
	return false;
}

static bool gmsslInvoke(NPObject *obj, NPIdentifier name, const NPVariant *args,
	uint32_t argCount, NPVariant *variant)
{
	if (name == gmsslMethodIdentifiers[GMSSL_METHOD_KEYGEN]) {
		if (argCount != 1) {
			fprintf(stderr, "GmSSLObject: bad arguments\n");
			return false;
		}
		return do_keygen(args[0], variant);
	}

	if (name == gmsslMethodIdentifiers[GMSSL_METHOD_ENCRYPT]) {
		if (argCount != 3) {
			fprintf(stderr, "%s: bad arguments", "prog");
			return false;
		}
		return do_encrypt(args[0], args[1], args[2], variant);
	}

	if (name == gmsslMethodIdentifiers[GMSSL_METHOD_DECRYPT]) {
		if (argCount != 3) {
			fprintf(stderr, "%s: bad argument count\n", "prog");
			return false;
		}
		return do_decrypt(args[0], args[1], args[2], variant);
	}

	return false;
}

static bool gmsslInvokeDefault(NPObject *obj, const NPVariant *args,
	uint32_t argCount, NPVariant *result)
{
	return false;
}

static bool gmsslHasProperty(NPObject *obj, NPIdentifier name)
{
	int i;
	for (i = 0; i < GMSSL_NUM_PROPERTIES; i++)
		if (name == gmsslPropertyIdentifiers[i])
			return true;
	return false;
}

static bool gmsslGetProperty(NPObject *obj, NPIdentifier name, NPVariant *variant)
{
	//GmSSLObject *gmsslObject = (GmSSLObject *)obj;
	fprintf(stderr, "%s: cryptoGetProperty(%s)\n", prog, browser->utf8fromidentifier(name));
	if (name == gmsslPropertyIdentifiers[GMSSL_PROPERTY_VERSION]) {
		STRINGZ_TO_NPVARIANT(strdup(GMSSL_VERSION), *variant);
		return true;
	}
	return false;
}

static bool gmsslSetProperty(NPObject *obj, NPIdentifier name, 
	const NPVariant *variant)
{
	return false;
}

static NPClass gmsslClass = {
	NP_CLASS_STRUCT_VERSION,
	gmsslAllocate,
	gmsslDeallocate,
	gmsslInvalidate,
	gmsslHasMethod,
	gmsslInvoke,
	gmsslInvokeDefault,
	gmsslHasProperty,
	gmsslGetProperty,
	gmsslSetProperty,
};

NPClass *getGmSSLClass(void)
{
	return &gmsslClass;
}

static bool do_keygen(const NPVariant algor, NPVariant *result)
{
	bool ret = false;
	return ret;
}

static bool do_encrypt(const NPVariant algor, const NPVariant plaintext,
	const NPVariant pubkey, NPVariant *result)
{
	bool ret = false;
	return ret;
}

static bool do_decrypt(const NPVariant algor, const NPVariant ciphertext,
	const NPVariant privkey, NPVariant *result)
{
	bool ret = false;
	return ret;

}
