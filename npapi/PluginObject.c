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
#include "PluginObject.h"

static bool identifiersInitialized = false;

#define PLUGIN_PROPERTY_GMSSL			0
#define PLUGIN_NUM_PROPERTIES			1

static NPIdentifier pluginPropertyIdentifiers[PLUGIN_NUM_PROPERTIES];
static const NPUTF8 *pluginPropertyNames[PLUGIN_NUM_PROPERTIES] = {
	"gmssl",
};

#define PLUGIN_METHOD_GETTOKEN			0
#define PLUGIN_NUM_METHODS			1

static NPIdentifier pluginMethodIdentifiers[PLUGIN_NUM_METHODS];
static const NPUTF8 *pluginMethodNames[PLUGIN_NUM_METHODS] = {
	"getToken"
};

static void initializeIdentifiers(void)
{
	browser->getstringidentifiers(pluginPropertyNames,
		PLUGIN_NUM_PROPERTIES, pluginPropertyIdentifiers);
	browser->getstringidentifiers(pluginMethodNames,
		PLUGIN_NUM_METHODS, pluginMethodIdentifiers);
}

bool pluginHasProperty(NPObject *obj, NPIdentifier name)
{
	int i;
	//fprintf(stderr, "pluginHasProperty(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < PLUGIN_NUM_PROPERTIES; i++)
		if (name == pluginPropertyIdentifiers[i])
			return true;
	return false;
}

bool pluginHasMethod(NPObject *obj, NPIdentifier name)
{
	int i;
	//fprintf(stderr, "pluginHasMethod(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < PLUGIN_NUM_METHODS; i++)
		if (name == pluginMethodIdentifiers[i])
			return true;
	return false;
}

bool pluginGetProperty(NPObject *obj, NPIdentifier name, NPVariant *variant)
{
	PluginObject *plugin = (PluginObject *)obj;
	//fprintf(stderr, "pluginGetProperty(%s)\n", browser->utf8fromidentifier(name));

	if (name == pluginPropertyIdentifiers[PLUGIN_PROPERTY_GMSSL]) {
		//fprintf(stderr, "webvision: get GmSSLObject\n");
		NPObject *resultObj = &plugin->gmsslObject->header;
		browser->retainobject(resultObj);
		OBJECT_TO_NPVARIANT(resultObj, *variant);
		return true;
	}

	return false;
}

bool pluginSetProperty(NPObject *obj, NPIdentifier name, const NPVariant *variant)
{
	return false;
}

bool pluginInvoke(NPObject *obj, NPIdentifier name, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return false;
}

bool pluginInvokeDefault(NPObject *obj, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return false;
}

void pluginInvalidate(NPObject *obj)
{
	// Release any remaining references to JavaScript objects.
}

NPObject *pluginAllocate(NPP npp, NPClass *theClass)
{
	PluginObject *newInstance = malloc(sizeof(PluginObject));

	//fprintf(stderr, "pluginAllocate()\n");

	if (!identifiersInitialized) {
		identifiersInitialized = true;
		initializeIdentifiers();
	}
	newInstance->gmsslObject =
		(GmSSLObject *)browser->createobject(npp, getGmSSLClass());
	newInstance->npp = npp;

	return &newInstance->header;
}

void pluginDeallocate(NPObject *obj)
{
	free(obj);
}

static NPClass pluginClass = {
	NP_CLASS_STRUCT_VERSION,
	pluginAllocate,
	pluginDeallocate,
	pluginInvalidate,
	pluginHasMethod,
	pluginInvoke,
	pluginInvokeDefault,
	pluginHasProperty,
	pluginGetProperty,
	pluginSetProperty,
};

NPClass *getPluginClass(void)
{
	return &pluginClass;
}
