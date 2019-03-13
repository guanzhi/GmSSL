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

#include "PluginObject.h"
#include <stdio.h>
#include <assert.h>


#define PLUGIN_NAME		"GmSSL Plugin"
#define PLUGIN_DESCRIPTION	"GmSSL NPAPI Plugin version 1.0"
#define PLUGIN_MIME		"application/x-gmssl::GmSSL NPAPI Plugin"

NPNetscapeFuncs* browser;


NPError NPP_New(NPMIMEType pluginType, NPP instance, uint16 mode, int16 argc,
	char* argn[], char* argv[], NPSavedData* saved)
{
	if (browser->version >= 14)
		instance->pdata = browser->createobject(instance, getPluginClass());
	return NPERR_NO_ERROR;
}

NPError NPP_Destroy(NPP instance, NPSavedData** save)
{
	return NPERR_NO_ERROR;
}

NPError NPP_SetWindow(NPP instance, NPWindow* window)
{
	return NPERR_NO_ERROR;
}

NPError NPP_NewStream(NPP instance, NPMIMEType type, NPStream* stream,
	NPBool seekable, uint16* stype)
{
	*stype = NP_ASFILEONLY;
	return NPERR_NO_ERROR;
}

NPError NPP_DestroyStream(NPP instance, NPStream* stream, NPReason reason)
{
	return NPERR_NO_ERROR;
}

int32 NPP_WriteReady(NPP instance, NPStream* stream)
{
	return 0;
}

int32 NPP_Write(NPP instance, NPStream* stream, int32 offset, int32 len,
	void* buffer)
{
	return 0;
}

void NPP_StreamAsFile(NPP instance, NPStream* stream, const char* fname)
{
}

void NPP_Print(NPP instance, NPPrint* platformPrint)
{
}

int16 NPP_HandleEvent(NPP instance, void* event)
{
	return 0;
}

void NPP_URLNotify(NPP instance, const char* url, NPReason reason,
	void* notifyData)
{
}

NPError NPP_GetValue(NPP instance, NPPVariable variable, void *value)
{
	switch (variable) {
	case NPPVpluginNameString:
		*((char **)value) = PLUGIN_NAME;
		return NPERR_NO_ERROR;

	case NPPVpluginDescriptionString:
		*((char **)value) = PLUGIN_DESCRIPTION;
		return NPERR_NO_ERROR;

	case NPPVpluginNeedsXEmbed:
		*((NPBool *)value) = TRUE;
		return NPERR_NO_ERROR;

	case NPPVpluginScriptableNPObject:
		assert(instance->pdata != NULL); /* this will not happen */
		browser->retainobject((NPObject*)instance->pdata);
		*((void **)value) = instance->pdata;
		return NPERR_NO_ERROR;

	default:
		fprintf(stderr, "HcryptPlugin: %s() unknown value `%x'\n",
			__FUNCTION__, variable);
		return NPERR_GENERIC_ERROR;
	}
	return NPERR_GENERIC_ERROR;
}

NPError NPP_SetValue(NPP instance, NPNVariable variable, void *value)
{
	return NPERR_GENERIC_ERROR;
}

NPError NP_GetValue(void* future, NPPVariable variable, void *value)
{
	return NPP_GetValue(future, variable, value);
}

NPError NP_GetEntryPoints(NPPluginFuncs* pluginFuncs)
{
	pluginFuncs->version		= 11;
	pluginFuncs->size		= sizeof(pluginFuncs);
	pluginFuncs->newp		= NPP_New;
	pluginFuncs->destroy		= NPP_Destroy;
	pluginFuncs->setwindow		= NPP_SetWindow;
	pluginFuncs->newstream		= NPP_NewStream;
	pluginFuncs->destroystream	= NPP_DestroyStream;
	pluginFuncs->asfile		= NPP_StreamAsFile;
	pluginFuncs->writeready		= NPP_WriteReady;
	pluginFuncs->write		= (NPP_WriteProcPtr)NPP_Write;
	pluginFuncs->print		= NPP_Print;
	pluginFuncs->event		= NPP_HandleEvent;
	pluginFuncs->urlnotify		= NPP_URLNotify;
	pluginFuncs->getvalue		= NPP_GetValue;
	pluginFuncs->setvalue		= NPP_SetValue;

	return NPERR_NO_ERROR;
}

NPError NP_Initialize(NPNetscapeFuncs* browserFuncs, NPPluginFuncs* pluginFuncs)
{
	browser = browserFuncs;
	NP_GetEntryPoints(pluginFuncs);
	return NPERR_NO_ERROR;
}

char *NP_GetMIMEDescription(void)
{
	return (char *)PLUGIN_MIME;
}

void NP_Shutdown(void)
{
}

#if 0
#pragma export on
NPError NP_Initialize(NPNetscapeFuncs* browserFuncs, NPPluginFuncs* pluginFuncs);
NPError NP_GetEntryPoints(NPPluginFuncs *pluginFuncs);
void NP_Shutdown(void);
#pragma export off
#endif
