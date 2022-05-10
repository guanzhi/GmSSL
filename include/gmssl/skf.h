/*
 * Copyright (c) 2014 - 2021 The GmSSL Project.  All rights reserved.
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

#ifndef GMSSL_SKF_H
#define GMSSL_SKF_H


#include <string.h>
#include <stdint.h>
#include <gmssl/sm2.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	void *handle;
	char manufacturer[65];
	char issuer[65];
	char label[33];
	char serial[33];
	uint8_t hardware_version[2];
	uint8_t firmware_version[2];
} SKF_DEVICE;

typedef struct {
	SM2_KEY public_key;
	void *app_handle;
	char app_name[65];
	void *container_handle;
	char container_name[65];
} SKF_KEY;

int skf_load_library(const char *so_path, const char *vendor);
void skf_unload_library(void);

int skf_list_devices(FILE *fp, int fmt, int ind, const char *label);
int skf_print_device_info(FILE *fp, int fmt, int ind, const char *devname);
int skf_open_device(SKF_DEVICE *dev, const char *devname, const uint8_t authkey[16]);
int skf_set_label(SKF_DEVICE *dev, const char *label);
int skf_change_authkey(SKF_DEVICE *dev, const uint8_t authkey[16]);
int skf_close_deivce(SKF_DEVICE *dev);;

int skf_list_apps(SKF_DEVICE *dev, int fmt, int ind, const char *label, FILE *fp);
int skf_create_app(SKF_DEVICE *dev, const char *appname, const char *admin_pin, const char *user_pin);
int skf_delete_app(SKF_DEVICE *dev, const char *appname);
int skf_change_app_admin_pin(SKF_DEVICE *dev, const char *appname, const char *oid_pin, const char *new_pin);
int skf_change_app_user_pin(SKF_DEVICE *dev, const char *appname, const char *oid_pin, const char *new_pin);
int skf_unblock_user_pin(SKF_DEVICE *dev, const char *appname, const char *admin_pin, const char *new_user_pin);

int skf_list_objects(FILE *fp, int fmt, int ind, const char *label, SKF_DEVICE *dev, const char *appname, const char *pin);
int skf_import_object(SKF_DEVICE *dev, const char *appname, const char *pin, const char *objname, const uint8_t *data, size_t datalen);
int skf_export_object(SKF_DEVICE *dev, const char *appname, const char *pin, const char *objname, uint8_t *out, size_t *outlen);
int skf_delete_object(SKF_DEVICE *dev, const char *appname, const char *pin, const char *objname);

int skf_list_containers(FILE *fp, int fmt, int ind, const char *label, SKF_DEVICE *dev, const char *appname, const char *pin);
int skf_create_container(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name);
int skf_delete_container(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name);
int skf_import_sign_cert(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name, const uint8_t *cert, size_t certlen);
int skf_export_sign_cert(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name, uint8_t *cert, size_t *certlen);

int skf_rand_bytes(SKF_DEVICE *dev, uint8_t *buf, size_t len);
int skf_load_sign_key(SKF_DEVICE *dev, const char *appname, const char *pin, const char *container_name, SKF_KEY *key);
int skf_sign(SKF_KEY *key, const uint8_t dgst[32], uint8_t *sig, size_t *siglen);
int skf_release_key(SKF_KEY *key);


#ifdef __cplusplus
}
#endif
#endif
