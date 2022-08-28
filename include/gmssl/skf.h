/*
 *  Copyright 2014-2022 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */


#ifndef GMSSL_SKF_H
#define GMSSL_SKF_H


#include <string.h>
#include <stdint.h>
#include <gmssl/sm2.h>


#ifdef __cplusplus
extern "C" {
#endif


/*
SKF Public API

	skf_load_library
	skf_unload_library
	skf_list_devices
	skf_print_device_info

	SKF_DEVICE
	skf_open_device
	skf_close_deivce
	skf_set_label
	skf_change_authkey
	skf_list_apps
	skf_create_app
	skf_delete_app
	skf_change_app_admin_pin
	skf_change_app_user_pin
	skf_unblock_user_pin
	skf_list_objects
	skf_import_object
	skf_export_object
	skf_delete_object
	skf_list_containers
	skf_create_container
	skf_delete_container
	skf_import_sign_cert
	skf_export_sign_cert
	skf_rand_bytes
	skf_load_sign_key

	SKF_KEY
	skf_sign
	skf_release_key
*/

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
int skf_close_device(SKF_DEVICE *dev);

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
