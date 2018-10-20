#!/bin/bash
# Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.

gmssl=$gmssl

$gmssl speed sm2
$gmssl speed -evp sm3
$gmssl speed -evp sms4
$gmssl speed -evp sms4 -decrypt
$gmssl speed -evp sm3 -engine skf
