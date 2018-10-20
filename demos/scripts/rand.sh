#!/bin/bash
# Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.

gmssl=gmssl
randfile=rand.bin

num=32
$gmssl rand -hex $num
$gmssl rand -base64 $num
$gmssl rand -out $randfile $num
