#!/bin/bash -x
# Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.

gmssl=gmssl

$gmssl passwd -crypt -salt xx password
$gmssl passwd -1     -salt xxxxxxxx password
$gmssl passwd -apr1  -salt xxxxxxxx password
