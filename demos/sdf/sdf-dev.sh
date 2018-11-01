#!/bin/bash -x


SO_PATH="./libsdf.so"

echo "[Commands]"
gmssl engine sdf -vvvv
echo "[Capabilities]"
gmssl engine sdf -c

echo "[Change Device Label and Auth key]"
gmssl engine sdf -pre SO_PATH:$SO_PATH -pre OPEN_DEV
#gmssl engine sdf -pre SO_PATH:$SO_PATH -pre OPEN_DEV -pre OPEN_CONTAINER:1

echo "[Import/Export File]"
gmssl engine sdf -pre SO_PATH:$SO_PATH -pre IMPORT_FILE:localhost-signcer.pem


