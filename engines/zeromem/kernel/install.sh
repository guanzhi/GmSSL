#!/bin/bash

sudo rmmod ecc
sudo insmod ecc.ko
dmesg|tail
