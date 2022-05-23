#!/bin/bash


KEY=11223344556677881122334455667788
IV=11223344556677881122334455667788

echo hello | gmssl zuc -key $KEY -iv $IV -out zuc.bin
gmssl zuc -key $KEY -iv $IV -in zuc.bin


