#!/bin/bash


KEY=11223344556677881122334455667788
IV=11223344556677881122334455667788

echo hello | gmssl sm4 -cbc -encrypt -key $KEY -iv $IV -out sm4.cbc
gmssl sm4 -cbc -decrypt -key $KEY -iv $IV -in sm4.cbc

echo hello | gmssl sm4 -ctr -encrypt -key $KEY -iv $IV -out sm4.ctr
gmssl sm4 -ctr -decrypt -key $KEY -iv $IV -in sm4.ctr

