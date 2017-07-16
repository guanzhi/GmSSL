#!/bin/bash

for file in $`ls *.pod`
do
	mdfile=`basename -s .pod $file`.md
	pod2markdown --utf8 $file $mdfile
done
