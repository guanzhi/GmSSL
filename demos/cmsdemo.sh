#!/bin/bash


gmssl sm2keygen -pass 1234 -out key.pem -pubout keypub.pem
gmssl certgen -C CN -ST Beijing -L Haidian -O PKU -OU CS -CN Alice -key_usage dataEncipherment -days 365 -key key.pem -pass 1234 -out cert.pem

echo "<html>The plaintext message.</html>" > plain.txt

gmssl cmsencrypt -in plain.txt -rcptcert cert.pem -out enveloped_data.pem
gmssl cmsparse -in enveloped_data.pem
gmssl cmsdecrypt -key key.pem -pass 1234 -cert cert.pem -in enveloped_data.pem

gmssl cmssign -key key.pem -pass 1234 -cert cert.pem -in plain.txt -out signed_data.pem
gmssl cmsparse -in signed_data.pem
gmssl cmsverify -in signed_data.pem -out signed_data.txt
cat signed_data.txt

