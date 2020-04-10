#/!/bin/sh
openssl genrsa -des3 -out bpx_private_with_pass.pem 2048
openssl rsa -in box_private_with_pass.pem -outform PEM -pubout -out box_public.pem
openssl rsa -in box_private_with_pass.pem -out box_private.pem

