#!/bin/bash

pkcs11-tool --module /workspace/CryptoLib/build/libCryptoKey.so --init-token --label "SMDP" --so-pin "012345"
pkcs11-tool --module /workspace/CryptoLib/build/libCryptoKey.so --init-pin --login --so-pin 012345 --new-pin 11111
pkcs11-tool --module /workspace/CryptoLib/build/libCryptoKey.so -I
pkcs11-tool --module /workspace/CryptoLib/build/libCryptoKey.so -T

pkcs11-tool --module /workspace/CryptoLib/build/libCryptoKey.so --login --pin 11111 --encrypt --id 2 -m AES-CBC --iv 0000000000000000 --input-file /workspace/plain_text.txt --output-file /workspace/cipher_text.bin
pkcs11-tool --module /workspace/CryptoLib/build/libCryptoKey.so --login --pin 11111 --decrypt --id 2 -m AES-CBC --iv 0000000000000000 --input-file /workspace/cipher_text.txt --output-file /workspace/plain_text1.txt