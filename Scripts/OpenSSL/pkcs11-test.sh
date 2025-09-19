#!/bin/bash

pkcs11-tool --module ../../CryptoLib/build/libCryptoKey.so -I
pkcs11-tool --module ../../CryptoLib/build/libCryptoKey.so -T
pkcs11-tool --module ../../CryptoLib/build/libCryptoKey.so --init-token --label "SMDP" --so-pin "012345"
pkcs11-tool --module ../../CryptoLib/build/libCryptoKey.so --init-pin --login --so-pin 012345 --new-pin 11111
pkcs11-tool --module ../../CryptoLib/build/libCryptoKey.so -I
pkcs11-tool --module ../../CryptoLib/build/libCryptoKey.so -T

pkcs11-tool --module ../../CryptoLib/build/libCryptoKey.so --login --pin "11111" --encrypt "1234567812345678"