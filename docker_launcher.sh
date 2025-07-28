#!/bin/sh

mkdir build
cd CryptoLib && ./build.sh && cp ./build/libCryptoKey.so ../build && cd ..
cd CryptoKey && ant && cp ./CryptoKey.cap ../build && cd ..
/data/jcshell.sh