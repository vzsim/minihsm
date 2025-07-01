# CryptoLib

A PKCS#11 library to the Mini HSM

## Build libCryptoKey.so

```bash
./build.sh
```

## Build Image

```bash
docker build -t vcard-runner-crypto-lib .
```

## Usage

mount directories you want to use inside docker ```-v src dst```

```bash
docker run -it -v "$PWD:/workspace" -v "$PWD/build/src:/cryptolib" vcard-runner 
```
