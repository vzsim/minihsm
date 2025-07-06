# CryptoLib

A PKCS#11 library to the Mini HSM

## Build Image

```bash
git submodule update --init --recursive
docker build -t vcard-runner-crypto-lib .
```

## Usage

Mount directories you want to use inside docker using `-v src dst`:

```bash
docker run -it -v "$PWD:/workspace" vcard-runner-crypto-lib 
```

### Build Steps

Create build directory if it doesn't exist:

```bash
mkdir build
```

Build CryptoLib.so inside docker container in mounted workspace folder:

```bash
cd CryptoLib && ./build.sh && cd ..
```

Build CryptoKey.cap inside docker container in mounted workspace folder:

```bash
cd CryptoKey && ant && mv ./CryptoKey.cap ../build/CryptoKey.cap && cd ..
```

Load CryptoKey.cap:

```bash
/data/jcshell.sh -f /workspace/CryptoKey/Scripts/load.jcsh 
```

### Testing

Run inside docker:

```bash
pkcs11-tool --module ./build/libCryptoKey.so -I
pkcs11-tool --module ./build/libCryptoKey.so -T
```
