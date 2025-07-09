# CryptoLib

A PKCS#11 library to the Mini HSM

## Cloning repositories:

Create 'minihsm' working folder:
```bash
mkdir minihsm && cd minihsm
```
Cloning the main rep into 'minihsm' folder:
```bash
git clone https://github.com/vzsim/minihsm.git .
```
Cloning the submodules:
```bash
git submodule update --init --recursive
```

## Building Docker image

```bash
docker build -t vcard-runner-crypto-lib .
```

## Usage

Mount directories you want to use inside docker using `-v src dst`:

```bash
docker run -it -v "$PWD:/workspace" vcard-runner-crypto-lib 
```

### Build modules (inside the docker)

Create build directory if it doesn't exist:

```bash
mkdir build
```

Build CryptoLib.so inside the mounted workspace folder:

```bash
cd CryptoLib && ./build.sh && cp ./build/libCryptoKey.so ../build && cd ..
```

Build CryptoKey.cap inside the mounted workspace folder:

```bash
cd CryptoKey && ant && cp ./CryptoKey.cap ../build && cd ..
```

Load CryptoKey.cap:

```bash
/data/jcshell.sh -f /workspace/CryptoKey/Scripts/load.jcsh 
```

### Run PKCS#11 tool

Run inside docker:

```bash
pkcs11-tool --module ./build/libCryptoKey.so -I
pkcs11-tool --module ./build/libCryptoKey.so -T
pkcs11-tool --module ./build/libCryptoKey.so --init-token --label "MyHSM" --so-pin "01234"
pkcs11-tool --module ./build/libCryptoKey.so --init-pin --login --so-pin 01234 --new-pin 43210
```
