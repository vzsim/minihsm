# HOW TO

1. Change to the folder containing the python scripts, create a virtual environment
and activate it:

```shell
root@21d85b:/workspace# cd ./CryptoKey/Scripts/Python
root@21d85b:/workspace/CryptoKey/Scripts/Python# python3 -m venv tests-venv
root@21d85b:/workspace/CryptoKey/Scripts/Python# source tests-venv/bin/activate
(tests-venv) root@21d85b:/workspace/CryptoKey/Scripts/Python#
```

2. Install dependencies
```shell
(tests-venv) root@21d85b:/workspace/CryptoKey/Scripts/Python# python3 -m pip install pyscard
(tests-venv) root@21d85b:/workspace/CryptoKey/Scripts/Python# python3 -m pip install cryptography
```

3. Run the example
```shell
(tests-venv) root@21d85b:/workspace/CryptoKey/Scripts/Python# python3 ecdh_test.py
Context established!
PCSC Readers:
     Virtual PCD 00 00
     Virtual PCD 00 01
try to open reader: Virtual PCD 00 00
RESET

"Virtual PCD 00 00" (T=1) state: 0x10034
ATR: 3B139557696E

Select CryptoKey
>> 00A40400 06 A00000000101
_
 ->  00A4 0400 06 A00000000101
 <-  9000
<< 9000 - sw_no_error
Duration: 0.04227590560913086

OPEN SM: get public key
>> 00220000 41 045741CA4C1C13D20F7AE9B244FE6A244E0C36FA74647753F03C5B3561AA629EF92C5F311B4449E15C6ADE9CCC756FED3536D280BA1E8BF0688E7A9AFEB0D33C10
_
 ->  0022 0000 41 045741CA4C1C13D20F7AE9B244FE6A244E0C36FA74647753F03C5B3561AA629EF92C5F311B4449E15C6ADE9CCC756FED3536D280BA1E8BF0688E7A9AFEB0D33C10
 <-  6141
_
 ->  00C0 0000 41 
 <-  046462E68DEA5FC7BE72CD851112CF2124F6589B0CD6E8527D8548A84949917119A2E94C5F2462EADBFB212ABECABE73FC2EAC467808C37C9361596755A1D236CD 9000
<< [6141, 00C00000 41] 046462E68DEA5FC7BE72CD851112CF2124F6589B0CD6E8527D8548A84949917119A2E94C5F2462EADBFB212ABECABE73FC2EAC467808C37C9361596755A1D236CD 9000 - sw_no_error
Duration: 0.04221010208129883

OPEN SM: get a random
>> 00220100 00
_
 ->  0022 0100 00 
 <-  6110
_
 ->  00C0 0000 10 
 <-  519EFF03A973397B6CBF280B70E99E1B 9000
<< [6110, 00C00000 10] 519EFF03A973397B6CBF280B70E99E1B 9000 - sw_no_error
Duration: 0.04207873344421387

OPEN SM: check the cryptogram
>> 00220200 10 9B71F362EA911C0E9EF1D714508932F9
_
 ->  0022 0200 10 9B71F362EA911C0E9EF1D714508932F9
 <-  6101
_
 ->  00C0 0000 01 
 <-  A5 9000
<< [6101, 00C00000 01] A5 9000 - sw_no_error
Duration: 0.0411372184753418

Disconnected
```
> Note: is't assumed that the vcard had been initialized previously.\
to do so, run the __01_install_test.jcsh__ and __03_change_refdata_test.jcsh__ scripts.



> Weird behavior.\
The below sequence will reduce the decrypted output.\
No matter what the input array length is , it will strip away the last 16 bytes.
```java
private short aes(byte[] buff, short cdataOff, short lc, byte mode)
{
	short le = ZERO;
	aesCipher.init(aesKey16, mode);
	le += aesCipher.doFinal(buff, cdataOff, lc, tempRamBuff, ZERO);
	Util.arrayCopyNonAtomic(tempRamBuff, ZERO, buff, ZERO, le);
	return le;
}
```
> Weird behavior. Part 2.\
The below sequence will increase the encrypted output.\
No matter what the input array length is, it will assign another 16 bytes.
```java
private short aes(byte[] buff, short cdataOff, short lc, byte mode)
{
	short le = ZERO;
	aesCipher.init(aesKey16, mode);
	le = aesCipher.update(buff, cdataOff, lc, tempRamBuff, ZERO);
	le += aesCipher.doFinal(buff, (short)(cdataOff + le), (short)(lc - le), tempRamBuff, le);
	Util.arrayCopyNonAtomic(tempRamBuff, ZERO, buff, ZERO, le);
	return le;
}
```