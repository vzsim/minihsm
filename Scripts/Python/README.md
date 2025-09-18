
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


> Weird behaviour. Part 3.\
This code outputs symmetric erroneous values, i.e. now both the input and output are\
assigned additional bytes.
```java
private short aes(byte[] buff, short cdataOff, short lc, byte mode)
{
	short le = ZERO;
	aesCipher.init(aesKey16, mode);
	le = aesCipher.update(buff, cdataOff, lc, tempRamBuff, ZERO);
	le += aesCipher.doFinal(buff, le, lc, tempRamBuff, le);
	Util.arrayCopyNonAtomic(tempRamBuff, ZERO, buff, ZERO, le);
	return le;
}
```