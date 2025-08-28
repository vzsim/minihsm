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
Duration: 0.08195805549621582

Generate shared secret
>> 00220000 41 04BCB79758EE1AB6C677DBD9030103D58724B8AC4263AEE080039DAC709533F6407947E99A42844F5D113E5D074B858288CB47C71052FE9F78C9EADE3B4761C822
_
 ->  0022 0000 41 04BCB79758EE1AB6C677DBD9030103D58724B8AC4263AEE080039DAC709533F6407947E99A42844F5D113E5D074B858288CB47C71052FE9F78C9EADE3B4761C822
 <-  6161
_
 ->  00C0 0000 61 
 <-  049F4254E210BAF366A91799D2F9B2370F33DA852D2918F2717561BFE08E990EF2E1F62DAA0DAA02F82B8E7421B069F13C2386E88141CC6A5102101182DA29059F26173F66813D09ED3992B19F0BE48A4B3D349C6DFC08AAEC0B8AC68DC03F404E 9000
<< [6161, 00C00000 61] 049F4254E210BAF366A91799D2F9B2370F33DA852D2918F2717561BFE08E990EF2E1F62DAA0DAA02F82B8E7421B069F13C2386E88141CC6A5102101182DA29059F26173F66813D09ED3992B19F0BE48A4B3D349C6DFC08AAEC0B8AC68DC03F404E 9000 - sw_no_error
Duration: 0.041307687759399414

Host public key :  04bcb79758ee1ab6c677dbd9030103d58724b8ac4263aee080039dac709533f6407947e99a42844f5d113e5d074b858288cb47c71052fe9f78c9eade3b4761c822
Card  public key:  9f4254e210baf366a91799d2f9b2370f33da852d2918f2717561bfe08e990ef2e1f62daa0daa02f82b8e7421b069f13c2386e88141cc6a5102101182da29059f
Host  shared key:  26173f66813d09ed3992b19f0be48a4b3d349c6dfc08aaec0b8ac68dc03f404e
Card  shared key:  26173f66813d09ed3992b19f0be48a4b3d349c6dfc08aaec0b8ac68dc03f404e
Are values equal?  True
```
> Note: is't assumed that the vcard had been initialized previously.\
to do so, run JCShell scripts __01_install_test.jcsh__ and __03_change_refdata_test.jcsh__