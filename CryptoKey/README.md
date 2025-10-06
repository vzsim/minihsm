# CryptoKey

## Life cycle states
`INITIALIZED` - at this state user should set PUK, PIN and token label (optional). Setting PIN shifts the LCS to `ACTIVATED` state.    
`ACTIVATED` - at this state some operations can be performed only after user authentication.
`DEACTIVATED` - the applet falls into this state if a user blocks its PIN (three attempts). To get back to `ACTIVATED` state, ones have to enter a correct PUK.
`TERMINATED` - if user enters the wrong PUK. He has only 10 attempts.

Use the following commands to manage the applet's life cycle state:  
`00443000` - shift LCS to `ACTIVATED`  
`00043000` - shift LCS to `DEACTIVATED` (PUK is required)  
`00E63000` - shift LCS to `TERMINATED` (irriversable)  

The cryptographic functions are only available at `ACTIVATED` state.  
If the user PIN is blocked, then the only way to return the applet to the working state is by means of the following commands:

```shell
00A40400 06 A00000000101 # select MiniHSM
002D010007 8105 3132333435 # RESET RETRY COUNTER: verify PUK
00443000 # ACTIVATE
```

>[WARNING]
the PUK is optional, thus if it isn't set at LCS `INITIALIZED`, and the applet's LCS changes to `DEACTIVATED`, then there will be no way to return it to the `ACTIVATED` state.  

## Applet initialization
At LCS `INITIZALIED` an owner should pass the following sequence of `CHANGE REFERENCE DATA` commands:  
```shell
00A40400 06 A00000000101 # select MiniHSM
00250001 07 8105 3132333435 # set PUK (12345 in ascii)
00250004 06 8104 534D4450 # set label (SMDP  in ascii)
00250002 07 8105 3131313131 # set PIN (11111 in ascii)
```

## PIN verification
The `VERIFY` commands are *NOT* allowed at `DEACTIVATED` LCS.  
Running this command at `INITIALIZED` LCS does nothing and thus returns `9000`.  

To get the number of attempts left one has to send the following command:  
```shell
00200000 # return the number of PIN verification attempts 
```

To verify user PIN:
```shell
00200001 05 3131313131 # compare the value passed over in CDATA with the actual one. 
```
There are a total of three attempts, after which the applet will go into the `DEACTIVATED` state.
On successful verification, the cryptographic functions become available for the user.

>[NOTE]
The series of MSE and PSO commands are only available if user presents the correct PIN.

## Reset retry counter
This command is allowed only at `DEACTIVATED` LCS.  
To get the number of PUK tries:
```shell
002D0300 # Returns the number of available PIK verification attempts.
```

The following command can be useful in cases where someone accidentally runs out of attempts and just want to restore the PIN accessibility rather than change it:  
```shell
002D0100 07 81 05 3132333435 # reset the tries counter of the current PIN. 
```

If the PIN has been forgotten, then the following command can help:  
```shell
002D0100 0E 81 05 3132333435 82 05 3030303030 # Set a new PIN. 
```
Here the first value is current PUK followed by the new PIN.

## Perform security operation
### symmetric encryption
To perform AES-based encryption/decryption one should perform the following steps:  

```shell
# CRD: create AES key with KID=00 and keying material 0102030405060708090A0B0C0D0E0F10
00250005 15 8101 00 8210 0102030405060708090A0B0C0D0E0F10

# MSE: select AES algo and use the key with ID '00'
002281B8 06 8001 01 8301 00

#PSO: encrypt a plain text using the algo and key defined in previous step
002A8480 10 00000000000000000000000000000000 # returns encrypted value
#PSO: decrypt a cipher text
002A8084 10 F95C7F6B192B22BFFEFD1B779933FBFC # returns decrypted value
```

Here is the important notes:
* before performing ecryption/decryption operation the Manage Security Environment command shall be called which specifies the algo and keyID.
* This command shall be called on applet reset or changing algorithm/KeyID pair.
* Both AES and DES alogrithms use CBC mode with no padding (ISO9797, method 1).

### generating shared secret
MiniHSM can generate and return a shared secret. To do so, proceed to the following commands:
```shell
#CRD: generate ECDSA (secP256k1) key pair
00250107
# MSE: generate shared secret. Returns card's 04PubKey + 32 bytes of shared secret
002281A6 43 9441 04[second party public key] 
```