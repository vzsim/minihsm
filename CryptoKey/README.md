# CryptoKey

## Life cycle stages
`INITIALIZED` - at this stage user should set PUK, PIN and token label (optional).  
`ACTIVATED` - at this stage some operations can be performed only after user authentication.
`DEACTIVATED` - the applet falls into this stage if a user blocks its PIN (three attempts). To get back to `ACTIVATED` stage, ones have to enter a correct PUK.
`TERMINATED` - if user enters the wrong PUK. He has only 10 attempts.

Use the following commands to manage the applet's life cycle stage:  
`00443000` - shift LCS to `ACTIVATED`  
`00043000` - shift LCS to `DEACTIVATED` (PUK is required)  
`00E63000` - shift LCS to `TERMINATED` (irriversable)  

The cryptographic functions are only available at `ACTIVATED` stage.  
If the user PIN is blocked, then the only way to return the applet to the working stage is by means of the following commands:

```shell
002D010007 8105 3132333435 # verify PUK
00443000 # ACTIVATE
```

>[WARNING]
the PUK is optional, thus if it isn't set at LCS `INITIALIZED`, and the applet's LCS changes to DEACTIVATED, then there will be no way to return it to the ACTIVATED stage.  

## Applet initialization
At LCS `INITIZALIED` an owner should pass the following sequence of `CHANGE REFERENCE DATA` commands:  
```shell
00A40400 06 A00000000101 # select MiniHSM
00250001 07 8105 3132333435 # set PUK (12345 in ascii)
00250004 06 8104 534D4450 # set label (SMDP  in ascii)
00250002 07 8105 3131313131 # set PIN (11111 in ascii)
```