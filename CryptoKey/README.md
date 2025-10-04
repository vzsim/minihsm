# CryptoKey

## Life cycle states
`INITIALIZED` - at this stage user should set PUK, PIN and token label (optional).  
`ACTIVATED` - at this stage some operations can be performed only after user authentication.
`DEACTIVATED` - the applet falls into this stage if a user blocks its PIN (three attempts). To get back to `ACTIVATED` state, ones have to enter a correct PUK.
`TERMINATED` - if user enters the wrong PUK. He has only 10 attempts.

>[WARNING]
the PUK is optional, thus if it isn't set, and the applet's LCS changes to DEACTIVATED, then there will be no way to restore the ACTIVATED state.

Use the following commands to manage the applet's life cycle state:  
`00443000` - shift LCS to `ACTIVATED`  
`00043000` - shift LCS to `DEACTIVATED` (PUK is required)  
`00E63000` - shift LCS to `TERMINATED` (irriversable)  

The cryptographic functions are only available at `ACTIVATED` stage.  
If the user PIN is blocked, then the only way to return the applet to the working state is by means of
`RESET RETRY COUNTER` command:  
`002D0100XX 81XX PUK` - pass the PUK

