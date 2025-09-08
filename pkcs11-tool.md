```shell
Usage: pkcs11-tool [OPTIONS]
Options:
      --module <arg>            Specify the module to load (default:/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so)
  -I, --show-info               Show global token information
  -L, --list-slots              List available slots
  -T, --list-token-slots        List slots with tokens
  -M, --list-mechanisms         List mechanisms supported by the token
  -O, --list-objects            Show objects on token
      --list-interfaces         List interfaces of PKCS #11 3.0 library
  -s, --sign                    Sign some data
      --verify                  Verify a signature of some data
      --decrypt                 Decrypt some data
      --encrypt                 Encrypt some data
      --unwrap                  Unwrap key
      --wrap                    Wrap key
  -h, --hash                    Hash some data
      --derive                  Derive a secret key using another key and some data
      --derive-pass-der         Derive ECDHpass DER encoded pubkey for compatibility with some PKCS#11 implementations
  -m, --mechanism <arg>         Specify mechanism (use -M for a list of supported mechanisms), or by hexadecimal, e.g., 0x80001234
      --hash-algorithm <arg>    Specify hash algorithm used with RSA-PKCS-PSS signature and RSA-PKCS-OAEP decryption
      --mgf <arg>               Specify MGF (Message Generation Function) used for RSA-PSS signature and RSA-OAEP decryption (possible values are MGF1-SHA1 to MGF1-SHA512)
      --salt-len <arg>          Specify how many bytes should be used for salt in RSA-PSS signatures (default is digest size)
      --session-rw              Forces to open the PKCS#11 session with CKF_RW_SESSION
  -l, --login                   Log into the token first
      --login-type <arg>        Specify login type ('so', 'user', 'context-specific'; default:'user')
  -p, --pin <arg>               Supply User PIN on the command line (if used in scripts: careful!)
      --puk <arg>               Supply User PUK on the command line
      --new-pin <arg>           Supply new User PIN on the command line
      --so-pin <arg>            Supply SO PIN on the command line (if used in scripts: careful!)
      --init-token              Initialize the token, its label and its SO PIN (use with --label and --so-pin)
      --init-pin                Initialize the User PIN (use with --pin and --login)
  -c, --change-pin              Change User PIN
      --unlock-pin              Unlock User PIN (without '--login' unlock in logged in session; otherwise '--login-type' has to be 'context-specific')
  -k, --keypairgen              Key pair generation
      --keygen                  Key generation
      --key-type <arg>          Specify the type and length (bytes if symmetric) of the key to create, for example rsa:1024, EC:prime256v1, EC:ed25519, EC:curve25519, GOSTR3410-2012-256:B, AES:16 or GENERIC:64
      --usage-sign              Specify 'sign' key usage flag (sets SIGN in privkey, sets VERIFY in pubkey)
      --usage-decrypt           Specify 'decrypt' key usage flag (sets DECRYPT in privkey and ENCRYPT in pubkey for RSA, sets both DECRYPT and ENCRYPT for secret keys)
      --usage-derive            Specify 'derive' key usage flag (EC only)
      --usage-wrap              Specify 'wrap' key usage flag
  -w, --write-object <arg>      Write an object (key, cert, data) to the card
  -r, --read-object             Get object's CKA_VALUE attribute (use with --type)
  -b, --delete-object           Delete an object (use with --type cert/data/privkey/pubkey/secrkey)
      --application-label <arg>
                                Specify the application label of the data object (use with --type data)
      --application-id <arg>    Specify the application ID of the data object (use with --type data)
      --issuer <arg>            Specify the issuer in hexadecimal format (use with --type cert)
      --subject <arg>           Specify the subject in hexadecimal format (use with --type cert/privkey/pubkey)
  -y, --type <arg>              Specify the type of object (e.g. cert, privkey, pubkey, secrkey, data)
  -d, --id <arg>                Specify the ID of the object
  -a, --label <arg>             Specify the label of the object
      --slot <arg>              Specify the ID of the slot to use (accepts HEX format with 0x.. prefix or decimal number)
      --slot-description <arg>  Specify the description of the slot to use
      --slot-index <arg>        Specify the index of the slot to use
      --object-index <arg>      Specify the index of the object to use
      --token-label <arg>       Specify the token label of the slot to use
  -e, --set-id <arg>            Set the CKA_ID of an object, <args>= the (new) CKA_ID
      --attr-from <arg>         Use <arg> to create some attributes when writing an object
  -i, --input-file <arg>        Specify the input file
      --signature-file <arg>    Specify the file with signature for verification
  -o, --output-file <arg>       Specify the output file
  -f, --signature-format <arg>  Format for ECDSA signature <arg>: 'rs' (default), 'sequence', 'openssl'
      --allowed-mechanisms <arg>
                                Specify the comma-separated list of allowed mechanisms when creating an object.
  -t, --test                    Test (best used with the --login or --pin option)
      --test-hotplug            Test hotplug capabilities (C_GetSlotList + C_WaitForSlotEvent)
  -z, --moz-cert <arg>          Test Mozilla-like key pair gen and cert req, <arg>=certfile
  -v, --verbose                 Verbose operation. (Set OPENSC_DEBUG to enable OpenSC specific debugging)
      --private                 Set the CKA_PRIVATE attribute (object is only viewable after a login)
      --sensitive               Set the CKA_SENSITIVE attribute (object cannot be revealed in plaintext)
      --extractable             Set the CKA_EXTRACTABLE attribute (object can be extracted)
      --undestroyable           Set the CKA_DESTROYABLE attribute to false (object cannot be destroyed)
      --always-auth             Set the CKA_ALWAYS_AUTHENTICATE attribute to a key object (require PIN verification for each use)
      --test-ec                 Test EC (best used with the --login or --pin option)
      --test-fork               Test forking and calling C_Initialize() in the child
      --use-locking             Call C_initialize() with CKF_OS_LOCKING_OK.
      --test-threads <arg>      Test threads. Multiple times to start additional threads, arg is string or 2 byte commands
      --generate-random <arg>   Generate given amount of random data
      --allow-sw                Allow using software mechanisms (without CKF_HW)
      --iv <arg>                Initialization vector
```

```c
C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{

}

logs a user into a token.
CK_SESSION_HANDLE hSession - session handle;
CK_USER_TYPE userType      - user type;
CK_UTF8CHAR_PTR pPin       - points to the user’s PIN;
CK_ULONG ulPinLen          - length of the PIN.

This standard allows PIN values to contain any valid UTF8 character, but the token may impose subset restrictions.
When the user type is either CKU_SO or CKU_USER, if the call succeeds, each of the application's sessions will enter either
	- the "R/W SO Functions" state,
	- the "R/W User Functions" state,
	- the "R/O User Functions" state.'
If the user type is CKU_CONTEXT_SPECIFIC, the behavior of C_Login depends on the context in which it is called. Improper use of this user type will result in a return value CKR_OPERATION_NOT_INITIALIZED..

If there are any active cryptographic or object finding operations in an application’s session, and then C_Login is successfully executed by that application, it may or may not be the case that those operations are still active.  Therefore, before logging in, any active operations should be finished.

If the application calling C_Login has a R/O session open with the token, then it will be unable to log the SO into a session (see [PKCS11-UG] for further details).  An attempt to do this will result in the error code CKR_SESSION_READ_ONLY_EXISTS.

C_Login may be called repeatedly, without intervening C_Logout calls, if (and only if) a key with the CKA_ALWAYS_AUTHENTICATE attribute set to CK_TRUE exists, and the user needs to do cryptographic operation on this key. See further Section 4.9.

Return values: CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_DEVICE_REMOVED, CKR_FUNCTION_CANCELED, CKR_FUNCTION_FAILED, CKR_GENERAL_ERROR, CKR_HOST_MEMORY, CKR_OK, CKR_OPERATION_NOT_INITIALIZED, CKR_PIN_INCORRECT, CKR_PIN_LOCKED, CKR_SESSION_CLOSED, CKR_SESSION_HANDLE_INVALID, CKR_SESSION_READ_ONLY_EXISTS, CKR_USER_ALREADY_LOGGED_IN, CKR_USER_ANOTHER_ALREADY_LOGGED_IN, CKR_USER_PIN_NOT_INITIALIZED, CKR_USER_TOO_MANY_TYPES, CKR_USER_TYPE_INVALID.

Example: see C_Logout.
```