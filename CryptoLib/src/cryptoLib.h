#ifndef CRYPTOLIB_H
#define CRYPTOLIB_H

#include "pkcs11-cryptolib.h"
#include "scard_library.h"

#define CAPDU_LENGTH 261	// CLA INS P1 P1 Lc [255 bytes of CDATA] Le
#define RAPDU_LENGTH 258	// [256 bytes of RDATA] SW1 SW2

typedef struct {
	uint8_t  cmd[CAPDU_LENGTH];
	uint32_t cmdLen;
	uint8_t  resp[RAPDU_LENGTH];
	uint64_t respLen;
	uint16_t sw;
	uint16_t  protocol;
} Apdu_t;

static CK_FUNCTION_LIST pkcs11_240_funcs =
{
	{0x02, 0x28},
	&C_Initialize,
	&C_Finalize,
	&C_GetInfo,
	&C_GetFunctionList,
	&C_GetSlotList,
	&C_GetSlotInfo,
	&C_GetTokenInfo,
	&C_GetMechanismList,
	&C_GetMechanismInfo,
	&C_InitToken,
	&C_InitPIN,
	&C_SetPIN,
	&C_OpenSession,
	&C_CloseSession,
	&C_CloseAllSessions,
	&C_GetSessionInfo,
	&C_GetOperationState,
	&C_SetOperationState,
	&C_Login,
	&C_Logout,
	&C_CreateObject,
	&C_CopyObject,
	&C_DestroyObject,
	&C_GetObjectSize,
	&C_GetAttributeValue,
	&C_SetAttributeValue,
	&C_FindObjectsInit,
	&C_FindObjects,
	&C_FindObjectsFinal,
	&C_EncryptInit,
	&C_Encrypt,
	&C_EncryptUpdate,
	&C_EncryptFinal,
	&C_DecryptInit,
	&C_Decrypt,
	&C_DecryptUpdate,
	&C_DecryptFinal,
	&C_DigestInit,
	&C_Digest,
	&C_DigestUpdate,
	&C_DigestKey,
	&C_DigestFinal,
	&C_SignInit,
	&C_Sign,
	&C_SignUpdate,
	&C_SignFinal,
	&C_SignRecoverInit,
	&C_SignRecover,
	&C_VerifyInit,
	&C_Verify,
	&C_VerifyUpdate,
	&C_VerifyFinal,
	&C_VerifyRecoverInit,
	&C_VerifyRecover,
	&C_DigestEncryptUpdate,
	&C_DecryptDigestUpdate,
	&C_SignEncryptUpdate,
	&C_DecryptVerifyUpdate,
	&C_GenerateKey,
	&C_GenerateKeyPair,
	&C_WrapKey,
	&C_UnwrapKey,
	&C_DeriveKey,
	&C_SeedRandom,
	&C_GenerateRandom,
	&C_GetFunctionStatus,
	&C_CancelFunction,
	&C_WaitForSlotEvent
};

#if defined(CRYPTOKI_DEBUG)

typedef struct {
	uint8_t cls_ins_p1[4];
	const char* str;
} cmd_struct;

static cmd_struct known_commands[] = {
	{{0x00, 0xc0, 0x00, 0x00}, "GET RESPONSE"},
	{{0x00, 0xa4, 0x04, 0x00}, "SELECT"},
	{{0x00, 0xca, 0x00, 0xff}, "GET DATA"},
	{{0x00, 0x25, 0x01, 0x01}, "INIT PIN"},
	{{0x00, 0x25, 0x01, 0x02}, "INIT TOKEN"},
	{{0x00, 0x25, 0x00, 0x00}, "UPDATE TOKEN"},
};

static void
print_cmd_name(uint8_t* cmd, uint32_t cmdLen)
{	
	for (uint32_t i = 0; i < sizeof(known_commands) / sizeof(cmd_struct); ++i) {
		if (!memcmp(known_commands[i].cls_ins_p1, cmd, 4)) {
			printf("%s\n", known_commands[i].str);
			return;
		}
	}

	printf("UNKNOWN COMMAND\n");
}

#	define DBG_PRINT_FUNC_NAME(name)		\
	printf("%s\n", name);

#	define DBG_PRINT_APDU(buff, len, isCmd)	\
	do {									\
		if (isCmd) {						\
			print_cmd_name(buff, len);		\
			printf(">> ");					\
		} else {							\
			printf("<< ");					\
		}									\
		for (uint32_t i = 0; i < len; ++i) {\
			if ((i != 0) && ((i % 32) == 0))\
				printf("\n   ");			\
			printf("%02x ", buff[i]);		\
		}									\
		printf("\n");						\
	} while (0);							

#else
#	define DBG_PRINT_FUNC_NAME(name)
#	define DBG_PRINT_APDU(buff, len, isCmd)
#endif


#endif /* CRYPTOLIB_H */