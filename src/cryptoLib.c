#include "pkcs11-cryptolib.h"

CK_BBOOL pkcs11_initialized = CK_FALSE;

CK_FUNCTION_LIST pkcs11_240_funcs =
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

	&C_WaitForSlotEvent
};

CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	if (CK_TRUE == pkcs11_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	IGNORE(pInitArgs);

	pkcs11_initialized = CK_TRUE;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL_PTR == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_240_funcs;

	return CKR_OK;
}