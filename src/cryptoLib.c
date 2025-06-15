#include "pkcs11-cryptolib.h"

CK_BBOOL pkcs11_initialized = CK_FALSE;
CK_BBOOL pkcs11_session_opened = CK_FALSE;
CK_ULONG pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
PKCS11_CRYPTOLIB_CK_OPERATION pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;

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


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(pReserved);

	pkcs11_initialized = CK_FALSE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = 0x00;
	pInfo->cryptokiVersion.minor = 0x01;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CRYPTOLIB_CK_INFO_MANUFACTURER_ID, strlen(PKCS11_CRYPTOLIB_CK_INFO_MANUFACTURER_ID));
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_DESCRIPTION, strlen(PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_DESCRIPTION));
	pInfo->libraryVersion.major = PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_VERSION_MAJOR;
	pInfo->libraryVersion.minor = PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_VERSION_MINOR;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_240_funcs;

	return CKR_OK;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(tokenPresent);

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlotList)
	{
		*pulCount = 1;
	}
	else
	{
		if (0 == *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pSlotList[0] = PKCS11_CRYPTOLIB_CK_SLOT_ID;
		*pulCount = 1;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_CRYPTOLIB_CK_SLOT_INFO_SLOT_DESCRIPTION, strlen(PKCS11_CRYPTOLIB_CK_SLOT_INFO_SLOT_DESCRIPTION));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CRYPTOLIB_CK_SLOT_INFO_MANUFACTURER_ID, strlen(PKCS11_CRYPTOLIB_CK_SLOT_INFO_MANUFACTURER_ID));
	pInfo->flags = CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, PKCS11_CRYPTOLIB_CK_TOKEN_INFO_LABEL, strlen(PKCS11_CRYPTOLIB_CK_TOKEN_INFO_LABEL));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MANUFACTURER_ID, strlen(PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MANUFACTURER_ID));
	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MODEL, strlen(PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MODEL));
	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	memcpy(pInfo->serialNumber, PKCS11_CRYPTOLIB_CK_TOKEN_INFO_SERIAL_NUMBER, strlen(PKCS11_CRYPTOLIB_CK_TOKEN_INFO_SERIAL_NUMBER));
	pInfo->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED;
	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulSessionCount = (CK_TRUE == pkcs11_session_opened) ? 1 : 0;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_session_state) && (CKS_RO_USER_FUNCTIONS != pkcs11_session_state))) ? 1 : 0;
	pInfo->ulMaxPinLen = PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MAX_PIN_LEN;
	pInfo->ulMinPinLen = PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MIN_PIN_LEN;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;
	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pMechanismList)
	{
		*pulCount = 9;
	}
	else
	{
		if (9 > *pulCount)
			return CKR_BUFFER_TOO_SMALL;

		pMechanismList[0] = CKM_RSA_PKCS_KEY_PAIR_GEN;
		pMechanismList[1] = CKM_RSA_PKCS;
		pMechanismList[2] = CKM_SHA1_RSA_PKCS;
		pMechanismList[3] = CKM_RSA_PKCS_OAEP;
		pMechanismList[4] = CKM_DES3_CBC;
		pMechanismList[5] = CKM_DES3_KEY_GEN;
		pMechanismList[6] = CKM_SHA_1;
		pMechanismList[7] = CKM_XOR_BASE_AND_DATA;
		pMechanismList[8] = CKM_AES_CBC;

		*pulCount = 9;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	switch (type)
	{
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_GENERATE_KEY_PAIR;
			break;

		case CKM_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER | CKF_WRAP | CKF_UNWRAP;
			break;

		case CKM_SHA1_RSA_PKCS:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_SIGN | CKF_VERIFY;
			break;

		case CKM_RSA_PKCS_OAEP:
			pInfo->ulMinKeySize = 1024;
			pInfo->ulMaxKeySize = 1024;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_CBC:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		case CKM_DES3_KEY_GEN:
			pInfo->ulMinKeySize = 192;
			pInfo->ulMaxKeySize = 192;
			pInfo->flags = CKF_GENERATE;
			break;

		case CKM_SHA_1:
			pInfo->ulMinKeySize = 0;
			pInfo->ulMaxKeySize = 0;
			pInfo->flags = CKF_DIGEST;
			break;

		case CKM_XOR_BASE_AND_DATA:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_DERIVE;
			break;

		case CKM_AES_CBC:
			pInfo->ulMinKeySize = 128;
			pInfo->ulMaxKeySize = 256;
			pInfo->flags = CKF_ENCRYPT | CKF_DECRYPT;
			break;

		default:
			return CKR_MECHANISM_INVALID;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pLabel)
		return CKR_ARGUMENTS_BAD;

	if (CK_TRUE == pkcs11_session_opened)
		return CKR_SESSION_EXISTS;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (CKS_RW_SO_FUNCTIONS != pkcs11_session_state)
		return CKR_USER_NOT_LOGGED_IN;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKS_RO_PUBLIC_SESSION == pkcs11_session_state) || (CKS_RO_USER_FUNCTIONS == pkcs11_session_state))
		return CKR_SESSION_READ_ONLY;

	if (NULL == pOldPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulOldLen < PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulOldLen > PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pNewPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulNewLen < PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulNewLen > PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (CK_TRUE == pkcs11_session_opened)
		return CKR_SESSION_COUNT;

	if (PKCS11_CRYPTOLIB_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (!(flags & CKF_SERIAL_SESSION))
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;

	IGNORE(pApplication);

	IGNORE(Notify);

	if (NULL == phSession)
		return CKR_ARGUMENTS_BAD;

	pkcs11_session_opened = CK_TRUE;
	pkcs11_session_state = (flags & CKF_RW_SESSION) ? CKS_RW_PUBLIC_SESSION : CKS_RO_PUBLIC_SESSION;
	*phSession = PKCS11_CRYPTOLIB_CK_SESSION_ID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_session_opened = CK_FALSE;
	pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)(CK_SLOT_ID slotID)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_SLOT_ID != slotID)
		return CKR_SLOT_ID_INVALID;

	pkcs11_session_opened = CK_FALSE;
	pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->slotID = PKCS11_CRYPTOLIB_CK_SLOT_ID;
	pInfo->state = pkcs11_session_state;
	pInfo->flags = CKF_SERIAL_SESSION;
	if ((pkcs11_session_state != CKS_RO_PUBLIC_SESSION) && (pkcs11_session_state != CKS_RO_USER_FUNCTIONS))
		pInfo->flags = pInfo->flags | CKF_RW_SESSION;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pOperationState)
	{
		*pulOperationStateLen = 256;
	}
	else
	{
		if (256 > *pulOperationStateLen)
			return CKR_BUFFER_TOO_SMALL;

		memset(pOperationState, 1, 256);
		*pulOperationStateLen = 256;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pOperationState)
		return CKR_ARGUMENTS_BAD;

	if (256 != ulOperationStateLen)
		return CKR_ARGUMENTS_BAD;

	IGNORE(hEncryptionKey);

	IGNORE(hAuthenticationKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Login)(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv = CKR_OK;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((CKU_SO != userType) && (CKU_USER != userType))
		return CKR_USER_TYPE_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MIN_PIN_LEN) || (ulPinLen > PKCS11_CRYPTOLIB_CK_TOKEN_INFO_MAX_PIN_LEN))
		return CKR_PIN_LEN_RANGE;

	switch (pkcs11_session_state)
	{
		case CKS_RO_PUBLIC_SESSION:

			if (CKU_SO == userType)
				rv = CKR_SESSION_READ_ONLY_EXISTS;
			else
				pkcs11_session_state = CKS_RO_USER_FUNCTIONS;

			break;

		case CKS_RO_USER_FUNCTIONS:
		case CKS_RW_USER_FUNCTIONS:

			rv = (CKU_SO == userType) ? CKR_USER_ANOTHER_ALREADY_LOGGED_IN : CKR_USER_ALREADY_LOGGED_IN;

			break;

		case CKS_RW_PUBLIC_SESSION:

			pkcs11_session_state = (CKU_SO == userType) ? CKS_RW_SO_FUNCTIONS : CKS_RW_USER_FUNCTIONS;

			break;

		case CKS_RW_SO_FUNCTIONS:

			rv = (CKU_SO == userType) ? CKR_USER_ALREADY_LOGGED_IN : CKR_USER_ANOTHER_ALREADY_LOGGED_IN;

			break;
	}

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((pkcs11_session_state == CKS_RO_PUBLIC_SESSION) || (pkcs11_session_state == CKS_RW_PUBLIC_SESSION))
		return CKR_USER_NOT_LOGGED_IN;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((0 != flags)  && (CKF_DONT_BLOCK != flags))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSlot)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pReserved)
		return CKR_ARGUMENTS_BAD;

	return CKR_NO_EVENT;
}

