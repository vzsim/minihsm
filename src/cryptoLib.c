#include "pkcs11-cryptolib.h"
#include "scard_library.h"

CK_BBOOL pkcs11_initialized = CK_FALSE;
CK_BBOOL pkcs11_session_opened = CK_FALSE;
CK_ULONG pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
PKCS11_CRYPTOLIB_CK_OPERATION pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
static CK_ULONG ulPinLenMin = 0;
static CK_ULONG ulPinLenMax = 0;

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
	CK_RV rv;
	IGNORE(pInitArgs);

	if (CK_TRUE == pkcs11_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	do {
		pkcs11_initialized = CK_FALSE;
		rv = CKR_FUNCTION_FAILED;
		reset_conn_manager();

		if (sc_create_ctx() != SCARD_S_SUCCESS)
			break;
		
		pkcs11_initialized = CK_TRUE;
		if (sc_get_available_readers() != SCARD_S_SUCCESS)
			break;
		
		if (sc_card_connect() != SCARD_S_SUCCESS)
			break;

		rv = CKR_OK;
	} while (0);
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	IGNORE(pReserved);
	
	sc_card_disconnect();
	sc_delete_ctx();
	pkcs11_initialized = CK_FALSE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->cryptokiVersion.major = PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_VERSION_MAJOR;
	pInfo->cryptokiVersion.minor = PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_VERSION_MINOR;
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CRYPTOLIB_CK_INFO_MANUFACTURER_ID, strlen(PKCS11_CRYPTOLIB_CK_INFO_MANUFACTURER_ID));
	pInfo->flags = 0;
	memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_DESCRIPTION, strlen(PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_DESCRIPTION));
	pInfo->libraryVersion.major = 0x00;
	pInfo->libraryVersion.minor = 0x01;

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

		pSlotList[0] = (CK_SLOT_ID)connMan.ctx; //PKCS11_CRYPTOLIB_CK_SLOT_ID;
		*pulCount = 1;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_SLOT_ID)connMan.ctx != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_CRYPTOLIB_CK_SLOT_INFO_SLOT_DESCRIPTION, strlen(PKCS11_CRYPTOLIB_CK_SLOT_INFO_SLOT_DESCRIPTION));
	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_CRYPTOLIB_CK_SLOT_INFO_MANUFACTURER_ID, strlen(PKCS11_CRYPTOLIB_CK_SLOT_INFO_MANUFACTURER_ID));
	pInfo->flags = CKF_REMOVABLE_DEVICE | CKF_TOKEN_PRESENT;
	pInfo->hardwareVersion.major = 0x01;
	pInfo->hardwareVersion.minor = 0x00;
	pInfo->firmwareVersion.major = 0x01;
	pInfo->firmwareVersion.minor = 0x00;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;
	LONG sc_rv;
	do {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;
		
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if ((CK_SLOT_ID)connMan.ctx != slotID)
			break;
		
		rv = CKR_ARGUMENTS_BAD;
		if (NULL == pInfo)
			break;

		BYTE GET_DATA[] = {0x00, 0xCA, 0x00, 0xFF};
		memcpy(connMan.apdu.cmd, GET_DATA, sizeof(GET_DATA));
		sc_rv = sc_apdu_transmit();

		if (sc_rv != SCARD_S_SUCCESS) {
			rv = CKR_VENDOR_DEFINED | (CK_RV)sc_rv;
			break;
		}
		LONG offset = 5;
		LONG len = 0;
		BYTE flags = connMan.apdu.resp[offset++];

		switch (flags) {
			case 0x01: // LCS CREATION
				pInfo->flags = CKF_USER_PIN_TO_BE_CHANGED | CKF_SO_PIN_TO_BE_CHANGED;
			break;
			case 0x03: // LCS INITIALIZATION
				pInfo->flags = CKF_SO_PUK_INITIALIZED;
			break;
			case 0x04: // LCS DEACTIVATE
				pInfo->flags = CKF_USER_PIN_LOCKED;
			break;
			case 0x05: // LCS ACTIVATE
				pInfo->flags = CKF_LOGIN_REQUIRED | CKF_TOKEN_INITIALIZED | CKF_SO_PUK_INITIALIZED | CKF_USER_PIN_INITIALIZED;
			break;
			case 0x0C: // LCS TERMINATED
		}

		pInfo->hardwareVersion.major = 0x01;
		pInfo->hardwareVersion.minor = 0x00;

		pInfo->firmwareVersion.major = connMan.apdu.resp[offset++];
		pInfo->firmwareVersion.minor = connMan.apdu.resp[offset++];

		pInfo->ulMaxPinLen = ulPinLenMax = connMan.apdu.resp[offset++];
		pInfo->ulMinPinLen = ulPinLenMin = connMan.apdu.resp[offset++];
		
		len = connMan.apdu.resp[offset++];
		memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
		memcpy(pInfo->manufacturerID, &connMan.apdu.resp[offset], len);

		len = connMan.apdu.resp[offset + len];
		memset(pInfo->label, ' ', sizeof(pInfo->label));
		memcpy(pInfo->label, &connMan.apdu.resp[offset], len);

		len = connMan.apdu.resp[offset + len];
		memset(pInfo->model, ' ', sizeof(pInfo->model));
		memcpy(pInfo->model, &connMan.apdu.resp[offset], len);

		len = connMan.apdu.resp[offset + len];
		memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
		memcpy(pInfo->serialNumber, &connMan.apdu.resp[offset], len);
		pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
		pInfo->ulSessionCount = (CK_TRUE == pkcs11_session_opened) ? 1 : 0;
		pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
		pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_session_state) && (CKS_RO_USER_FUNCTIONS != pkcs11_session_state))) ? 1 : 0;
		
		
		pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
		pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
		pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
		pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
		
		memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));
	} while(0);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitToken)(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_SLOT_ID)connMan.ctx != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulPinLen < ulPinLenMin) || (ulPinLen > ulPinLenMax))
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

	if ((ulPinLen < ulPinLenMin) || (ulPinLen > ulPinLenMax))
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

	if ((ulOldLen < ulPinLenMin) || (ulOldLen > ulPinLenMax))
		return CKR_PIN_LEN_RANGE;

	if (NULL == pNewPin)
		return CKR_ARGUMENTS_BAD;

	if ((ulNewLen < ulPinLenMin) || (ulNewLen > ulPinLenMax))
		return CKR_PIN_LEN_RANGE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (CK_TRUE == pkcs11_session_opened)
		return CKR_SESSION_COUNT;

	if ((CK_SLOT_ID)connMan.ctx != slotID)
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

	if ((CK_SLOT_ID)connMan.ctx != slotID)
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

	pInfo->slotID = (CK_SLOT_ID)connMan.ctx;
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

	if ((ulPinLen < ulPinLenMin) || (ulPinLen > ulPinLenMax))
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

