#include "cryptoLib.h"
#include "iso7816.h"
#include <stdlib.h>
#include "stdio.h"

#define OUTBUFF_CAPACITY (32 * 1024)
static uint8_t AID[] = {0xA0, 0x00, 0x00, 0x00, 0x01, 0x01};
static uint32_t aidLen = sizeof(AID);
static uint8_t outBuff[OUTBUFF_CAPACITY];
static uint32_t outDataLen = 0;

static CK_BBOOL pkcs11_initialized = CK_FALSE;
static CK_BBOOL pkcs11_session_opened = CK_FALSE;
static CK_ULONG pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
static CK_SLOT_ID pkcs11_slotID = 0;
static PKCS11_CRYPTOLIB_CK_OPERATION pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
static CK_OBJECT_HANDLE pkcs11_mock_find_result = CKR_OBJECT_HANDLE_INVALID;

static CK_ULONG ulPinLenMin = 0;
static CK_ULONG ulPinLenMax = 0;


CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	CK_RV rv;
	IGNORE(pInitArgs);

	DBG_PRINT_FUNC_NAME("C_Initialize")

	do {
		rv = CKR_CRYPTOKI_ALREADY_INITIALIZED;
		if (pkcs11_initialized == CK_TRUE)
			break;
			
		rv = CKR_FUNCTION_FAILED;
		if (initialize_token()) {
			break;
		}
			
		pkcs11_initialized = CK_TRUE;
		rv = CKR_OK;
	} while (0);
	
	return rv;
}

CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	CK_RV rv;
	DBG_PRINT_FUNC_NAME("C_Finalize")
	IGNORE(pReserved);

	do {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized) {
			break;
		}

		rv = CKR_FUNCTION_FAILED;
		if (finalize_token()) {
			break;
		}

		pkcs11_initialized = CK_FALSE;
		rv = CKR_OK;
	} while (0);

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	CK_RV rv;
	DBG_PRINT_FUNC_NAME("C_GetInfo")

	do {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;
		
		rv = CKR_ARGUMENTS_BAD;
		if (NULL == pInfo)
			break;
	
		pInfo->cryptokiVersion.major = PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_VERSION_MAJOR;
		pInfo->cryptokiVersion.minor = PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_VERSION_MINOR;
		memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
		memcpy(pInfo->manufacturerID, PKCS11_CRYPTOLIB_CK_INFO_MANUFACTURER_ID, strlen(PKCS11_CRYPTOLIB_CK_INFO_MANUFACTURER_ID));
		pInfo->flags = 0;
		memset(pInfo->libraryDescription, ' ', sizeof(pInfo->libraryDescription));
		memcpy(pInfo->libraryDescription, PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_DESCRIPTION, strlen(PKCS11_CRYPTOLIB_CK_INFO_LIBRARY_DESCRIPTION));
		pInfo->libraryVersion.major = 0x00;
		pInfo->libraryVersion.minor = 0x01;
		rv = CKR_OK;
	} while (0);
	
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	DBG_PRINT_FUNC_NAME("C_GetFunctionList")

	if (NULL == ppFunctionList)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &pkcs11_240_funcs;
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	DBG_PRINT_FUNC_NAME("C_GetSlotList")

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

		pSlotList[0] = pkcs11_slotID; //PKCS11_CRYPTOLIB_CK_SLOT_ID;
		*pulCount = 1;
	}
	
	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	DBG_PRINT_FUNC_NAME("C_GetSlotInfo")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pkcs11_slotID != slotID)
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

	DBG_PRINT_FUNC_NAME("C_GetTokenInfo")

	do {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;
		
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (pkcs11_slotID != slotID)
			break;
		
		rv = CKR_ARGUMENTS_BAD;
		if (NULL == pInfo)
			break;

		rv = CKR_FUNCTION_FAILED;
		
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}
		
		if (transmit(cmd_get_data, NULL, 0, outBuff, &outDataLen)) {
			break;
		}
		
		int32_t offset = 0;
		uint8_t flags = outBuff[offset++];

		switch (flags) {
			case 0x01: // LCS CREATION
				pInfo->flags = CKF_USER_PIN_TO_BE_CHANGED | CKF_SO_PIN_TO_BE_CHANGED;
			break;
			case 0x03: // LCS INITIALIZATION
				pInfo->flags = CKF_SO_PUK_INITIALIZED | CKF_USER_PIN_TO_BE_CHANGED; //https://meet.google.com/xeg-yegi-oir
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

		pInfo->firmwareVersion.major = outBuff[offset++];
		pInfo->firmwareVersion.minor = outBuff[offset++];

		ulPinLenMin = outBuff[offset++];
		ulPinLenMax = outBuff[offset++];

		pInfo->ulMinPinLen = ulPinLenMin;
		pInfo->ulMaxPinLen = ulPinLenMax;
		
		int32_t len = outBuff[offset++];
		memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
		memcpy(pInfo->manufacturerID, &outBuff[offset], len);

		offset += len;
		len = outBuff[offset++];
		memset(pInfo->label, ' ', sizeof(pInfo->label));
		memcpy(pInfo->label, &outBuff[offset], len);

		offset += len;
		len = outBuff[offset++];
		memset(pInfo->model, ' ', sizeof(pInfo->model));
		memcpy(pInfo->model, &outBuff[offset], len);

		offset += len;
		len = outBuff[offset++];
		memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
		memcpy(pInfo->serialNumber, &outBuff[offset], len);

		pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
		pInfo->ulSessionCount = (CK_TRUE == pkcs11_session_opened) ? 1 : 0;
		pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;
		pInfo->ulRwSessionCount = ((CK_TRUE == pkcs11_session_opened) && ((CKS_RO_PUBLIC_SESSION != pkcs11_session_state) && (CKS_RO_USER_FUNCTIONS != pkcs11_session_state))) ? 1 : 0;
		
		pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
		pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
		pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
		pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;
		
		memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));
		
		rv = CKR_OK;
	} while(0);
	
	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	DBG_PRINT_FUNC_NAME("C_GetMechanismList")
	
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	
	if (pkcs11_slotID != slotID)
		return CKR_SLOT_ID_INVALID;
	
	if (NULL == pulCount)
		return CKR_ARGUMENTS_BAD;
	
	if (NULL == pMechanismList)
	{
		*pulCount = 9;
	}
	else
	{
		printf("pulCount = %ld\n", *pulCount);
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
	DBG_PRINT_FUNC_NAME("C_GetMechanismInfo")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pkcs11_slotID != slotID)
		return CKR_SLOT_ID_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;
	printf("mechanism type = %ld\n", type);
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
	CK_RV rv;
	
	DBG_PRINT_FUNC_NAME("C_InitToken")

	do {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;
		
		
		rv = CKR_SLOT_ID_INVALID;
		if (pkcs11_slotID != slotID)
			break;
		
		rv = CKR_ARGUMENTS_BAD;
		if (NULL == pPin)
			break;
		
		rv = CKR_PIN_LEN_RANGE;
		if ((ulPinLen < ulPinLenMin) || (ulPinLen > ulPinLenMax))
			break;
	
		rv = CKR_ARGUMENTS_BAD;
		if (NULL == pLabel)
			break;
		
		rv = CKR_SESSION_EXISTS;
		if (CK_TRUE == pkcs11_session_opened)
			break;

		rv = CKR_FUNCTION_FAILED;
		
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}

		uint32_t labelLen = strlen((const char *)pLabel);
		if (transmit(cmd_crd_set_label, pLabel, labelLen, NULL, NULL)) {
			break;
		}

		if (transmit(cmd_crd_set_puk, pPin, ulPinLen, NULL, NULL)) {
			break;
		}
		
		rv = CKR_OK;
	} while (0);

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rv;

	DBG_PRINT_FUNC_NAME("C_InitPIN")

	do {
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;
	
		rv = CKR_SESSION_HANDLE_INVALID;
		if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
			break;
		
		rv = CKR_USER_NOT_LOGGED_IN;
		if (CKS_RW_SO_FUNCTIONS != pkcs11_session_state)
			break;
		
		rv = CKR_ARGUMENTS_BAD;
		if (NULL == pPin)
			break;
		
		rv = CKR_PIN_LEN_RANGE;
		if ((ulPinLen < ulPinLenMin) || (ulPinLen > ulPinLenMax))
			break;
		
		rv = CKR_FUNCTION_FAILED;
		
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}
		
		if (transmit(cmd_crd_set_pin, pPin, ulPinLen, NULL, NULL)) {
			break;
		}

		if (transmit(cmd_lcs_activated, NULL, 0, NULL, NULL)) {
			break;
		}
		
		rv = CKR_OK;
	} while (0);

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	DBG_PRINT_FUNC_NAME("C_SetPIN")

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
	DBG_PRINT_FUNC_NAME("C_OpenSession")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (CK_TRUE == pkcs11_session_opened)
		return CKR_SESSION_COUNT;

	if (pkcs11_slotID != slotID)
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
	DBG_PRINT_FUNC_NAME("C_CloseSession")

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
	DBG_PRINT_FUNC_NAME("C_CloseAllSessions")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (pkcs11_slotID != slotID)
		return CKR_SLOT_ID_INVALID;

	pkcs11_session_opened = CK_FALSE;
	pkcs11_session_state = CKS_RO_PUBLIC_SESSION;
	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	DBG_PRINT_FUNC_NAME("C_GetSessionInfo")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pInfo)
		return CKR_ARGUMENTS_BAD;

	pInfo->slotID = pkcs11_slotID;
	pInfo->state = pkcs11_session_state;
	pInfo->flags = CKF_SERIAL_SESSION;
	if ((pkcs11_session_state != CKS_RO_PUBLIC_SESSION) && (pkcs11_session_state != CKS_RO_USER_FUNCTIONS))
		pInfo->flags = pInfo->flags | CKF_RW_SESSION;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	DBG_PRINT_FUNC_NAME("C_GetOperationState")

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
	DBG_PRINT_FUNC_NAME("C_SetOperationState")

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
	
	DBG_PRINT_FUNC_NAME("C_Login")

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

	do {
		rv = CKR_FUNCTION_FAILED;
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}
		
		cmdEnum cmdType = userType == CKU_SO ? cmd_verify_puk : cmd_verify_pin;
		rv = CKR_PIN_INCORRECT;
		if (transmit(cmdType, pPin, ulPinLen, NULL, NULL)) {
			break;
		}
		rv = CKR_OK;
	} while (0);

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)(CK_SESSION_HANDLE hSession)
{
	CK_RV rv = CKR_OK;
	DBG_PRINT_FUNC_NAME("C_Logout")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((pkcs11_session_state == CKS_RO_PUBLIC_SESSION) || (pkcs11_session_state == CKS_RW_PUBLIC_SESSION))
		return CKR_USER_NOT_LOGGED_IN;

	do {
		rv = CKR_FUNCTION_FAILED;
			
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}
		
		if (transmit(cmd_verify_reset, NULL, 0, NULL, NULL)) {
			break;
		}
		
		rv = CKR_OK;
	} while (0);

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phObject)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phObject = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phNewObject)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 < ulCount))
	{
		for (i = 0; i < ulCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phNewObject = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pulSize)
		return CKR_ARGUMENTS_BAD;

	*pulSize = PKCS11_MOCK_CK_OBJECT_SIZE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if (CKA_LABEL == pTemplate[i].type)
		{
			if (NULL != pTemplate[i].pValue)
			{
				if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL))
					return CKR_BUFFER_TOO_SMALL;
				else
					memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_LABEL, strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL));
			}

			pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_LABEL);
		}
		else if (CKA_VALUE == pTemplate[i].type)
		{
			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY == hObject)
			{
				pTemplate[i].ulValueLen = (CK_ULONG) -1;
			}
			else
			{
				if (NULL != pTemplate[i].pValue)
				{
					if (pTemplate[i].ulValueLen < strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE))
						return CKR_BUFFER_TOO_SMALL;
					else
						memcpy(pTemplate[i].pValue, PKCS11_MOCK_CK_OBJECT_CKA_VALUE, strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE));
				}

				pTemplate[i].ulValueLen = strlen(PKCS11_MOCK_CK_OBJECT_CKA_VALUE);
			}
		}
		else
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((PKCS11_MOCK_CK_OBJECT_HANDLE_DATA != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hObject) &&
		(PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hObject))
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulCount)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulCount; i++)
	{
		if ((CKA_LABEL == pTemplate[i].type) || (CKA_VALUE == pTemplate[i].type))
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
		else
		{
			return CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_ULONG i = 0;
	CK_ULONG_PTR cka_class_value = NULL;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	IGNORE(ulCount);

	pkcs11_mock_find_result = CK_INVALID_HANDLE;

	for (i = 0; i < ulCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (CKA_CLASS == pTemplate[i].type)
		{
			if (sizeof(CK_ULONG) != pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			cka_class_value = (CK_ULONG_PTR) pTemplate[i].pValue;

			switch (*cka_class_value)
			{
				case CKO_DATA:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_DATA;
					break;
				case CKO_SECRET_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;
					break;
				case CKO_PUBLIC_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
					break;
				case CKO_PRIVATE_KEY:
					pkcs11_mock_find_result = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;
					break;
			}
		}
	}

	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_FIND;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_FIND != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if ((NULL == phObject) && (0 < ulMaxObjectCount))
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulObjectCount)
		return CKR_ARGUMENTS_BAD;

	switch (pkcs11_mock_find_result)
	{
		case PKCS11_MOCK_CK_OBJECT_HANDLE_DATA:
			
			if (ulMaxObjectCount >= 2)
			{
				phObject[0] = pkcs11_mock_find_result;
				phObject[1] = pkcs11_mock_find_result;
			}

			*pulObjectCount = 2;

			break;

		case CK_INVALID_HANDLE:
			
			*pulObjectCount = 0;

			break;

		default:

			if (ulMaxObjectCount >= 1)
			{
				phObject[0] = pkcs11_mock_find_result;
			}

			*pulObjectCount = 1;

			break;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)(CK_SESSION_HANDLE hSession)
{
	DBG_PRINT_FUNC_NAME("C_FindObjectsFinal")
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_FIND != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	DBG_PRINT_FUNC_NAME("C_EncryptInit")
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST != pkcs11_active_operation) && 
		(PKCS11_CRYPTOLIB_CK_OPERATION_SIGN != pkcs11_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:

			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_RSA_PKCS_OAEP:

			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_DES3_CBC:

			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_AES_CBC:
			
			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		default:

			return CKR_MECHANISM_INVALID;
	}

	switch (pkcs11_active_operation)
	{
		case PKCS11_CRYPTOLIB_CK_OPERATION_NONE:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT;
			break;
		case PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST_ENCRYPT;
			break;
		case PKCS11_CRYPTOLIB_CK_OPERATION_SIGN:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_ENCRYPT;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	CK_RV rv = CKR_ARGUMENTS_BAD;

	DBG_PRINT_FUNC_NAME("C_Encrypt")

	do {
		if (NULL == pData)
			break;

		if (0 >= ulDataLen)
			break;

		if (NULL == pEncryptedData)
			break;
		
		if (NULL == pulEncryptedDataLen)
			break;
		
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;

		rv = CKR_OPERATION_NOT_INITIALIZED;
		if (PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT != pkcs11_active_operation)
			break;

		rv = CKR_SESSION_HANDLE_INVALID;
		if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
			break;

		rv = CKR_BUFFER_TOO_SMALL;
		if (ulDataLen > *pulEncryptedDataLen)
			break;

		rv = CKR_FUNCTION_FAILED;
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}

#if (1)
		if (transmit(cmd_pso_enc, pData, ulDataLen, pEncryptedData, (uint32_t*)pulEncryptedDataLen)) {
			break;
		}
#else
		if (transmit(cmd_pso_enc, pData, ulDataLen, outBuff, &outDataLen)) {
			break;
		}
		memcpy(pEncryptedData, outBuff, outDataLen);
		*pulEncryptedDataLen = outDataLen;
#endif
		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
		rv = CKR_OK;
	} while (0);

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	DBG_PRINT_FUNC_NAME("C_EncryptUpdate")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart, CK_ULONG_PTR pulLastEncryptedPartLen)
{
	DBG_PRINT_FUNC_NAME("C_EncryptFinal")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_ENCRYPT != pkcs11_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastEncryptedPart)
	{
		switch (pkcs11_active_operation)
		{
			case PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT:
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
				break;
			case PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST_ENCRYPT:
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST;
				break;
			case PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_ENCRYPT:
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_SIGN;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastEncryptedPartLen = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	DBG_PRINT_FUNC_NAME("C_DecryptInit")
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST != pkcs11_active_operation) && 
		(PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY != pkcs11_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	switch (pMechanism->mechanism)
	{
		case CKM_RSA_PKCS:

			if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_RSA_PKCS_OAEP:

			if ((NULL == pMechanism->pParameter) || (sizeof(CK_RSA_PKCS_OAEP_PARAMS) != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_DES3_CBC:

			if ((NULL == pMechanism->pParameter) || (8 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		case CKM_AES_CBC:
			
			if ((NULL == pMechanism->pParameter) || (16 != pMechanism->ulParameterLen))
				return CKR_MECHANISM_PARAM_INVALID;

			if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
				return CKR_KEY_TYPE_INCONSISTENT;

			break;

		default:

			return CKR_MECHANISM_INVALID;
	}

	switch (pkcs11_active_operation)
	{
		case PKCS11_CRYPTOLIB_CK_OPERATION_NONE:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT;
			break;
		case PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_DIGEST;
			break;
		case PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_VERIFY;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv = CKR_ARGUMENTS_BAD;

	DBG_PRINT_FUNC_NAME("C_Decrypt")

	do {
		if (NULL == pEncryptedData)
			break;

		if (0 >= ulEncryptedDataLen)
			break;

		if (NULL == pData)
			break;
		
		if (NULL == pulDataLen)
			break;
		
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;

		rv = CKR_OPERATION_NOT_INITIALIZED;
		if (PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT != pkcs11_active_operation)
			break;

		rv = CKR_SESSION_HANDLE_INVALID;
		if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
			break;
		
		rv = CKR_BUFFER_TOO_SMALL;
		if (ulEncryptedDataLen > *pulDataLen)
			break;
		
		rv = CKR_FUNCTION_FAILED;
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}

		if (transmit(cmd_pso_enc, pEncryptedData, ulEncryptedDataLen, pData, (uint32_t*)pulDataLen)) {
			break;
		}

		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
		rv = CKR_OK;
	} while (0);

	*pulDataLen = ulEncryptedDataLen;

	return rv;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	DBG_PRINT_FUNC_NAME("C_DecryptUpdate")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	DBG_PRINT_FUNC_NAME("C_DecryptFinal")

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_DIGEST != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_VERIFY != pkcs11_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulLastPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pLastPart)
	{
		switch (pkcs11_active_operation)
		{
			case PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT:
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
				break;
			case PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_DIGEST:
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST;
				break;
			case PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_VERIFY:
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY;
				break;
			default:
				return CKR_FUNCTION_FAILED;
		}
	}

	*pulLastPartLen = 0;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT != pkcs11_active_operation) && 
		(PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT != pkcs11_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_SHA_1 != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	switch (pkcs11_active_operation)
	{
		case PKCS11_CRYPTOLIB_CK_OPERATION_NONE:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST;
			break;
		case PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST_ENCRYPT;
			break;
		case PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT:
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_DIGEST;
			break;
		default:
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Digest)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pDigest)
	{
		if (sizeof(hash) > *pulDigestLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pDigest, hash, sizeof(hash));
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
		}
	}

	*pulDigestLen = sizeof(hash);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_OBJECT_HANDLE_INVALID;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_BYTE hash[20] = { 0x7B, 0x50, 0x2C, 0x3A, 0x1F, 0x48, 0xC8, 0x60, 0x9A, 0xE2, 0x12, 0xCD, 0xFB, 0x63, 0x9D, 0xEE, 0x39, 0x67, 0x3F, 0x5E };

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST != pkcs11_active_operation) && 
		(PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_active_operation) && 
		(PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_DIGEST != pkcs11_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pDigest)
	{
		if (sizeof(hash) > *pulDigestLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pDigest, hash, sizeof(hash));

			switch (pkcs11_active_operation)
			{
				case PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST:
					pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
					break;
				case PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST_ENCRYPT:
					pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT;
					break;
				case PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_DIGEST:
					pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT;
					break;
				default:
					return CKR_FUNCTION_FAILED;
			}
		}
	}

	*pulDigestLen = sizeof(hash);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT != pkcs11_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	if (PKCS11_CRYPTOLIB_CK_OPERATION_NONE == pkcs11_active_operation)
		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_SIGN;
	else
		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_ENCRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Sign)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_SIGN != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (sizeof(signature) > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, signature, sizeof(signature));
			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
		}
	}

	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_SIGN != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_SIGN != pkcs11_active_operation) && 
		(PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_ENCRYPT != pkcs11_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (sizeof(signature) > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			memcpy(pSignature, signature, sizeof(signature));

			if (PKCS11_CRYPTOLIB_CK_OPERATION_SIGN == pkcs11_active_operation)
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
			else
				pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_ENCRYPT;
		}
	}

	*pulSignatureLen = sizeof(signature);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_RECOVER != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pSignature)
	{
		if (ulDataLen > *pulSignatureLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulDataLen; i++)
				pSignature[i] = pData[i] ^ 0xAB;

			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
		}
	}

	*pulSignatureLen = ulDataLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT != pkcs11_active_operation))
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if ((CKM_RSA_PKCS == pMechanism->mechanism) || (CKM_SHA1_RSA_PKCS == pMechanism->mechanism))
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	if (PKCS11_CRYPTOLIB_CK_OPERATION_NONE == pkcs11_active_operation)
		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY;
	else
		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_VERIFY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_Verify)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (sizeof(signature) != ulSignatureLen)
		return CKR_SIGNATURE_LEN_RANGE;

	if (0 != memcmp(pSignature, signature, sizeof(signature)))
		return CKR_SIGNATURE_INVALID;

	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_BYTE signature[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY != pkcs11_active_operation) &&
		(PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_VERIFY != pkcs11_active_operation))
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (sizeof(signature) != ulSignatureLen)
		return CKR_SIGNATURE_LEN_RANGE;

	if (0 != memcmp(pSignature, signature, sizeof(signature)))
		return CKR_SIGNATURE_INVALID;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY == pkcs11_active_operation)
		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
	else
		pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_NONE != pkcs11_active_operation)
		return CKR_OPERATION_ACTIVE;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS == pMechanism->mechanism)
	{
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			return CKR_MECHANISM_PARAM_INVALID;

		if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hKey)
			return CKR_KEY_TYPE_INCONSISTENT;
	}
	else
	{
		return CKR_MECHANISM_INVALID;
	}

	pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY_RECOVER;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_VERIFY_RECOVER != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSignature)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSignatureLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulDataLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pData)
	{
		if (ulSignatureLen > *pulDataLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulSignatureLen; i++)
				pData[i] = pSignature[i] ^ 0xAB;

			pkcs11_active_operation = PKCS11_CRYPTOLIB_CK_OPERATION_NONE;
		}
	}

	*pulDataLen = ulSignatureLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_DIGEST_ENCRYPT != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_DIGEST != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_SIGN_ENCRYPT != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pEncryptedPart)
	{
		if (ulPartLen > *pulEncryptedPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulPartLen; i++)
				pEncryptedPart[i] = pPart[i] ^ 0xAB;
		}
	}

	*pulEncryptedPartLen = ulPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (PKCS11_CRYPTOLIB_CK_OPERATION_DECRYPT_VERIFY != pkcs11_active_operation)
		return CKR_OPERATION_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pEncryptedPart)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulEncryptedPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pulPartLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL != pPart)
	{
		if (ulEncryptedPartLen > *pulPartLen)
		{
			return CKR_BUFFER_TOO_SMALL;
		}
		else
		{
			for (i = 0; i < ulEncryptedPartLen; i++)
				pPart[i] = pEncryptedPart[i] ^ 0xAB;
		}
	}

	*pulPartLen = ulEncryptedPartLen;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;
	CK_RV rv = CKR_ARGUMENTS_BAD;

	do {
		if (NULL == pMechanism)
			break;
			
		if (NULL == pTemplate)
			break;

		if (0 >= ulCount)
			break;

		if (NULL == phKey)
			break;
		
		rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		if (CK_FALSE == pkcs11_initialized)
			break;

		rv = CKR_SESSION_HANDLE_INVALID;
		if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
			break;
		
		rv = CKR_MECHANISM_INVALID;
		if (CKM_DES3_KEY_GEN != pMechanism->mechanism)
			break;
		
		rv = CKR_MECHANISM_PARAM_INVALID;
		if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
			break;
		
		rv = CKR_ATTRIBUTE_VALUE_INVALID;

		printf("template {\n");
		for (i = 0; i < ulCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				break;
	
			if (0 >= pTemplate[i].ulValueLen)
				break;
			
			printf("\tvalue: %.*s", (int)pTemplate[i].ulValueLen, (char*)pTemplate[i].pValue);
		}
		printf("}\n");
		rv = CKR_FUNCTION_FAILED;
		if (transmit(cmd_select_app, AID, aidLen, NULL, NULL)) {
			break;
		}

		if (transmit(cmd_crd_create_aes, NULL, 0, NULL, NULL)) {
			break;
		}

		rv = CKR_OK;
	} while (0);


	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return rv;
}


/**
 * @brief generates a public/private key pair, creating new key objects.
 * @param hSession  is the session’s handle
 * @param pMechanism the key generation mechanism
 * @param pPublicKeyTemplate the template for the public key
 * @param ulPublicKeyAttributeCount the number of attributes in the public-key template
 * @param pPrivateKeyTemplate the template for the private key
 * @param ulPrivateKeyAttributeCount the number of attributes in the private-key template
 * @param phPublicKey the location that receives the handle of the new public key
 * @param phPrivateKey the location that receives the handle of the new private key
 */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)(CK_SESSION_HANDLE hSession,
											CK_MECHANISM_PTR pMechanism,
											CK_ATTRIBUTE_PTR pPublicKeyTemplate,
											CK_ULONG ulPublicKeyAttributeCount,
											CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
											CK_ULONG ulPrivateKeyAttributeCount,
											CK_OBJECT_HANDLE_PTR phPublicKey,
											CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_ECDSA_KEY_PAIR_GEN != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;
	
	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (NULL == pPublicKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPublicKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pPrivateKeyTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulPrivateKeyAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPublicKey)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phPrivateKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulPublicKeyAttributeCount; i++)
	{
		if (NULL == pPublicKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPublicKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	for (i = 0; i < ulPrivateKeyAttributeCount; i++)
	{
		if (NULL == pPrivateKeyTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pPrivateKeyTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phPublicKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY;
	*phPrivateKey = PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey, CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_BYTE wrappedKey[10] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PUBLIC_KEY != hWrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL != pWrappedKey)
	{
		if (sizeof(wrappedKey) > *pulWrappedKeyLen)
			return CKR_BUFFER_TOO_SMALL;
		else
			memcpy(pWrappedKey, wrappedKey, sizeof(wrappedKey));
	}

	*pulWrappedKeyLen = sizeof(wrappedKey);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey, CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_RSA_PKCS != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL != pMechanism->pParameter) || (0 != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_PRIVATE_KEY != hUnwrappingKey)
		return CKR_KEY_HANDLE_INVALID;

	if (NULL == pWrappedKey)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulWrappedKeyLen)
		return CKR_ARGUMENTS_BAD;

	if (NULL == pTemplate)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulAttributeCount)
		return CKR_ARGUMENTS_BAD;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	for (i = 0; i < ulAttributeCount; i++)
	{
		if (NULL == pTemplate[i].pValue)
			return CKR_ATTRIBUTE_VALUE_INVALID;

		if (0 >= pTemplate[i].ulValueLen)
			return CKR_ATTRIBUTE_VALUE_INVALID;
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_ULONG i = 0;

	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pMechanism)
		return CKR_ARGUMENTS_BAD;

	if (CKM_XOR_BASE_AND_DATA != pMechanism->mechanism)
		return CKR_MECHANISM_INVALID;

	if ((NULL == pMechanism->pParameter) || (sizeof(CK_KEY_DERIVATION_STRING_DATA) != pMechanism->ulParameterLen))
		return CKR_MECHANISM_PARAM_INVALID;

	if (PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY != hBaseKey)
		return CKR_OBJECT_HANDLE_INVALID;

	if (NULL == phKey)
		return CKR_ARGUMENTS_BAD;

	if ((NULL != pTemplate) && (0 < ulAttributeCount))
	{
		for (i = 0; i < ulAttributeCount; i++)
		{
			if (NULL == pTemplate[i].pValue)
				return CKR_ATTRIBUTE_VALUE_INVALID;

			if (0 >= pTemplate[i].ulValueLen)
				return CKR_ATTRIBUTE_VALUE_INVALID;
		}
	}

	*phKey = PKCS11_MOCK_CK_OBJECT_HANDLE_SECRET_KEY;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == pSeed)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulSeedLen)
		return CKR_ARGUMENTS_BAD;

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)(CK_SESSION_HANDLE hSession, CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;

	if (NULL == RandomData)
		return CKR_ARGUMENTS_BAD;

	if (0 >= ulRandomLen)
		return CKR_ARGUMENTS_BAD;

	memset(RandomData, 1, ulRandomLen);

	return CKR_OK;
}


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)(CK_SESSION_HANDLE hSession)
{
	if (CK_FALSE == pkcs11_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if ((CK_FALSE == pkcs11_session_opened) || (PKCS11_CRYPTOLIB_CK_SESSION_ID != hSession))
		return CKR_SESSION_HANDLE_INVALID;
	
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	DBG_PRINT_FUNC_NAME("C_WaitForSlotEvent")

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

