#include "scard_library.h"

typedef struct {
	LONG code;
	const char* name;
} errorCode;

static errorCode codes[] = {

	{SCARD_S_SUCCESS, 			"SCARD_S_SUCCESS" },
	{SCARD_F_INTERNAL_ERROR,	"SCARD_F_INTERNAL_ERROR" },
	{SCARD_E_CANCELLED,			"SCARD_E_CANCELLED" },
	{SCARD_E_INVALID_HANDLE,	"SCARD_E_INVALID_HANDLE" },
	{SCARD_E_INVALID_PARAMETER	, "SCARD_E_INVALID_PARAMETER" },
	{SCARD_E_INVALID_TARGET		, "SCARD_E_INVALID_TARGET" },
	{SCARD_E_NO_MEMORY		, "SCARD_E_NO_MEMORY" },
	{SCARD_F_WAITED_TOO_LONG	, "SCARD_F_WAITED_TOO_LONG" },
	{SCARD_E_INSUFFICIENT_BUFFER	, "SCARD_E_INSUFFICIENT_BUFFER" },
	{SCARD_E_UNKNOWN_READER		, "SCARD_E_UNKNOWN_READER" },
	{SCARD_E_TIMEOUT			, "SCARD_E_TIMEOUT" },
	{SCARD_E_SHARING_VIOLATION	, "SCARD_E_SHARING_VIOLATION" },
	{SCARD_E_NO_SMARTCARD		, "SCARD_E_NO_SMARTCARD" },
	{SCARD_E_UNKNOWN_CARD		, "SCARD_E_UNKNOWN_CARD" },
	{SCARD_E_CANT_DISPOSE		, "SCARD_E_CANT_DISPOSE" },
	{SCARD_E_PROTO_MISMATCH		, "SCARD_E_PROTO_MISMATCH" },
	{SCARD_E_NOT_READY		, "SCARD_E_NOT_READY" },
	{SCARD_E_INVALID_VALUE		, "SCARD_E_INVALID_VALUE" },
	{SCARD_E_SYSTEM_CANCELLED	, "SCARD_E_SYSTEM_CANCELLED" },
	{SCARD_F_COMM_ERROR		, "SCARD_F_COMM_ERROR" },
	{SCARD_F_UNKNOWN_ERROR		, "SCARD_F_UNKNOWN_ERROR" },
	{SCARD_E_INVALID_ATR		, "SCARD_E_INVALID_ATR" },
	{SCARD_E_NOT_TRANSACTED		, "SCARD_E_NOT_TRANSACTED" },
	{SCARD_E_READER_UNAVAILABLE	, "SCARD_E_READER_UNAVAILABLE" },
	{SCARD_P_SHUTDOWN		, "SCARD_P_SHUTDOWN" },
	{SCARD_E_PCI_TOO_SMALL		, "SCARD_E_PCI_TOO_SMALL" },
	{SCARD_E_READER_UNSUPPORTED	, "SCARD_E_READER_UNSUPPORTED" },
	{SCARD_E_DUPLICATE_READER	, "SCARD_E_DUPLICATE_READER" },
	{SCARD_E_CARD_UNSUPPORTED	, "SCARD_E_CARD_UNSUPPORTED" },
	{SCARD_E_NO_SERVICE		, "SCARD_E_NO_SERVICE" },
	{SCARD_E_SERVICE_STOPPED	, "	SCARD_E_SERVICE_STOPPED" },
	{SCARD_E_UNEXPECTED		, "SCARD_E_UNEXPECTED" },
	{SCARD_E_UNSUPPORTED_FEATURE	, "SCARD_E_UNSUPPORTED_FEATURE" },
	{SCARD_E_ICC_INSTALLATION	, "SCARD_E_ICC_INSTALLATION" },
	{SCARD_E_ICC_CREATEORDER		, "SCARD_E_ICC_CREATEORDER" },
	{SCARD_E_UNSUPPORTED_FEATURE	, "SCARD_E_UNSUPPORTED_FEATURE" },
	{SCARD_E_DIR_NOT_FOUND		, "SCARD_E_DIR_NOT_FOUND" },
	{SCARD_E_FILE_NOT_FOUND		, "SCARD_E_FILE_NOT_FOUND" },
	{SCARD_E_NO_DIR			, "SCARD_E_NO_DIR" },
	{SCARD_E_NO_FILE			, "SCARD_E_NO_FILE" },
	{SCARD_E_NO_ACCESS, "SCARD_E_NO_ACCESS" },
	{SCARD_E_WRITE_TOO_MANY		, "SCARD_E_WRITE_TOO_MANY" },
	{SCARD_E_BAD_SEEK		, "SCARD_E_BAD_SEEK" },
	{SCARD_E_INVALID_CHV		, "SCARD_E_INVALID_CHV" },
	// {SCARD_E_UNKNOWN_RES_MSG		, "SCARD_E_UNKNOWN_RES_MSG" },
	{SCARD_E_UNKNOWN_RES_MNG	, "SCARD_E_UNKNOWN_RES_MNG" },
	{SCARD_E_NO_SUCH_CERTIFICATE	, "SCARD_E_NO_SUCH_CERTIFICATE" },
	{SCARD_E_CERTIFICATE_UNAVAILABLE	, "SCARD_E_CERTIFICATE_UNAVAILABLE" },
	{SCARD_E_NO_READERS_AVAILABLE    , "SCARD_E_NO_READERS_AVAILABLE" },
	{SCARD_E_COMM_DATA_LOST, "SCARD_E_COMM_DATA_LOST" },
	{SCARD_E_NO_KEY_CONTAINER, "SCARD_E_NO_KEY_CONTAINER" },
	{SCARD_E_SERVER_TOO_BUSY, "SCARD_E_SERVER_TOO_BUSY" }
};

#if defined(CRYPTOKI_DEBUG)
#	define DBG_PRINT_ERROR(rv)	\
	print_error_code(rv);

#	define DBG_PRINT_IFD_NAME()	\
	printf("\n%s\n", connMan.ifdState[i].szReader);
#else
#	define DBG_PRINT_ERROR(rv)
#	define DBG_PRINT_IFD_NAME()
#endif

ConnectionManager_t connMan;

static void
print_error_code(LONG rv)
{
	for (uint32_t i = 0; i < (sizeof(codes) / sizeof(codes[0])); ++i) {
		if (codes[i].code == rv) {
			printf("%s\n", codes[i].name);
			return;
		}
	}
	printf("Unknown SCARD error\n");
}

void
sc_reset_conn_manager(void)
{
	memset(&connMan, 0x00, sizeof(Apdu_t));
	connMan.apdu.respLen = RAPDU_LENGTH;
	connMan.ifdNameLen = MAX_READERNAME;

	for (uint32_t i = 0; i < 4; ++i) {
		connMan.ifdState[i].cbAtr = MAX_ATR_SIZE;
		connMan.ifdState[i].dwCurrentState = SCARD_STATE_EMPTY;
	}
}

LONG
sc_create_ctx(void)
{
	return SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &connMan.ctx);
}

void
sc_delete_ctx(void)
{
	if (connMan.ctx)
		SCardReleaseContext(connMan.ctx);

	if (connMan.ifdList != NULL)
		free(connMan.ifdList);
}

LONG
sc_get_available_readers(void)
{
	LONG rv = SCARD_S_SUCCESS;
	do {
		// Calculating a length required for a buffer to be allocated to hold the list of names of available readers
		rv = SCardListReaders(connMan.ctx, NULL, NULL, &connMan.ifdListLen);
		if (rv != SCARD_S_SUCCESS) {
			break;
		}

		// allocate the buffer.
		rv = SCARD_E_NO_MEMORY;
		connMan.ifdList = malloc(connMan.ifdListLen);
		if (NULL == connMan.ifdList) {
			break;
		}

		rv = SCardListReaders(connMan.ctx, NULL, connMan.ifdList, &connMan.ifdListLen);

		for (uint32_t i = 0, j = 0; i < connMan.ifdListLen - 1; ++j) {
			connMan.ifdState[j].szReader = &connMan.ifdList[i];
			while (connMan.ifdList[i++] != '\0');
		}

	} while (0);

	return rv;
}

LONG
sc_card_connect(void)
{
	LONG rv = SCARD_E_READER_UNAVAILABLE;

	do {
		for (int32_t i = 0; i < 4; ++i) {
			
			// Wait 10 milliseconds for card insertion event.
			rv = SCardGetStatusChange(connMan.ctx, 10, &connMan.ifdState[0], 4);
			if (rv == SCARD_S_SUCCESS) {
				rv = SCardConnect(connMan.ctx, connMan.ifdState[i].szReader, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &connMan.connHdlr, &connMan.connPtcl);
				if (rv == SCARD_S_SUCCESS) {
					DBG_PRINT_IFD_NAME()
					break;
				}
			} else {
				DBG_PRINT_ERROR(rv)
			}
		}
	} while (0);

	return rv;
}

LONG
sc_card_disconnect(void)
{
	LONG rv = SCARD_S_SUCCESS;

	if (connMan.connHdlr) {
		rv = SCardDisconnect(connMan.connHdlr, SCARD_UNPOWER_CARD);
	}

	return rv;
}

LONG
sc_get_reader_status(void)
{
	// DWORD readerState = 0;

	return SCARD_E_NO_SERVICE; //SCardStatus(connMan.connHdlr, connMan.ifdName, &connMan.ifdNameLen, &readerState, &connMan.connPtcl, connMan.ifdState.rgbAtr, &connMan.ifdState.cbAtr);
}

LONG
sc_apdu_transmit(void)
{
	LONG rv = SCARD_E_INVALID_PARAMETER;
	const SCARD_IO_REQUEST* protocolType = NULL;
	connMan.apdu.respLen = RAPDU_LENGTH;
	memset(connMan.apdu.resp, 0x00, RAPDU_LENGTH);

	do {
		if (connMan.apdu.cmdLen > CAPDU_LENGTH) {
			break;
		}

		protocolType = (connMan.connPtcl == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
		rv = SCardTransmit(connMan.connHdlr, protocolType, connMan.apdu.cmd, connMan.apdu.cmdLen, NULL, connMan.apdu.resp, &connMan.apdu.respLen);
	} while (0);

	return rv;
}