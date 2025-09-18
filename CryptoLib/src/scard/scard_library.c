#include "scard_library.h"

static IFD_t connMan;

uint8_t
sc_create_ctx(void)
{
	LONG rv;
	memset(&connMan, 0x00, sizeof(IFD_t));

	for (uint32_t i = 0; i < 16; ++i) {
		connMan.ifdState[i].cbAtr = MAX_ATR_SIZE;
		connMan.ifdState[i].dwCurrentState = SCARD_STATE_EMPTY;
	}
	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &connMan.ctx);

	return rv == SCARD_S_SUCCESS ? 0 : 1;
}

void
sc_delete_ctx(void)
{
	if (connMan.ctx) {
		SCardReleaseContext(connMan.ctx);
	}

	if (connMan.list != NULL) {
		free(connMan.list);
	}
}

uint8_t
sc_get_available_readers(void)
{
	LONG rv;
	do {
		// Calculating a length required for a buffer to be allocated to hold the list of names of available readers
		rv = SCardListReaders(connMan.ctx, NULL, NULL, &connMan.listLen);
		if (rv != SCARD_S_SUCCESS) {
			break;
		}

		// allocate the buffer.
		rv = SCARD_E_NO_MEMORY;
		connMan.list = malloc(connMan.listLen);
		if (NULL == connMan.list) {
			break;
		}

		rv = SCardListReaders(connMan.ctx, NULL, connMan.list, &connMan.listLen);

		for (uint32_t i = 0, j = 0; i < connMan.listLen - 1; ++j) {
			connMan.ifdCount++;
			connMan.ifdState[j].szReader = &connMan.list[i];
			while (connMan.list[i++] != '\0');
		}

	} while (0);

	return rv == SCARD_S_SUCCESS ? 0 : 1;
}

uint8_t
sc_card_connect()
{
	LONG rv = SCARD_E_READER_UNAVAILABLE;
	// uint16_t protocol;

	do {
		for (int32_t i = 0; connMan.ifdState[i].szReader != NULL; ++i) {
			
			// Wait 10 milliseconds for card insertion event.
			rv = SCardGetStatusChange(connMan.ctx, 10, &connMan.ifdState[0], connMan.ifdCount);
			if (rv == SCARD_S_SUCCESS) {
				rv = SCardConnect(connMan.ctx, connMan.ifdState[i].szReader, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &connMan.connHdlr, &connMan.connPtcl);
				if (rv == SCARD_S_SUCCESS) {
					DBG_PRINT_IFD_NAME()
					// protocol = (connMan.connPtcl == SCARD_PROTOCOL_T0) ? SCARD_PROTOCOL_T0 : SCARD_PROTOCOL_T1;
					break;
				}
			} else {
				DBG_PRINT_ERROR(rv)
			}
		}
	} while (0);

	return rv == SCARD_S_SUCCESS ? 0 : 1;
}

uint8_t
sc_card_disconnect(void)
{
	LONG rv = SCARD_S_SUCCESS;

	if (connMan.connHdlr) {
		rv = SCardDisconnect(connMan.connHdlr, SCARD_UNPOWER_CARD);
	}

	return rv == SCARD_S_SUCCESS ? 0 : 1;
}

uint8_t
sc_get_reader_status(void)
{
	// DWORD readerState = 0;
	return 1; //SCardStatus(connMan.connHdlr, connMan.ifdName, &connMan.ifdNameLen, &readerState, &connMan.connPtcl, connMan.ifdState.rgbAtr, &connMan.ifdState.cbAtr);
}

uint8_t
sc_apdu_transmit(uint8_t* cmd, uint32_t cmdLen, uint8_t* resp, uint64_t* respLen)
{
	LONG rv;
	const SCARD_IO_REQUEST* protocolType = NULL;
	
	protocolType = (connMan.connPtcl == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
	rv = SCardTransmit(connMan.connHdlr, protocolType, cmd, cmdLen, NULL, resp, respLen);

	return rv == SCARD_S_SUCCESS ? 0 : 1;
}


#if defined(CRYPTOKI_DEBUG)
errorCode codes[] = {

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

void
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
#endif