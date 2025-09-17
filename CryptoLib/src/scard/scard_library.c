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