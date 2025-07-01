#include "scard_library.h"

ConnectionManager_t connMan;

void
sc_reset_conn_manager(void)
{
	memset(&connMan, 0x00, sizeof(Apdu_t));
	connMan.apdu.respLen = RAPDU_LENGTH;
	connMan.ifdNameLen = MAX_READERNAME;
	connMan.ifdState.cbAtr = MAX_ATR_SIZE;
	connMan.ifdState.dwCurrentState = SCARD_STATE_EMPTY;
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
	} while (0);

	return rv;
}

LONG
sc_card_connect(void)
{
	LONG rv = SCARD_E_READER_UNAVAILABLE;
	

	do {
		for (uint32_t i = 0; i < connMan.ifdListLen - 1; ++i) {
			
			printf("%s\n", &connMan.ifdList[i]);
			connMan.ifdState.szReader = &connMan.ifdList[i];

			// Wait 10 milliseconds for card insertion event.
			rv = SCardGetStatusChange(connMan.ctx, 10, &connMan.ifdState, 1);
			if (rv == SCARD_S_SUCCESS) {
				rv = SCardConnect(connMan.ctx, &connMan.ifdList[i], SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &connMan.connHdlr, &connMan.connPtcl);
				if (rv == SCARD_S_SUCCESS) {
					break;
				}
			} else {
				while (connMan.ifdList[i++] != '\0');
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
	DWORD readerState = 0;

	return SCardStatus(connMan.connHdlr, connMan.ifdName, &connMan.ifdNameLen, &readerState, &connMan.connPtcl, connMan.ifdState.rgbAtr, &connMan.ifdState.cbAtr);
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