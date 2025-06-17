#include "scard_library.h"

ConnectionManager_t connMan;

void
reset_conn_manager(void)
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
	LONG rv;
	connMan.ifdState.szReader = &connMan.ifdList[0];

	do {
		// Wait 10 milliseconds for card insertion event.
		rv = SCardGetStatusChange(connMan.ctx, 10, &connMan.ifdState, 1);
		if (rv != SCARD_S_SUCCESS)
			break;

		rv = SCardConnect(connMan.ctx, connMan.ifdList, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &connMan.connHdlr, &connMan.connPtcl);
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
	SCARD_IO_REQUEST* protocolType = NULL;
	connMan.apdu.respLen = RAPDU_LENGTH;

	do {
		if (connMan.apdu.cmdLen > CAPDU_LENGTH)
			break;
		
		protocolType = (connMan.connPtcl == SCARD_PROTOCOL_T0) ? SCARD_PCI_T0 : SCARD_PCI_T1;
		rv = SCardTransmit(connMan.connHdlr, protocolType, connMan.apdu.cmd, connMan.apdu.cmdLen, NULL, connMan.apdu.resp, &connMan.apdu.respLen);
	} while (0);

	return rv;
}

// =================== UTILS =================== //

uint8_t
stringify_hex(const char* string, BYTE outBuff[CAPDU_LENGTH], PDWORD outLen)
{
	if(string == NULL) 
		return 1;

	uint32_t index = 0;
	uint32_t wSpaces = 0;
	uint32_t slength = strlen(string);

	memset(outBuff, 0, CAPDU_LENGTH);

	for (index = 0; index < slength; ++index) {
		
		char c = string[index];
		int value = 0;
		
		if(c >= '0' && c <= '9') {
			value = (c - '0');
		} else if (c >= 'A' && c <= 'F') {
			value = (10 + (c - 'A'));
		} else if (c >= 'a' && c <= 'f')
			value = (10 + (c - 'a'));
		else if (c == ' ') {
			wSpaces++;
			continue;
		}
		else {	// encountering a non-hexadecimal character 
			return 1;
		}

		outBuff[(index / 2)] += value << (((index + 1) % 2) * 4);
	}

	*outLen = (index - wSpaces) / 2;

	return 0;
}

void
print_bytes(uint8_t* bytes, uint32_t bytesLen)
{
    for (uint32_t i = 0; i < bytesLen; ++i) {
        printf("%02X ", bytes[i]);
    }

    printf("\n");
}