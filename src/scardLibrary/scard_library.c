#include "scard_library.h"

static SCARDCONTEXT ctx = 0;
static LPSTR readersList = NULL;
static DWORD readersListLen = 0;
static SCARDHANDLE connHandle = 0;
static DWORD connProtocol = 0;
static SCARD_READERSTATE readersState[1];

static void
print_available_readers(void)
{
	for (uint32_t i = 0; i < readersListLen - 1; ++i) {
		printf("    Reader #%d: %s\n", (i + 1), &readersList[i]);
		while (readersList[++i] != 0);
	}
}

static void
init_apdu(Apdu_t* apdu)
{
	memset(apdu, 0x00, sizeof(Apdu_t));
	apdu->respLen = RAPDU_LENGTH;
}

LONG
sc_create_ctx(Apdu_t* apdu)
{
	init_apdu(apdu);
	memset(readersState, 0x00, sizeof(SCARD_READERSTATE));

	return SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);
}

void
sc_delete_ctx(void)
{
	if (ctx)
		SCardReleaseContext(ctx);

	if (readersList != NULL)
		free(readersList);
}

LONG
sc_get_available_readers(void)
{
	LONG rv = SCARD_S_SUCCESS;
	do {
		// Get the length of the buffer required for the name list of available readers
		rv = SCardListReaders(ctx, NULL, NULL, &readersListLen);
		if (rv != SCARD_S_SUCCESS) {
			break;
		}

		// allocate buffer for the name list of available readers
		rv = SCARD_E_NO_MEMORY;
		readersList = malloc(readersListLen);
		if (NULL == readersList) {
			break;
		}

		rv = SCardListReaders(ctx, NULL, readersList, &readersListLen);
	} while (0);

	print_available_readers();

	return rv;
}

#if(0)
LONG
sc_get_reader_status(void)
{
	char  friendlyName[MAX_READERNAME] = {0};
	DWORD friendlyNameLen = MAX_READERNAME;

	BYTE  atr[MAX_ATR_SIZE] = {0};
	DWORD atrLen = MAX_ATR_SIZE;

	DWORD readerState = 0;
	LONG rv = SCardStatus(connHandle, friendlyName, &friendlyNameLen, &readerState, &connProtocol, atr, &atrLen);

	if (rv != SCARD_S_SUCCESS) {
		printf("ERROR: failed to retrieve the reader's state. "
				"Reason: %s\n", pcsc_stringify_error(rv));
		return rv;
	}

	printf("    Reader name: %s\n", friendlyName);
	printf("    ATR: ");
	print_bytes(atr, atrLen);

	return rv;

}
#endif

LONG
sc_apdu_transmit(const char* string, Apdu_t* apdu)
{
	LONG rv = SCARD_E_INVALID_VALUE;

	do {
		if (stringify_hex(string, apdu->cmd, &apdu->cmdLen))
			break;
		
		printf("    >> ");
		print_bytes(apdu->cmd, apdu->cmdLen);

		rv = SCardTransmit(connHandle, SCARD_PCI_T1, apdu->cmd, apdu->cmdLen, NULL, apdu->resp, &apdu->respLen);
		if (rv != SCARD_S_SUCCESS)
			break;
		
		printf("    << ");
		print_bytes(apdu->resp, apdu->respLen);	
	} while (0);

	return rv;
}

LONG
sc_card_connect(void)
{
	LONG rv;
	readersState[0].szReader = &readersList[0];
	readersState[0].dwCurrentState = SCARD_STATE_EMPTY;

	do {
		// Blocks until either the card is inserted or 10 milliseconds elapsed.
		rv = SCardGetStatusChange(ctx, 10, readersState, 1);
		if (rv != SCARD_S_SUCCESS)
			break;
		
		rv = SCardConnect(ctx, readersList, SCARD_SHARE_EXCLUSIVE, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &connHandle, &connProtocol);
	} while (0);

	return rv;
}

LONG
sc_card_disconnect(void)
{
	LONG rv = SCARD_E_INVALID_HANDLE;
	if (connHandle) {
		rv = SCardDisconnect(connHandle, SCARD_UNPOWER_CARD);
	}

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