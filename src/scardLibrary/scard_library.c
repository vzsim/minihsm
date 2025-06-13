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
}

LONG
sc_create_ctx(Apdu_t* apdu)
{
	init_apdu(apdu);
	memset(readersState, 0x00, sizeof(SCARD_READERSTATE));
	LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &ctx);

	if (rv != SCARD_S_SUCCESS) {
		printf("ERROR: failed to establish context. "
				"Reason: %s\n", pcsc_stringify_error(rv));
		return rv;
	}
	
	printf("Connection to PCSC established.\n    ctx: %08lX\n", ctx);
	return rv;
}

void
sc_delete_ctx(void)
{
	if (ctx) {
		LONG rv = SCardReleaseContext(ctx);
		if (rv != SCARD_S_SUCCESS) {
			printf("WARNING: failed to release context.\n"
					"Reason: %s\n", pcsc_stringify_error(rv));
		}
	}

	if (readersList != NULL) {
		free(readersList);
	}

	printf("Connection to PCSC closed.\n");
}

LONG
sc_get_available_readers(void)
{
	// Get the length of the buffer required for the name list of available readers
	LONG rv = SCardListReaders(ctx, NULL, NULL, &readersListLen);
	if (rv != SCARD_S_SUCCESS) {
		printf("ERROR: failed to retrieve a list of readers. "
				"Reason: %s\n", pcsc_stringify_error(rv));
		return rv;
	}

	// allocate buffer for the name list of available readers
	readersList = malloc(readersListLen);
	if (NULL == readersList) {
		printf("ERROR: failed to allocate memory for a list of readers.\n");
		return rv;
	}

	rv = SCardListReaders(ctx, NULL, readersList, &readersListLen);
	if (rv != SCARD_S_SUCCESS) {
		printf("ERROR: failed to retrieve a list of readers. "
				"Reason: %s\n", pcsc_stringify_error(rv));
		return rv;
	}

	print_available_readers();

	return rv;
}

LONG
sc_get_reader_status(void)
{
	char  friendlyName[MAX_READERNAME] = {0};
	DWORD friendlyNameLen = MAX_READERNAME;

	BYTE  atr[MAX_ATR_SIZE] = {0};
	DWORD atrLen = MAX_ATR_SIZE;

	DWORD readerState = 0;
	LONG rv = SCardStatus(
		connHandle, friendlyName,
		&friendlyNameLen, &readerState,
		&connProtocol,
		atr,
		&atrLen
	);

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

LONG
sc_apdu_transmit(BYTE* cmd, DWORD cmdLen)
{
	BYTE recvBuff[255] = {0};
	DWORD recvBuffLen = sizeof(recvBuff);

	printf("    >> ");
	print_bytes(cmd, cmdLen);

	LONG rv = SCardTransmit(connHandle, SCARD_PCI_T1, cmd, cmdLen, NULL, recvBuff, &recvBuffLen);
	if (rv != SCARD_S_SUCCESS) {
		printf("ERROR: failed to transmit data. "
				"Reason: %s\nSize expected: %ld\n", pcsc_stringify_error(rv), recvBuffLen);
		return rv;
	}

	printf("    << ");
	print_bytes(recvBuff, recvBuffLen);
	
	return rv;
}

LONG
sc_card_connect(void)
{
	readersState[0].szReader = &readersList[0];
	readersState[0].dwCurrentState = SCARD_STATE_EMPTY;

	// Blocks until either the card is inserted or 10 milliseconds elapsed.
	LONG rv = SCardGetStatusChange(ctx, 10, readersState, 1);
	if (rv != SCARD_S_SUCCESS) {
		printf("ERROR: SCardGetStatusChange() call failed. "
				"Reason: %s\n", pcsc_stringify_error(rv));
		return rv;
	}
	
	rv = SCardConnect(ctx, readersList, SCARD_SHARE_EXCLUSIVE,
							SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
							&connHandle, &connProtocol);

	if (rv != SCARD_S_SUCCESS) {
		printf("ERROR: failed to establish connection with the card reader. "
				"Reason: %s\n", pcsc_stringify_error(rv));
		return rv;
	} else {
		const char* temp = connProtocol == SCARD_PROTOCOL_T0 ? "T=0" : "T=1";
		printf("    Card inserted.\n    connProtocol: %s\n    connHandle: %08lX\n",
			temp, connHandle);
	}

	return rv;
}

LONG
sc_card_disconnect(void)
{
	LONG rv = SCARD_S_SUCCESS;
	if (connHandle) {
		rv = SCardDisconnect(connHandle, SCARD_UNPOWER_CARD);
		if (rv != SCARD_S_SUCCESS) {
			printf("ERROR: failed to disconnect the card reader. "
					"Reason: %s\n", pcsc_stringify_error(rv));
		}
	}

	return rv;
}


// =================== UTILS =================== //

uint8_t
stringify_hex(const char* string, uint8_t outBuff[CAPDU_LENGTH], uint32_t* outLen)
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