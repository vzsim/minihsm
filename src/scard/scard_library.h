#ifndef SCARD_LIBRARY_H
#define SCARD_LIBRARY_H

#include <pcsclite.h>
#include <winscard.h>
#include <wintypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


#define CAPDU_LENGTH 261	// CLA INS P1 P1 Lc [255 bytes of CDATA] Le
#define RAPDU_LENGTH 258	// [256 bytes of RDATA] SW1 SW2

typedef struct {
	BYTE  cmd[CAPDU_LENGTH];
	DWORD cmdLen;
	BYTE  resp[RAPDU_LENGTH];
	DWORD respLen;
} Apdu_t;

typedef struct {
	SCARDCONTEXT      ctx;						// SCard connection contex
	SCARDHANDLE       connHdlr;					// Connection handler
	DWORD             connPtcl;					// Connection protocol (T=0/T=1)
	LPSTR             ifdList;					// The list of available readers
	DWORD             ifdListLen;				// The length of list of available readers
	SCARD_READERSTATE ifdState;					// The state of reader connected to
	char              ifdName[MAX_READERNAME];	// The name of this reader
	DWORD             ifdNameLen;
	Apdu_t            apdu;						// CR-APDU
} ConnectionManager_t;

extern ConnectionManager_t connMan;

void init_connection_manager(void);
LONG sc_create_ctx(void);
void sc_delete_ctx(void);
LONG sc_get_available_readers(void);
LONG sc_get_reader_status(void);
LONG sc_apdu_transmit(void);
LONG sc_card_connect(void);
LONG sc_card_disconnect(void);

// =================== UTILS =================== //
uint8_t stringify_hex(const char* string, BYTE outBuff[CAPDU_LENGTH], PDWORD outLen);
void print_bytes(uint8_t* bytes, uint32_t bytesLen);

#endif /* SCARD_LIBRARY_H */