#ifndef SCARD_LIBRARY_H
#define SCARD_LIBRARY_H

#ifdef __APPLE__
#	include <PCSC/pcsclite.h>
#	include <PCSC/winscard.h>
#	include <PCSC/wintypes.h>
#else
#	include <pcsclite.h>
#	include <winscard.h>
#	include <wintypes.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef struct {
	SCARDCONTEXT      ctx;						// SCard connection contex
	SCARDHANDLE       connHdlr;					// Connection handler
	DWORD             connPtcl;					// Connection protocol (T=0/T=1)
	LPSTR             ifdList;					// The list of available readers
	DWORD             ifdListLen;				// The length of list of available readers
	SCARD_READERSTATE ifdState[16];				// The state of reader connected to
	char              ifdName[MAX_READERNAME];	// The name of this reader
	DWORD             ifdNameLen;
	DWORD             ifdCount;
} ConnectionManager_t;

uint8_t sc_create_ctx(void);
void sc_delete_ctx(void);
uint8_t sc_get_available_readers(void);
uint8_t sc_get_reader_status(void);
uint8_t sc_apdu_transmit(uint8_t* cmd, uint32_t cmdLen, uint8_t* resp, uint32_t* respLen);
uint8_t sc_card_connect(void);
uint8_t sc_card_disconnect(void);

#endif /* SCARD_LIBRARY_H */