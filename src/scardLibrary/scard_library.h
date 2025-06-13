#ifndef SCARD_LIBRARY_H
#define SCARD_LIBRARY_H

#include <pcsclite.h>
#include <winscard.h>
#include <wintypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>


#define CAPDU_LENGTH 261
#define RAPDU_LENGTH 258

typedef struct {
	uint8_t   cmd[CAPDU_LENGTH];
	uint32_t  cmdLen;
	uint8_t   resp[RAPDU_LENGTH];
	uint32_t* respLen;
} Apdu_t;

LONG sc_create_ctx(Apdu_t* apdu);
void sc_delete_ctx(void);
LONG sc_get_available_readers(void);
LONG sc_get_reader_status(void);
LONG sc_apdu_transmit(BYTE* cmd, DWORD cmdLen);
LONG sc_card_connect(void);
LONG sc_card_disconnect(void);

// =================== UTILS =================== //
uint8_t stringify_hex(const char* string, uint8_t outBuff[CAPDU_LENGTH], uint32_t* outLen);
void print_bytes(uint8_t* bytes, uint32_t bytesLen);

#endif /* SCARD_LIBRARY_H */