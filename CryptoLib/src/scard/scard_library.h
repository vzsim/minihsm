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

uint8_t sc_create_ctx(void);
void sc_delete_ctx(void);
uint8_t sc_get_available_readers(void);
uint8_t sc_get_reader_status(void);
uint8_t sc_apdu_transmit(uint8_t* cmd, uint32_t cmdLen, uint8_t* resp, uint64_t* respLen);
uint8_t sc_card_connect(void);
uint8_t sc_card_disconnect(void);

#endif /* SCARD_LIBRARY_H */