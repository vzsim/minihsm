#include "iso7816.h"

Apdu_t apdu;

cmd_t cmdList[] = {
	[cmd_select_app]      = {(uint8_t[]){0x00, 0xA4, 0x04, 0x00, 0x06, 0xA0, 0x00, 0x00, 0x00, 0x01, 0x01}, 11},
	[cmd_get_data]        = {(uint8_t[]){0x00, 0xCA, 0x00, 0xFF, 0x00}, 5},
	[cmd_change_ref_data] = {(uint8_t[]){0x00, 0x25, 0x00, 0x00, 0x00}, 5},
	[cmd_verify]          = {(uint8_t[]){0x00, 0x25, 0x00, 0x00, 0x00}, 5},
	[cmd_get_response]    = {(uint8_t[]){0x00, 0xC0, 0x00, 0x00, 0x00}, 5},
};

uint16_t
fetch_sw(Apdu_t* apdu)
{
	return ((((uint16_t)apdu->resp[apdu->respLen - 2] << 8) & 0xFF00)
			|((uint16_t)apdu->resp[apdu->respLen - 1]       & 0x00FF));
}

int32_t
transmit(Apdu_t* apdu)
{
	int32_t rv = 1;

	do {
		if (apdu->cmdLen > CAPDU_LENGTH) {
			break;
		}

		apdu->respLen = RAPDU_LENGTH;
		DBG_PRINT_APDU(apdu->cmd, apdu->cmdLen, 1)
	
		rv = sc_apdu_transmit(apdu->cmd, apdu->cmdLen, apdu->resp, &apdu->respLen);
		apdu->sw = fetch_sw(apdu);

		if (0x6100 != (apdu->sw & 0xFF00)) {
			break;
		} else {
			cmdList[cmd_get_response].cmd[OFFSET_LC] = apdu->sw & 0x00FF;
			memcpy(apdu->cmd, cmdList[cmd_get_response].cmd, apdu->cmdLen);
		}

	} while (0);
	DBG_PRINT_APDU(apdu->resp, apdu->respLen, 0)

	return rv;
}

uint32_t
get_response(Apdu_t* apdu)
{
	int32_t rv = 0;
	apdu->cmdLen = cmdList[cmd_get_response].len;

	do {
		if (0x6100 != (apdu->sw & 0xFF00)) {
			break;
		}
		
		cmdList[cmd_get_response].cmd[OFFSET_LC] = apdu->sw & 0x00FF;
		// get_resp[4] = apdu->sw & 0x00FF;
		memcpy(apdu->cmd, cmdList[cmd_get_response].cmd, apdu->cmdLen);

		rv = 1;
		if (transmit(apdu)) {
			break;
		}

		rv = 0;
	} while (0);

	return rv;
}