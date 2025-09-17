#include "iso7816.h"
#include <string.h>

static Apdu_t apdu;

uint8_t AID[] = {0xA0, 0x00, 0x00, 0x00, 0x01, 0x01};

static uint8_t* cmdList[] = {
	[cmd_select_app]        = (uint8_t[]){0x00, 0xA4, 0x04, 0x00, 0x06},
	[cmd_get_data]          = (uint8_t[]){0x00, 0xCA, 0x00, 0xFF, 0x00},

	// change reference data subcommands
	[cmd_crd_set_puk]       = (uint8_t[]){0x00, 0x25, 0x00, 0x01, 0x00},
	[cmd_crd_set_pin]       = (uint8_t[]){0x00, 0x25, 0x00, 0x02, 0x00},
	[cmd_crd_upd_pin]       = (uint8_t[]){0x00, 0x25, 0x00, 0x03, 0x00},
	[cmd_crd_set_label]     = (uint8_t[]){0x00, 0x25, 0x00, 0x04, 0x00},
	[cmd_crd_create_aes_km] = (uint8_t[]){0x00, 0x25, 0x00, 0x05, 0x00},
	[cmd_crd_create_aes]    = (uint8_t[]){0x00, 0x25, 0x01, 0x05, 0x00},
	[cmd_crd_gen_ecdsa]     = (uint8_t[]){0x00, 0x25, 0x01, 0x07, 0x00},

	// Security status related operations
	[cmd_verify]            = (uint8_t[]){0x00, 0x20, 0x00, 0x00, 0x00},
	[cmd_verify_reset]      = (uint8_t[]){0x00, 0x20, 0xFF, 0x00, 0x00},

	// Perform security operations
	[cmd_pso_enc]           = (uint8_t[]){0x00, 0x2A, 0x84, 0x80, 0x00},
	[cmd_pso_dec]           = (uint8_t[]){0x00, 0x2A, 0x80, 0x84, 0x00},
	
	// CLS management
	[cmd_lcs_activated]     = (uint8_t[]){0x00, 0x44, 0x00, 0x00, 0x00},

	[cmd_get_response]      = (uint8_t[]){0x00, 0xC0, 0x00, 0x00, 0x00},
};

static uint8_t
fetch_sw(void)
{
	memcpy(&apdu.sw, &apdu.resp[apdu.respLen - 2], 2);

	if ((apdu.sw & 0xFF00) == 0x6100) {
		memcpy(apdu.cmd, cmdList[cmd_get_response], 5);
		apdu.cmd[OFFSET_LC] = apdu.resp[apdu.respLen - 1];

		apdu.cmdLen = 5;
		return 1;
	}

	return 0;
}

static int32_t
send_command(void* buff, uint16_t len)
{
	int32_t rv = 1;
	apdu.respLen = RAPDU_LENGTH;

	DBG_PRINT_APDU(apdu.cmd, apdu.cmdLen, 1)
	rv = sc_apdu_transmit(apdu.cmd, apdu.cmdLen, apdu.resp, &apdu.respLen);
	DBG_PRINT_APDU(apdu.resp, apdu.respLen, 0)

	return rv;
}

int32_t
transmit(cmdEnum cmdID, void* inBuff, uint16_t inLen, void* outBuff, uint16_t outLen)
{
	int32_t rv = 1;

	memcpy(apdu.cmd, cmdList[cmdID], apdu.cmdLen);

	switch (cmdID) {
		case cmd_select_app:
			apdu.cmd[OFFSET_LC] = sizeof(AID);
			memcpy(&apdu.cmd[OFFSET_CDATA], AID, sizeof(AID));
			apdu.cmdLen = 5 + sizeof(AID);
		break;
		case cmd_get_data:        

		case cmd_crd_set_puk:     
		case cmd_crd_set_pin:     
		case cmd_crd_upd_pin:     
		case cmd_crd_set_label:   
		case cmd_crd_create_aes_km: 
		case cmd_crd_create_aes:  
		case cmd_crd_gen_ecdsa:   

		case cmd_verify:          
		case cmd_verify_reset:    

		case cmd_pso_enc:         
		case cmd_pso_dec:         

		case cmd_lcs_activated:   
		case cmd_get_response:
		break;
		default: return rv;
	}

	do {
		if (apdu.cmdLen > CAPDU_LENGTH) {
			break;
		}

		send_command(inBuff, inLen);
		if (fetch_sw()) {
			continue;
		}

		memcpy((uint8_t*)outBuff, apdu.resp, apdu.respLen);
		rv = 0;
	} while (0);

	return rv;
}

#if(0)
uint32_t
get_response(void)
{
	int32_t rv = 0;
	apdu.cmdLen = cmdList[cmd_get_response].len;

	do {
		if (0x6100 != (apdu.sw & 0xFF00)) {
			break;
		}

		cmdList[cmd_get_response].cmd[OFFSET_LC] = apdu.sw & 0x00FF;
		// get_resp[4] = apdu.sw & 0x00FF;
		memcpy(apdu.cmd, cmdList[cmd_get_response].cmd, apdu.cmdLen);

		rv = 1;
		if (transmit(apdu)) {
			break;
		}

		rv = 0;
	} while (0);

	return rv;
}
#endif