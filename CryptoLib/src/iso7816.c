#include "iso7816.h"
#include <string.h>
#include "scard_library.h"

static Apdu_t apdu;
static uint8_t hasResponse = 0;

uint8_t* cmdList[] = {
	[cmd_select_app]        = (uint8_t[]){0x00, 0xA4, 0x04, 0x00, 0x00},
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
	[cmd_verify_puk]        = (uint8_t[]){0x00, 0x20, 0x00, 0x00, 0x00},
	[cmd_verify_pin]        = (uint8_t[]){0x00, 0x20, 0x00, 0x01, 0x00},
	[cmd_verify_reset]      = (uint8_t[]){0x00, 0x20, 0xFF, 0x00, 0x00},

	// Perform security operations
	[cmd_pso_enc]           = (uint8_t[]){0x00, 0x2A, 0x84, 0x80, 0x00},
	[cmd_pso_dec]           = (uint8_t[]){0x00, 0x2A, 0x80, 0x84, 0x00},
	
	// CLS management
	[cmd_lcs_activated]     = (uint8_t[]){0x00, 0x44, 0x30, 0x00, 0x00},
	[cmd_lcs_deactivated]   = (uint8_t[]){0x00, 0x04, 0x30, 0x00, 0x00},
	[cmd_lcs_terminated]    = (uint8_t[]){0x00, 0xE6, 0x30, 0x00, 0x00},

	[cmd_get_response]      = (uint8_t[]){0x00, 0xC0, 0x00, 0x00, 0x00},
};

static uint8_t
fetch_sw(void)
{
	apdu.sw1 = apdu.resp[apdu.respLen - 2];
	apdu.sw2 = apdu.resp[apdu.respLen - 1];

	if (apdu.sw1  == 0x61) {
		memcpy(apdu.cmd, cmdList[cmd_get_response], 5);
		apdu.cmd[OFFSET_LC] = apdu.sw2;

		apdu.cmdLen = 5;
		return 1;
	}

	return 0;
}

static int32_t
send_command(void)
{
	int32_t rv = 1;
	apdu.respLen = RAPDU_LENGTH;

	// DBG_PRINT_APDU(apdu.cmd, apdu.cmdLen, 1)
	rv = sc_apdu_transmit(apdu.cmd, apdu.cmdLen, apdu.resp, &apdu.respLen);
	// DBG_PRINT_APDU(apdu.resp, apdu.respLen, 0)

	return rv;
}

int32_t
transmit(cmdEnum cmdID, void* inBuff, uint16_t inLen, void* outBuff, uint16_t* outLen)
{
	int32_t rv = 1;

	// First of all, using a cmdID param copy requested APDU into apdu.cmd buffer
	memcpy(apdu.cmd, cmdList[cmdID], APDU_HEADER_LENGTH);

	switch (cmdID) {
		case cmd_select_app: {
			apdu.cmd[OFFSET_LC] = inLen;
			memcpy(&apdu.cmd[OFFSET_CDATA], inBuff, inLen);
			apdu.cmdLen = APDU_HEADER_LENGTH + inLen;
		} break;
		case cmd_get_data: {
			// nothing to send to the token in CDATA for this command.
			apdu.cmdLen = APDU_HEADER_LENGTH;
		} break;

		case cmd_crd_set_puk: {
			apdu.cmd[OFFSET_LC]        = inLen + 2; // '2' is for 0x81 and LEN fields of the TLV 
			apdu.cmd[OFFSET_CDATA]     = 0x81;
			apdu.cmd[OFFSET_CDATA + 1] = inLen;
			memcpy(&apdu.cmd[OFFSET_CDATA + 2], inBuff, inLen);
			apdu.cmdLen = APDU_HEADER_LENGTH + inLen + 2;
		} break;
		case cmd_crd_set_pin: {
			apdu.cmd[OFFSET_LC]        = inLen + 2; // '2' is for 0x81 and LEN fields of the TLV 
			apdu.cmd[OFFSET_CDATA]     = 0x81;
			apdu.cmd[OFFSET_CDATA + 1] = inLen;
			memcpy(&apdu.cmd[OFFSET_CDATA + 2], inBuff, inLen);
			apdu.cmdLen = APDU_HEADER_LENGTH + inLen + 2;
		} break;
		case cmd_crd_upd_pin: {} break;
		case cmd_crd_set_label: {
			apdu.cmd[OFFSET_LC]        = inLen + 2; // '2' is for 0x81 and LEN fields of the TLV 
			apdu.cmd[OFFSET_CDATA]     = 0x81;
			apdu.cmd[OFFSET_CDATA + 1] = inLen;
			memcpy(&apdu.cmd[OFFSET_CDATA + 2], inBuff, inLen);
			apdu.cmdLen = APDU_HEADER_LENGTH + inLen + 2;
		} break;
		case cmd_crd_create_aes_km: {} break;
		case cmd_crd_create_aes: {} break;
		case cmd_crd_gen_ecdsa: {} break;

		case cmd_verify_puk:
		case cmd_verify_pin: {
			apdu.cmd[OFFSET_LC] = inLen;
			memcpy(&apdu.cmd[OFFSET_CDATA], inBuff, inLen);
			apdu.cmdLen = APDU_HEADER_LENGTH + inLen;
		} break;
		case cmd_verify_reset: {
			// nothing to send to the token in CDATA for this command.
			apdu.cmdLen = APDU_HEADER_LENGTH;
		} break;

		case cmd_pso_enc: {} break;
		case cmd_pso_dec: {} break;

		case cmd_lcs_activated:
		case cmd_lcs_deactivated:
		case cmd_lcs_terminated: {
			// nothing to send to the token in CDATA for this command.
			apdu.cmdLen = APDU_HEADER_LENGTH;
		} break;
		case cmd_get_response: {} break;

		default: return rv;
	}

	do {
		if (apdu.cmdLen > CAPDU_LENGTH) {
			break;
		}

		send_command();
		if (fetch_sw()) {
			hasResponse = 1;
			continue;
		}
		
		if (hasResponse) {
			hasResponse = 0;
			if ((outBuff == NULL) || (outLen == NULL)) {
				rv = 1;
				break;
			}
			memcpy((uint8_t*)outBuff, apdu.resp, apdu.respLen);
			*outLen = apdu.respLen;
		}
		rv = 0;
		break;
	} while (1);

	return rv;
}

#if defined(CRYPTOKI_DEBUG)

cmd_struct known_commands[] = {

	{{0x00, 0xA4, 0x04, 0x00, 0x00},"SELECT"},
	{{0x00, 0xCA, 0x00, 0xFF, 0x00},"GET DATA"},
	{{0x00, 0x25, 0x00, 0x01, 0x00},"SET PUK"},
	{{0x00, 0x25, 0x00, 0x02, 0x00},"SET PIN"},
	{{0x00, 0x25, 0x00, 0x03, 0x00},"UPDATE SET PIN"},
	{{0x00, 0x25, 0x00, 0x04, 0x00},"SET LABEL"},
	{{0x00, 0x25, 0x00, 0x05, 0x00},"CREATE AES KEY USING GIVEN KEY MATERIAL"},
	{{0x00, 0x25, 0x01, 0x05, 0x00},"CREATE AES KEY"},
	{{0x00, 0x25, 0x01, 0x07, 0x00},"GENERATE ECDSA"},
		// Security status related operations
	{{0x00, 0x20, 0x00, 0x00, 0x00},"VERIFY PIN"},
	{{0x00, 0x20, 0xFF, 0x00, 0x00},"RESET PIN"},
	{{0x00, 0x2A, 0x84, 0x80, 0x00},"ENCRYPT"},
	{{0x00, 0x2A, 0x80, 0x84, 0x00},"DECRYPT"},
	{{0x00, 0x44, 0x00, 0x00, 0x00},"LCS: SET ACTIVATED"},
	{{0x00, 0xC0, 0x00, 0x00, 0x00},"GET RESPONSE"},
};

void
print_cmd_name(uint8_t* cmd, uint32_t cmdLen)
{	
	for (uint32_t i = 0; i < sizeof(known_commands) / sizeof(cmd_struct); ++i) {
		if (!memcmp(known_commands[i].cls_ins_p1, cmd, (long unsigned int)4)) {
			printf("%s\n", known_commands[i].str);
			return;
		}
	}

	printf("UNKNOWN COMMAND\n");
}
#endif