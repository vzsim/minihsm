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
has_response(void)
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

	DBG_PRINT_CMD_NAME(cmdList[cmdID])

	// First of all, using a cmdID param copy requested command into apdu.cmd buffer
	memcpy(apdu.cmd, cmdList[cmdID], APDU_HEADER_LENGTH);
	apdu.cmd[OFFSET_LC] = inLen;
	apdu.cmdLen = APDU_HEADER_LENGTH + inLen;

	switch (cmdID) {
		case cmd_select_app:
			
		case cmd_verify_puk:
		case cmd_verify_pin:
		case cmd_pso_enc:
		case cmd_pso_dec:
		case cmd_verify_reset:
		case cmd_get_data:
		case cmd_lcs_activated:
		case cmd_lcs_deactivated:
		case cmd_lcs_terminated:
			memcpy(&apdu.cmd[OFFSET_CDATA], inBuff, inLen);
		break;
		
		case cmd_crd_set_puk:
		case cmd_crd_set_pin:
		case cmd_crd_upd_pin:
		case cmd_crd_set_label:
		case cmd_crd_create_aes_km:
			apdu.cmd[OFFSET_LC] += 2; // '2' is for the Tag and Len fields of the TLV DO
			apdu.cmd[OFFSET_CDATA] = 0x81;
			apdu.cmd[OFFSET_CDATA + 1] = inLen;
			memcpy(&apdu.cmd[OFFSET_CDATA + 2], inBuff, inLen);
			apdu.cmdLen += 2;
		// fall through
		case cmd_crd_create_aes:
		case cmd_crd_gen_ecdsa: break;

		default: {
			goto _exit;
		}
	}

	if (apdu.cmdLen > CAPDU_LENGTH) {
		goto _exit;
	}

_again:
	send_command();
	if (has_response()) {
		hasResponse = 1;
		goto _again;
	}
	
	if (hasResponse) {
		hasResponse = 0;
		if ((outBuff == NULL) || (outLen == NULL)) {
			goto _exit;
		}

		// Here 'apdu.respLen - 2' is intended to strip out SW bytes
		memcpy((uint8_t*)outBuff, apdu.resp, apdu.respLen - 2);
		*outLen = apdu.respLen - 2;
	}

	if (apdu.sw1 == 0x90) {
		rv = 0;
	}

_exit:
	return rv;
}

int32_t
initialize_token(void)
{
	int32_t rv = 1;
	do {
		if (sc_create_ctx()){
			break;
		}
		
		if (sc_get_available_readers()){
			break;
		}
			
		if (sc_card_connect()){
			break;
		}
			
		rv = 0;
	} while (0);
	return rv;
}

int32_t
finalize_token(void)
{
	int32_t rv = 1;
	do {
		if (sc_card_disconnect())
			break;
		
		sc_delete_ctx();
		rv = 0;
	} while (0);

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

	{{0x00, 0x20, 0x00, 0x00, 0x00},"VERIFY PIN"},
	{{0x00, 0x20, 0xFF, 0x00, 0x00},"RESET PIN"},
	{{0x00, 0x2A, 0x84, 0x80, 0x00},"ENCRYPT"},
	{{0x00, 0x2A, 0x80, 0x84, 0x00},"DECRYPT"},
	{{0x00, 0x44, 0x00, 0x00, 0x00},"LCS: SET ACTIVATED"},
	{{0x00, 0xC0, 0x00, 0x00, 0x00},"GET RESPONSE"},
};

void
print_cmd_name(uint8_t* cmd)
{	
	for (uint32_t i = 0; i < sizeof(known_commands) / sizeof(cmd_struct); ++i) {
		if (!memcmp(known_commands[i].cls_ins_p1, cmd, (long unsigned int)4)) {
			printf("\t***%s***\n", known_commands[i].str);
			return;
		}
	}

	printf("UNKNOWN COMMAND\n");
}
#endif