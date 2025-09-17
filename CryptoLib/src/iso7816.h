#ifndef ISO7816_H
#define ISO7816_H

#include <stdint.h>
#include <stdio.h>

#define CAPDU_LENGTH 261	// CLA INS P1 P1 Lc [255 bytes of CDATA] Le
#define RAPDU_LENGTH 258	// [256 bytes of RDATA] SW1 SW2
#define OFFSET_CLA   0
#define OFFSET_INS   1
#define OFFSET_P1    2
#define OFFSET_P2    3
#define OFFSET_LC    4
#define OFFSET_CDATA 5

typedef struct {
	uint8_t  cmd[CAPDU_LENGTH];
	uint32_t cmdLen;
	uint8_t  resp[RAPDU_LENGTH];
	uint64_t respLen;
	uint16_t sw;
} Apdu_t;

typedef enum {
	cmd_select_app,
	cmd_get_data,
	cmd_crd_set_puk,
	cmd_crd_set_pin,
	cmd_crd_upd_pin,
	cmd_crd_set_label,
	cmd_crd_create_aes_km, // create aes key object using user's key material
	cmd_crd_create_aes,    // create aes key object using PRNG
	cmd_crd_gen_ecdsa,     // generate ECDSA key pair
	
	cmd_verify,
	cmd_verify_reset,


	cmd_pso_enc,
	cmd_pso_dec,

	cmd_lcs_activated,
	cmd_lcs_dectivated,
	cmd_lcs_terminated,

	cmd_get_response,
	cmd_total
} cmdEnum;

extern uint8_t* cmdList[];

uint8_t dataBuff[32 * 1024];

#if defined(CRYPTOKI_DEBUG)

typedef struct {
	uint8_t cls_ins_p1[4];
	const char* str;
} cmd_struct;

static cmd_struct known_commands[] = {
	{{0x00, 0xc0, 0x00, 0x00}, "GET RESPONSE"},
	{{0x00, 0xa4, 0x04, 0x00}, "SELECT"},
	{{0x00, 0xca, 0x00, 0xff}, "GET DATA"},
	{{0x00, 0x25, 0x01, 0x01}, "INIT PIN"},
	{{0x00, 0x25, 0x01, 0x02}, "INIT TOKEN"},
	{{0x00, 0x25, 0x00, 0x00}, "UPDATE TOKEN"},
};

static void
print_cmd_name(uint8_t* cmd, uint32_t cmdLen)
{	
	for (uint32_t i = 0; i < sizeof(known_commands) / sizeof(cmd_struct); ++i) {
		if (!memcmp(known_commands[i].cls_ins_p1, cmd, 4)) {
			printf("%s\n", known_commands[i].str);
			return;
		}
	}

	printf("UNKNOWN COMMAND\n");
}

#	define DBG_PRINT_FUNC_NAME(name)		\
	printf("%s\n", name);

#	define DBG_PRINT_APDU(buff, len, isCmd)	\
	do {									\
		if (isCmd) {						\
			print_cmd_name(buff, len);		\
			printf(">> ");					\
		} else {							\
			printf("<< ");					\
		}									\
		for (uint32_t i = 0; i < len; ++i) {\
			if ((i != 0) && ((i % 32) == 0))\
				printf("\n   ");			\
			printf("%02x ", buff[i]);		\
		}									\
		printf("\n");						\
	} while (0);							

#else
#	define DBG_PRINT_FUNC_NAME(name)
#	define DBG_PRINT_APDU(buff, len, isCmd)
#endif

// extern Apdu_t apdu;

#endif /* ISO7816_H */