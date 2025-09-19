#ifndef ISO7816_H
#define ISO7816_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPDU_LENGTH 261	// CLA INS P1 P1 Lc [255 bytes of CDATA] Le
#define RAPDU_LENGTH 258	// [256 bytes of RDATA] SW1 SW2
#define APDU_HEADER_LENGTH 5

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
	uint8_t sw1;
	uint8_t sw2;
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

	cmd_verify_puk,
	cmd_verify_pin,
	cmd_verify_reset,

	cmd_pso_enc,
	cmd_pso_dec,

	cmd_lcs_activated,
	cmd_lcs_deactivated,
	cmd_lcs_terminated,

	cmd_get_response,
	cmd_total
} cmdEnum;

extern uint8_t* cmdList[];

int32_t transmit(cmdEnum cmdID, void* inBuff, uint16_t inLen, void* outBuff, uint16_t* outLen);
int32_t initialize_token(void);
int32_t finalize_token(void);

#if defined(CRYPTOKI_DEBUG)

void print_cmd_name(uint8_t* cmd);

typedef struct {
	uint8_t cls_ins_p1[5];
	const char* str;
} cmd_struct;

extern cmd_struct known_commands[];

#	define DBG_PRINT_CMD_NAME(buff)         \
	print_cmd_name(buff);

#	define DBG_PRINT_FUNC_NAME(name)		\
	printf("%s\n", name);

#	define DBG_PRINT_APDU(buff, len, isCmd)	\
	do {									\
		if (isCmd) {						\
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