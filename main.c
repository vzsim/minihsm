#include "scard_library.h"

int
main(int argc, char* argv[])
{
	LONG rv;
	Apdu_t apdu;

	if (sc_create_ctx(&apdu)) {
		return 1;
	}

	if (sc_get_available_readers()) {
		sc_delete_ctx();
		return 1;
	}

	if (sc_card_connect()) {
		sc_delete_ctx();
		return 1;
	}

	rv = sc_get_reader_status();
	if (rv) {
		sc_card_disconnect();
		sc_delete_ctx();
		return 1;
	}

	if (stringify_hex("00a40400", apdu.cmd, &apdu.cmdLen)) {
		printf("ERROR: something went wrong while hexifying SELECT ISD command.\n");
		return 1;
	} else {
		print_bytes(apdu.cmd, apdu.cmdLen);
	}

	rv = sc_apdu_transmit(apdu.cmd, apdu.cmdLen);
	if (rv) {
		sc_card_disconnect();
		sc_delete_ctx();
		return 1;
	}
	
	if (stringify_hex("00a4040006a00000000101", apdu.cmd, &apdu.cmdLen)) {
		printf("ERROR: something went wrong while hexifying SELECT ISD command.\n");
		return 1;
	}

	rv = sc_apdu_transmit(apdu.cmd, apdu.cmdLen);
	if (rv) {
		sc_card_disconnect();
		sc_delete_ctx();
		return 1;
	}

	sc_card_disconnect();
	sc_delete_ctx();

	return 0;
}