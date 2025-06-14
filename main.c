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

	rv = sc_apdu_transmit("00a40400", &apdu);
	if (rv) {
		sc_card_disconnect();
		sc_delete_ctx();
		return 1;
	}

	rv = sc_apdu_transmit("00a4040006a00000000101", &apdu);
	if (rv) {
		sc_card_disconnect();
		sc_delete_ctx();
		return 1;
	}

	sc_card_disconnect();
	sc_delete_ctx();

	return 0;
}