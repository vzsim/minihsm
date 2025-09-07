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
uint8_t sc_card_connect(uint16_t* protocolType);
uint8_t sc_card_disconnect(void);

typedef struct {
	SCARDCONTEXT      ctx;						// SCard connection contex
	SCARDHANDLE       connHdlr;					// Connection handler
	DWORD             connPtcl;					// Connection protocol (T=0/T=1)
	LPSTR             list;					// The list of available readers
	DWORD             listLen;				// The length of list of available readers
	SCARD_READERSTATE ifdState[16];				// The state of reader connected to
	char              ifdName[MAX_READERNAME];	// The name of this reader
	DWORD             ifdNameLen;
	DWORD             ifdCount;
} IFD_t;


#if defined(CRYPTOKI_DEBUG)

#define DBG_PRINT_ERROR(rv)	\
	print_error_code(rv);

#define DBG_PRINT_IFD_NAME()	\
	printf("\n%s\n", connMan.ifdState[i].szReader);

typedef struct {
	LONG code;
	const char* name;
} errorCode;

static errorCode codes[] = {

	{SCARD_S_SUCCESS, 			"SCARD_S_SUCCESS" },
	{SCARD_F_INTERNAL_ERROR,	"SCARD_F_INTERNAL_ERROR" },
	{SCARD_E_CANCELLED,			"SCARD_E_CANCELLED" },
	{SCARD_E_INVALID_HANDLE,	"SCARD_E_INVALID_HANDLE" },
	{SCARD_E_INVALID_PARAMETER	, "SCARD_E_INVALID_PARAMETER" },
	{SCARD_E_INVALID_TARGET		, "SCARD_E_INVALID_TARGET" },
	{SCARD_E_NO_MEMORY		, "SCARD_E_NO_MEMORY" },
	{SCARD_F_WAITED_TOO_LONG	, "SCARD_F_WAITED_TOO_LONG" },
	{SCARD_E_INSUFFICIENT_BUFFER	, "SCARD_E_INSUFFICIENT_BUFFER" },
	{SCARD_E_UNKNOWN_READER		, "SCARD_E_UNKNOWN_READER" },
	{SCARD_E_TIMEOUT			, "SCARD_E_TIMEOUT" },
	{SCARD_E_SHARING_VIOLATION	, "SCARD_E_SHARING_VIOLATION" },
	{SCARD_E_NO_SMARTCARD		, "SCARD_E_NO_SMARTCARD" },
	{SCARD_E_UNKNOWN_CARD		, "SCARD_E_UNKNOWN_CARD" },
	{SCARD_E_CANT_DISPOSE		, "SCARD_E_CANT_DISPOSE" },
	{SCARD_E_PROTO_MISMATCH		, "SCARD_E_PROTO_MISMATCH" },
	{SCARD_E_NOT_READY		, "SCARD_E_NOT_READY" },
	{SCARD_E_INVALID_VALUE		, "SCARD_E_INVALID_VALUE" },
	{SCARD_E_SYSTEM_CANCELLED	, "SCARD_E_SYSTEM_CANCELLED" },
	{SCARD_F_COMM_ERROR		, "SCARD_F_COMM_ERROR" },
	{SCARD_F_UNKNOWN_ERROR		, "SCARD_F_UNKNOWN_ERROR" },
	{SCARD_E_INVALID_ATR		, "SCARD_E_INVALID_ATR" },
	{SCARD_E_NOT_TRANSACTED		, "SCARD_E_NOT_TRANSACTED" },
	{SCARD_E_READER_UNAVAILABLE	, "SCARD_E_READER_UNAVAILABLE" },
	{SCARD_P_SHUTDOWN		, "SCARD_P_SHUTDOWN" },
	{SCARD_E_PCI_TOO_SMALL		, "SCARD_E_PCI_TOO_SMALL" },
	{SCARD_E_READER_UNSUPPORTED	, "SCARD_E_READER_UNSUPPORTED" },
	{SCARD_E_DUPLICATE_READER	, "SCARD_E_DUPLICATE_READER" },
	{SCARD_E_CARD_UNSUPPORTED	, "SCARD_E_CARD_UNSUPPORTED" },
	{SCARD_E_NO_SERVICE		, "SCARD_E_NO_SERVICE" },
	{SCARD_E_SERVICE_STOPPED	, "	SCARD_E_SERVICE_STOPPED" },
	{SCARD_E_UNEXPECTED		, "SCARD_E_UNEXPECTED" },
	{SCARD_E_UNSUPPORTED_FEATURE	, "SCARD_E_UNSUPPORTED_FEATURE" },
	{SCARD_E_ICC_INSTALLATION	, "SCARD_E_ICC_INSTALLATION" },
	{SCARD_E_ICC_CREATEORDER		, "SCARD_E_ICC_CREATEORDER" },
	{SCARD_E_UNSUPPORTED_FEATURE	, "SCARD_E_UNSUPPORTED_FEATURE" },
	{SCARD_E_DIR_NOT_FOUND		, "SCARD_E_DIR_NOT_FOUND" },
	{SCARD_E_FILE_NOT_FOUND		, "SCARD_E_FILE_NOT_FOUND" },
	{SCARD_E_NO_DIR			, "SCARD_E_NO_DIR" },
	{SCARD_E_NO_FILE			, "SCARD_E_NO_FILE" },
	{SCARD_E_NO_ACCESS, "SCARD_E_NO_ACCESS" },
	{SCARD_E_WRITE_TOO_MANY		, "SCARD_E_WRITE_TOO_MANY" },
	{SCARD_E_BAD_SEEK		, "SCARD_E_BAD_SEEK" },
	{SCARD_E_INVALID_CHV		, "SCARD_E_INVALID_CHV" },
	// {SCARD_E_UNKNOWN_RES_MSG		, "SCARD_E_UNKNOWN_RES_MSG" },
	{SCARD_E_UNKNOWN_RES_MNG	, "SCARD_E_UNKNOWN_RES_MNG" },
	{SCARD_E_NO_SUCH_CERTIFICATE	, "SCARD_E_NO_SUCH_CERTIFICATE" },
	{SCARD_E_CERTIFICATE_UNAVAILABLE	, "SCARD_E_CERTIFICATE_UNAVAILABLE" },
	{SCARD_E_NO_READERS_AVAILABLE    , "SCARD_E_NO_READERS_AVAILABLE" },
	{SCARD_E_COMM_DATA_LOST, "SCARD_E_COMM_DATA_LOST" },
	{SCARD_E_NO_KEY_CONTAINER, "SCARD_E_NO_KEY_CONTAINER" },
	{SCARD_E_SERVER_TOO_BUSY, "SCARD_E_SERVER_TOO_BUSY" }
};

static void
print_error_code(LONG rv)
{
	for (uint32_t i = 0; i < (sizeof(codes) / sizeof(codes[0])); ++i) {
		if (codes[i].code == rv) {
			printf("%s\n", codes[i].name);
			return;
		}
	}
	printf("Unknown SCARD error\n");
}

#else
#	define DBG_PRINT_ERROR(rv)
#	define DBG_PRINT_IFD_NAME()
#endif

#endif /* SCARD_LIBRARY_H */