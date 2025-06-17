add_library(${ENTRY_POINT} MODULE
	${CMAKE_CURRENT_SOURCE_DIR}/cryptoLib.c
	${CMAKE_CURRENT_SOURCE_DIR}/scard/scard_library.c
)

target_include_directories(${ENTRY_POINT}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/scard
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cryptoki
	PUBLIC /usr/include/PCSC
)

target_link_libraries(${ENTRY_POINT}
	pcsclite
)