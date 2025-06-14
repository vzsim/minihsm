add_library(${SCARD_LIB}
	${CMAKE_CURRENT_SOURCE_DIR}/scard_library.c
)

target_include_directories(${SCARD_LIB}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
	PUBLIC /usr/include/PCSC
)
target_link_libraries(${SCARD_LIB}
	pcsclite
)