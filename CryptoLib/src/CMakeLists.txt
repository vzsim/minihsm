add_library(${ENTRY_POINT} MODULE
	${CMAKE_CURRENT_SOURCE_DIR}/cryptoLib.c
	${CMAKE_CURRENT_SOURCE_DIR}/scard/scard_library.c
	${CMAKE_CURRENT_SOURCE_DIR}/iso7816.c
)

target_include_directories(${ENTRY_POINT}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/scard
	PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/cryptoki
	PUBLIC /usr/include/PCSC
)

add_compile_definitions(
	CRYPTOKI_DEBUG
)

if(CMAKE_HOST_APPLE)
  #target_link_libraries(${ENTRY_POINT} libpcsclite)
  find_library(PCSC_FRAMEWORK PCSC)
  target_link_libraries(${ENTRY_POINT} ${PCSC_FRAMEWORK})
else()
  target_link_libraries(${ENTRY_POINT} pcsclite)
endif()

add_custom_command(TARGET ${ENTRY_POINT}
	POST_BUILD
	COMMAND mv  lib${ENTRY_POINT}.so ${PROJECT_SOURCE_DIR}/build/lib${ENTRY_POINT}.so
	BYPRODUCTS lib${ENTRY_POINT}.so
)