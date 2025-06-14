cmake_minimum_required(VERSION 3.20)
project(SCardApp VERSION 0.1)

set(ENTRY_POINT "SCardApp")
set(SCARD_LIB   "scardHdlr")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O0 -g")

add_subdirectory(src/scard)

add_executable(${ENTRY_POINT}
	main.c
)

target_include_directories(${ENTRY_POINT}
	PUBLIC ${PROJECT_SOURCE_DIR}/src/scard
)

target_link_libraries(${ENTRY_POINT}
	${SCARD_LIB}
)