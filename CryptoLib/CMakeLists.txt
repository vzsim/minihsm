cmake_minimum_required(VERSION 3.20)
project(SCardApp VERSION 0.1)

set(ENTRY_POINT "CryptoKey")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -O0 -g")

add_subdirectory(src)