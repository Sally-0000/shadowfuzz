cmake_minimum_required(VERSION 3.16)

project(shadowfuzz_dbi_cov C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SHADOWFUZZ_DYNAMORIO_DIR
  "${CMAKE_SOURCE_DIR}/third_party/DynamoRIO-Linux-11.3.0-1/cmake"
  CACHE PATH "Path to DynamoRIOConfig.cmake directory")

if (EXISTS "${SHADOWFUZZ_DYNAMORIO_DIR}/DynamoRIOConfig.cmake")
  list(PREPEND CMAKE_PREFIX_PATH "${SHADOWFUZZ_DYNAMORIO_DIR}")
endif()

find_package(DynamoRIO REQUIRED)

add_library(shadowcov SHARED
  src/shadowcov.c
)

configure_DynamoRIO_client(shadowcov)
use_DynamoRIO_extension(shadowcov drmgr)
