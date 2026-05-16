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
use_DynamoRIO_extension(shadowcov drreg)
use_DynamoRIO_extension(shadowcov drwrap)

add_executable(shadowfuzz-dbi
  src/shadowfuzz_dbi.c
)

add_executable(poc-a
  poc/a.c
)

add_executable(poc-b
  poc/b.c
)

add_executable(poc-stack-overflow
  poc/stack_overflow.c
)

target_compile_options(poc-stack-overflow PRIVATE
  -fstack-protector-all
)

add_executable(poc-file-magic
  poc/file_magic.c
)

add_executable(poc-format-string
  poc/format_string.c
)

add_executable(poc-command-injection
  poc/command_injection.c
)

add_executable(poc-command-system
  poc/command_system.c
)

add_executable(poc-strcmp-magic
  poc/strcmp_magic.c
)

add_executable(poc-compare-more
  poc/compare_more.c
)

add_executable(poc-int-compare
  poc/int_compare.c
)

add_executable(poc-counter-loop
  poc/counter_loop.c
)

add_executable(poc-path-open
  poc/path_open.c
)

add_executable(poc-exec-path
  poc/exec_path.c
)

add_executable(poc-env-access
  poc/env_access.c
)

add_executable(poc-credential-file
  poc/credential_file.c
)

add_executable(poc-network-connect
  poc/network_connect.c
)

add_executable(poc-network-send
  poc/network_send.c
)

add_executable(poc-file-mutation
  poc/file_mutation.c
)

add_executable(poc-branch-churn
  poc/branch_churn.c
)

add_executable(poc-persistent-harness
  poc/persistent_harness.c
)

add_library(poc-shared-entry SHARED
  poc/shared_entry_target.c
)

add_library(poc-plugin-target SHARED
  poc/plugin_target.c
)

add_executable(harness-shared-object-entry
  templates/shared_object_entry_harness.c
)
target_link_libraries(harness-shared-object-entry PRIVATE
  ${CMAKE_DL_LIBS}
)

add_executable(harness-plugin-host
  templates/plugin_host_harness.c
)
target_link_libraries(harness-plugin-host PRIVATE
  ${CMAKE_DL_LIBS}
)
