# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

cmake_minimum_required(VERSION 3.21)

project(indexer LANGUAGES C CXX)

# Standalone indexer prototype: do NOT use add_ccf_app to avoid pulling the
# full node runtime or requiring make_user_endpoints. Only depends on libuv
# and libcurl plus header-only CCF components we include.

# Build app executable
add_executable(indexer
    ${CCF_DIR}/src/indexer/main.cpp ${CCF_DIR}/src/enclave/thread_local.cpp
    ${CCF_DIR}/src/pal/attestation.cpp
)

add_warning_checks(indexer)

target_link_libraries(
  indexer PRIVATE uv curl t_cose ccfcrypto)

if(NOT (SAN OR TSAN))
  target_link_options(indexer PRIVATE LINKER:--no-undefined)
endif()

set_property(TARGET indexer PROPERTY POSITION_INDEPENDENT_CODE ON)

add_san(indexer)
add_tidy(indexer)

if(USE_SNMALLOC)
  target_link_libraries(indexer INTERFACE snmallocshim-static)
endif()

add_dependencies(indexer indexer)

install(TARGETS indexer DESTINATION bin)