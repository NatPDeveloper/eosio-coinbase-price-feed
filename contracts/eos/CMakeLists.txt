project(eoscontract NONE)
cmake_minimum_required(VERSION 3.5)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(ExternalProject)
if(CDT_ROOT STREQUAL "" OR NOT CDT_ROOT)
   find_package(cdt)
endif()
ExternalProject_Add(
                oracle
                SOURCE_DIR oracle
                BINARY_DIR oracle
                CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CDT_ROOT}/lib/cmake/cdt/CDTWasmToolchain.cmake
                UPDATE_COMMAND ""
                PATCH_COMMAND ""
                TEST_COMMAND ""
                INSTALL_COMMAND ""
                BUILD_ALWAYS 1
             )