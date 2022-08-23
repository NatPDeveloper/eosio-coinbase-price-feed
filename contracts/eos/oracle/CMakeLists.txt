get_filename_component(PROJ_NAME "${CMAKE_CURRENT_SOURCE_DIR}" NAME )
cmake_minimum_required(VERSION 3.5)
project(${PROJ_NAME} VERSION 1.0.0)
set(EOSIO_WASM_OLD_BEHAVIOR "Off")
if(CDT_ROOT STREQUAL "" OR NOT CDT_ROOT)
   find_package(cdt)
endif()
add_contract( ${PROJ_NAME} ${PROJ_NAME} ${PROJ_NAME}.cpp )
include_directories( ${PROJ_NAME} PUBLIC ./ )


