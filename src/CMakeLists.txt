cmake_minimum_required (VERSION 2.8)

# cmake versions:
# Debian 6 - 2.8.2
# Debian 7 - 2.8.9
# CentOS 6 - 2.8.12

set(FASTNETMON_LIBRARIES_GLOBAL_PATH "/opt")

project(FastNetMon)

# Unfortunately, Debian Squeeze haven't support for this feature
# It added in 2.8.5 release: http://www.cmake.org/cmake/help/v2.8.5/cmake.html
# Get convinient paths for all system folders: http://www.cmake.org/gitweb?p=cmake.git;a=commitdiff;h=a262fe09
# include(GNUInstallDirs)

include(CheckCXXCompilerFlag)
include(CheckLibraryExists)

# Enable it and fix all warnigns!
# add_definitions ("-Wall")

set (FASTNETMON_VERSION_MAJOR 1)
set (FASTNETMON_VERSION_MINOR 1)


set(HIREDIS_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/libhiredis_0_13")
set(LOG4CPP_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/log4cpp1.1.1")
set(JSONC_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/json-c-0.13")
set(PFRING_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/pf_ring_6.0.3")
set(LIBPCAP_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/libpcap_1.7.4")
set(MONGO_C_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/mongo_c_driver_1_16_1")
set(CAPNP_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/capnproto_0_8_0")
set(OPENSSL_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/openssl_1_0_2d")
set(GRPC_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/grpc_1_30_2")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} --std=c++14")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} --std=c++14")

set(CMAKE_INSTALL_SYSTEMD_SERVICEDIR "/lib/systemd/system"
  CACHE PATH "Location for systemd service files")

# With this flag we can enable GoBGP build via console: cmake .. -DENABLE_GOBGP_SUPPORT=ON
option(ENABLE_GOBGP_SUPPORT "Enable GoBGP support build" ON)

if (ENABLE_GOBGP_SUPPORT)
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++14")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++14")
endif()

option(ENABLE_CUSTOM_BOOST_BUILD "Enable build with custom Boost" ON)
if (ENABLE_CUSTOM_BOOST_BUILD)
    message(STATUS "Build with custom Boost")

    set(Boost_NO_SYSTEM_PATHS ON)

    set(BOOST_INCLUDEDIR "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/boost_1_74_0")
    set(BOOST_LIBRARYDIR "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/boost_1_74_0/stage/lib/")

    SET(Boost_DIR "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/boost_1_74_0/stage/lib/cmake/Boost-1.74.0/")

    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++14")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -std=c++14")

    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wno-deprecated-declarations")

    set(ICU_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/libicu_65_1")

    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${FASTNETMON_LIBRARIES_GLOBAL_PATH}/boost_1_74_0/stage/lib;${ICU_CUSTOM_INSTALL_PATH}/lib;${FASTNETMON_LIBRARIES_GLOBAL_PATH}/gcc930/lib64")

    # For custom Boost we need to build libicu library
    find_library(ICU_LIBRARY_UC_PATH NAMES icuuc PATHS "${ICU_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(ICU_LIBRARY_DATA_PATH NAMES icudata PATHS "${ICU_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(ICU_LIBRARY_I18N_PATH NAMES icui18n PATHS "${ICU_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

    if (ICU_LIBRARY_UC_PATH AND ICU_LIBRARY_DATA_PATH AND ICU_LIBRARY_I18N_PATH)
        message(STATUS "Found libicu")
    else()
        message(FATAL_ERROR "Could not find icu libraries ${ICU_LIBRARY_UC_PATH} ${ICU_LIBRARY_DATA_PATH} ${ICU_LIBRARY_I18N_PATH}")
    endif()

endif()
 
# Specify full RPATH for build tree
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

# Create builds in current folder with install RPATH
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${FASTNETMON_LIBRARIES_GLOBAL_PATH}/libhiredis_0_13/lib;${FASTNETMON_LIBRARIES_GLOBAL_PATH}/log4cpp1.1.1/lib;${FASTNETMON_LIBRARIES_GLOBAL_PATH}/ndpi/lib;${FASTNETMON_LIBRARIES_GLOBAL_PATH}/pf_ring_6.0.3/lib;${FASTNETMON_LIBRARIES_GLOBAL_PATH}/json-c-0.13/lib;${MONGO_C_CUSTOM_INSTALL_PATH}/lib;${MONGO_C_CUSTOM_INSTALL_PATH}/lib64;${GRPC_CUSTOM_INSTALL_PATH}/lib;${FASTNETMON_LIBRARIES_GLOBAL_PATH}/protobuf_3.11.4/lib;${CAPNP_CUSTOM_INSTALL_PATH}/lib;${OPENSSL_CUSTOM_INSTALL_PATH}/lib")

message(STATUS "C++ compilation flags: ${CMAKE_CXX_FLAGS_RELEASE}")
message(STATUS "C++ debug compilation flags: ${CMAKE_CXX_FLAGS_DEBUG}")

set(FASTNETMON_PROFILER OFF)

set(FASTNETMON_PROFILE_FLAGS "-g -pg")

# set(CMAKE_BUILD_TYPE DEBUG)

if (NOT CMAKE_BUILD_TYPE) 
    message(STATUS "Setting build type to Release as none was specified.")
    set(CMAKE_BUILD_TYPE Release)
endif()

if (FASTNETMON_PROFILER) 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
endif()

execute_process(COMMAND sh -c ". /etc/os-release; echo $ID" OUTPUT_VARIABLE OS_ID ERROR_QUIET)

### Executables definition 

# Main tool
add_executable(fastnetmon fastnetmon.cpp)

# Get last commit hash
execute_process(COMMAND git rev-list HEAD COMMAND head -n 1 OUTPUT_VARIABLE GIT_LAST_COMMIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE)

set(FASTNETMON_APPLICATION_VERSION "1.2.0 master git-${GIT_LAST_COMMIT_HASH}")
configure_file(fast_platform.h.template "${PROJECT_SOURCE_DIR}/fast_platform.h")

# Use new Memory Model Aware Atomic Operations
# You could enable it using: cmake .. -DUSE_NEW_ATOMIC_BUILTINS=ON
if (USE_NEW_ATOMIC_BUILTINS)
    message(STATUS "Will use new memory model aware atomic builtins")
    add_definitions(-DUSE_NEW_ATOMIC_BUILTINS) 
endif() 

CHECK_CXX_SOURCE_COMPILES("
#include <cstdint>
int main() {
    uint64_t x = 1;
    __atomic_add_fetch(&x, 0, __ATOMIC_RELAXED);
    return x;
}
" HAVE__ATOMIC_ADD_FETCH)

if (NOT HAVE__ATOMIC_ADD_FETCH)
    check_library_exists(atomic __atomic_add_fetch_8 "" HAVE_LIBATOMIC)
    if (HAVE_LIBATOMIC)
        target_link_libraries(fastnetmon atomic)
    endif()
endif()

# With this flag we can enable PF_RING build via console: cmake .. -DENABLE_PF_RING_SUPPORT=ON
option(ENABLE_PF_RING_SUPPORT "Enable PF_RING build" OFF)

option(ENABLE_NETMAP_SUPPORT "Enable Netmap support" ON)

CHECK_CXX_SOURCE_COMPILES("
int main() {
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    return 0;
}
" HAVE_ATOMIC_THREAD_FENCE)

# If we do not have it then we need to disable it
if (NOT HAVE_ATOMIC_THREAD_FENCE) 
    set(ENABLE_NETMAP_SUPPORT OFF)
    message(STATUS "Your system does not support __atomic_thread_fence, disabled Netmap plugin support")
endif()

if (ENABLE_NETMAP_SUPPORT)
    message(STATUS "We will build Netmap support for you")
    add_definitions(-DNETMAP_PLUGIN)
endif()

if (ENABLE_PF_RING_SUPPORT)
    # Set path to manually compiled PF_RING
    set(PFRING_INCLUDE_DIRS "${PFRING_CUSTOM_INSTALL_PATH}/include")

    find_library(PFRING_LIBRARIES NAMES pfring PATHS "${PFRING_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

    if (NOT PFRING_LIBRARIES)
        message(FATAL_ERROR "Could not find PF_RING")
    endif()
    
    link_directories("${PFRING_CUSTOM_INSTALL_PATH}/lib")
    add_definitions(-DPF_RING)

    if (EXISTS "${PFRING_CUSTOM_INSTALL_PATH}/include/pfring_zc.h" OR EXISTS "/usr/local/include/pfring_zc.h")
        message(STATUS "We found PF_RING ZC headers and will build PF_RING ZC support")
        # Enable ZC support
        add_definitions(-DPF_RING_ZC)
    else()
        message(WARNING "We can't find PF_RING ZC header pfring_zc.h. Will not compile ZC support") 
    endif()

    include_directories(${PFRING_INCLUDE_DIRS})

    message(STATUS "We have enabled PF_RING's hardware filtering option")
endif()

add_library(simple_packet_capnp STATIC simple_packet_capnp/simple_packet.capnp.c++)

# Our LPM library
add_library(patricia STATIC libpatricia/patricia.c)

# Graphite metrics
add_library(graphite_metrics STATIC metrics/graphite.cpp)
target_link_libraries(fastnetmon graphite_metrics)

# InfluxDB metrics
add_library(influxdb_metrics STATIC metrics/influxdb.cpp)
target_link_libraries(fastnetmon influxdb_metrics)

add_library(fastnetmon_pcap_format STATIC fastnetmon_pcap_format.cpp)

# Our tools library
add_library(fast_library STATIC fast_library.cpp)

# Our parser
add_library(unified_parser STATIC unified_parser.cpp)
target_link_libraries(unified_parser fastnetmon_packet_parser)

# Our ipfix database library
add_library(ipfix_rfc STATIC ipfix_rfc.cpp)

add_library(bgp_protocol bgp_protocol.cpp)

# Our packet parser
add_library(fastnetmon_packet_parser STATIC fastnetmon_packet_parser.c)

# Our logic library
add_library(fastnetmon_logic STATIC fastnetmon_logic.cpp)

CHECK_CXX_SOURCE_COMPILES("
#include <linux/if_packet.h>
int main() {
    return TPACKET_V3;
}
" HAVE_TPACKET_V3)


if (${HAVE_TPACKET_V3})
    message(STATUS "Your system has support for AF_PACKET v3")
    set (ENABLE_AFPACKET_SUPPORT ON)
else()
    message(STATUS "Your system does not support AF_PACKET v3, disabled it")
endif()

# -DENABLE_AFPACKET_SUPPORT=ON ..
if (ENABLE_AFPACKET_SUPPORT)
   add_definitions(-DFASTNETMON_ENABLE_AFPACKET) 
   add_library(afpacket_plugin STATIC afpacket_plugin/afpacket_collector.cpp)
   target_link_libraries(afpacket_plugin unified_parser)
endif()

# Library with data types for parsing network structures
add_library(network_data_structures STATIC network_data_structures.cpp)

# Our new parser for parsing traffic up to L4
add_library(simple_packet_parser_ng STATIC simple_packet_parser_ng.cpp)
target_link_libraries(simple_packet_parser_ng network_data_structures)

# Our own sFlow parser library
set_source_files_properties(libsflow/libsflow.cpp PROPERTIES COMPILE_FLAGS -pedantic)
add_library(libsflow STATIC libsflow/libsflow.cpp)

# sFlow plugin
add_library(sflow_plugin STATIC sflow_plugin/sflow_collector.cpp)

# Link sFlow plugin with new traffic parser
target_link_libraries(sflow_plugin simple_packet_parser_ng)

# Link sFlow plugin with libsflow
target_link_libraries(sflow_plugin libsflow)  

# netflow library
add_library(netflow STATIC netflow_plugin/netflow.cpp)

# netflow plugin
add_library(netflow_plugin STATIC netflow_plugin/netflow_collector.cpp)
target_link_libraries(netflow_plugin ipfix_rfc netflow)

option(ENABLE_DPI_SUPPORT "Enable Deep Packet Inspection support" ON)
if (ENABLE_DPI_SUPPORT) 
    message(STATUS "We will enable nDPI support")

    add_library(fast_dpi STATIC fast_dpi.cpp)

    set(NDPI_INCLUDE_DIRS "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/ndpi/include/libndpi-1.7.1")

    find_library(NDPI_LIBRARIES NAMES ndpi PATHS "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/ndpi/lib" NO_DEFAULT_PATH)

    if (NOT NDPI_LIBRARIES)
        message(FATAL_ERROR "Could not find nDPI library")
    endif()

    link_directories("${FASTNETMON_LIBRARIES_GLOBAL_PATH}/ndpi/lib")
    include_directories(${NDPI_INCLUDE_DIRS})

    add_definitions(-DENABLE_DPI)

    target_link_libraries(fast_dpi ${NDPI_LIBRARIES})
endif()

# pcap plugin
add_library(pcap_plugin STATIC pcap_plugin/pcap_collector.cpp)
target_link_libraries(pcap_plugin pcap)

find_package(Threads)

if (ENABLE_PF_RING_SUPPORT) 
    add_library(pfring_plugin STATIC pfring_plugin/pfring_collector.cpp)
    target_link_libraries(pfring_plugin ${PFRING_LIBRARIES})
    target_link_libraries(pfring_plugin numa)
    target_link_libraries(pfring_plugin ${CMAKE_THREAD_LIBS_INIT})
endif()

add_library(exabgp_action STATIC actions/exabgp_action.cpp)

if (ENABLE_GOBGP_SUPPORT)
    set(PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/protobuf_3.11.4")

    add_definitions(-DENABLE_GOBGP)
    add_library(gobgp_action STATIC actions/gobgp_action.cpp)

    find_path(GRPC_INCLUDES_FOLDER NAMES grpc/grpc.h PATHS "${GRPC_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
    find_library(GRPC_LIBRARY_GRPC_PATH NAMES grpc PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(GRPC_LIBRARY_GPR_PATH NAMES gpr PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(GRPC_LIBRARY_GRPC_CPP_PATH NAMES grpc++ PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH) 

    if (GRPC_INCLUDES_FOLDER AND GRPC_LIBRARY_GRPC_PATH AND GRPC_LIBRARY_GPR_PATH AND GRPC_LIBRARY_GRPC_CPP_PATH)
        include_directories(${GRPC_INCLUDES_FOLDER})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GRPC_PATH})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GPR_PATH})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GRPC_CPP_PATH})

	    message(STATUS "Found gRPC library: ${GRPC_LIBRARY_GRPC_PATH} ${GRPC_LIBRARY_GPR_PATH} ${GRPC_LIBRARY_GRPC_CPP_PATH}")
    else()
        message(FATAL_ERROR "Could not find gRPC library")
    endif()

    find_path(PROTOCOL_BUFFERS_INCLUDE_FOLDER NAMES "google/protobuf/stubs/common.h" PATHS "${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/include")

    find_library(PROTOCOL_BUFFERS_LIBRARY_PATH NAMES protobuf PATHS "${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/lib") 

    if (PROTOCOL_BUFFERS_INCLUDE_FOLDER AND PROTOCOL_BUFFERS_LIBRARY_PATH)
        include_directories(${PROTOCOL_BUFFERS_INCLUDE_FOLDER}) 
        target_link_libraries(gobgp_action ${PROTOCOL_BUFFERS_LIBRARY_PATH}) 
	    message(STATUS "Found protobuf library: ${PROTOCOL_BUFFERS_LIBRARY_PATH}")
    else()
        message(FATAL_ERROR "Could not find protocol buffers")
    endif()


    # message(STATUS "grpc: ${GRPC_INCLUDES_FOLDER} ${GRPC_LIBRARY_GRPC_PATH} ${GRPC_LIBRARY_GPR_PATH}")
    # message(STATUS ${PROJECT_BINARY_DIR})

    find_program(PROTOC_BINARY protoc PATHS "${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/bin" NO_DEFAULT_PATH)

    if (PROTOC_BINARY)
        message(STATUS "Found protoc protobuf compiler: ${PROTOC_BINARY}")
    else()
        message(FATAL_ERROR "Can't find protoc compiler")
    endif()

    message(STATUS "Building protobuf and gRPC mappings for C++")

    set(GRPC_CPP_PLUGIN "${GRPC_CUSTOM_INSTALL_PATH}/bin/grpc_cpp_plugin")

    execute_process(COMMAND ${PROTOC_BINARY} -I ${PROJECT_BINARY_DIR}/../actions --grpc_out=${PROJECT_BINARY_DIR}/../actions --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROJECT_BINARY_DIR}/../actions/gobgp.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code for gobgp.proto gRPC: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    execute_process(COMMAND ${PROTOC_BINARY} -I  ${PROJECT_BINARY_DIR}/../actions --cpp_out=${PROJECT_BINARY_DIR}/../actions ${PROJECT_BINARY_DIR}/../actions/gobgp.proto ${PROJECT_BINARY_DIR}/../actions/attribute.proto  ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code for gobgp.proto and attribute.proto Protobuf: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    # Build gRPC and protocol bufffers libraries and link they to gobgp_action
    add_library(gobgp_api_client_pb_cc STATIC actions/gobgp.pb.cc)
    add_library(gobgp_api_client_grpc_pb_cc STATIC actions/gobgp.grpc.pb.cc)

    # Disable annoying warnings
    set_source_files_properties(actions/gobgp.pb.cc PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
    set_source_files_properties(actions/gobgp.grpc.pb.cc PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)

    set_source_files_properties(actions/gobgp.pb.h PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
    set_source_files_properties(actions/gobgp.grpc.pb.h PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)

    target_link_libraries(gobgp_action gobgp_api_client_pb_cc)
    target_link_libraries(gobgp_action gobgp_api_client_grpc_pb_cc)

    # Add attributes
    add_library(attribute_pb_cc STATIC actions/attribute.pb.cc)
    target_link_libraries(gobgp_action attribute_pb_cc)

    # FastNetMon API
    add_definitions(-DFASTNETMON_API)    

    execute_process(COMMAND ${PROTOC_BINARY} -I ${PROJECT_BINARY_DIR}/.. --grpc_out=${PROJECT_BINARY_DIR}/.. --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROJECT_BINARY_DIR}/../fastnetmon.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code for gRPC fastnetmon.proto: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    execute_process(COMMAND ${PROTOC_BINARY} -I  ${PROJECT_BINARY_DIR}/.. --cpp_out=${PROJECT_BINARY_DIR}/.. ${PROJECT_BINARY_DIR}/../fastnetmon.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE) 

    message(STATUS "Protoc return code for protobuf fastnetmon.proto: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    # Disable annoying warnings
    set_source_files_properties(fastnetmon.grpc.pb.cc PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
    set_source_files_properties(fastnetmon.pb.cc PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
    set_source_files_properties(fastnetmon.grpc.pb.h PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)
    set_source_files_properties(fastnetmon.pb.h PROPERTIES COMPILE_FLAGS -Wno-deprecated-declarations)

    add_library(fastnetmon_grpc_pb_cc STATIC fastnetmon.grpc.pb.cc)
    add_library(fastnetmon_pb_cc STATIC fastnetmon.pb.cc)

    add_executable(fastnetmon_api_client fastnetmon_api_client.cpp)

    target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GPR_PATH})
    target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GRPC_CPP_PATH})
    target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GRPC_PATH})
    target_link_libraries(fastnetmon_api_client fastnetmon_grpc_pb_cc)
    target_link_libraries(fastnetmon_api_client fastnetmon_pb_cc)
    target_link_libraries(fastnetmon_api_client ${PROTOCOL_BUFFERS_LIBRARY_PATH}) 

    target_link_libraries(fastnetmon ${GRPC_LIBRARY_GPR_PATH})
    target_link_libraries(fastnetmon ${GRPC_LIBRARY_GRPC_CPP_PATH})
    target_link_libraries(fastnetmon ${GRPC_LIBRARY_GRPC_PATH})
    target_link_libraries(fastnetmon fastnetmon_grpc_pb_cc)
    target_link_libraries(fastnetmon fastnetmon_pb_cc)
    target_link_libraries(fastnetmon ${PROTOCOL_BUFFERS_LIBRARY_PATH}) 
endif()

if (ENABLE_CUSTOM_BOOST_BUILD)
    target_link_libraries(fastnetmon ${ICU_LIBRARY_UC_PATH})
    target_link_libraries(fastnetmon ${ICU_LIBRARY_DATA_PATH})
    target_link_libraries(fastnetmon ${ICU_LIBRARY_I18N_PATH})
endif()

# example plugin
add_library(example_plugin STATIC example_plugin/example_collector.cpp)

if (ENABLE_NETMAP_SUPPORT)
    # Netmap plugin
    set(NETMAP_INCLUDE_DIRS "netmap_plugin/netmap_includes")
    include_directories(${NETMAP_INCLUDE_DIRS})
    add_library(netmap_plugin STATIC netmap_plugin/netmap_collector.cpp)
    target_link_libraries(netmap_plugin fastnetmon_packet_parser)
    target_link_libraries(netmap_plugin unified_parser)
endif()

# Client tool
add_executable(fastnetmon_client fastnetmon_client.cpp)

# Find boost: http://www.cmake.org/cmake/help/v3.0/module/FindBoost.html

# Enable detailed errors
set(Boost_DETAILED_FAILURE_MSG ON)
# set(Boost_DEBUG ON)

find_package(Boost COMPONENTS thread regex program_options system REQUIRED)

if(Boost_FOUND)
    message(STATUS "Found Boost: ${Boost_LIBRARIES} ${Boost_INCLUDE_DIRS}")

    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(fastnetmon ${Boost_LIBRARIES})
    target_link_libraries(fast_library ${Boost_LIBRARIES})
    target_link_libraries(fastnetmon_client ${Boost_LIBRARIES})
endif()

target_link_libraries(fast_library patricia)
target_link_libraries(fast_library fastnetmon_pcap_format)

# Try to find ncurses librreary
find_package(Curses REQUIRED)

if(CURSES_FOUND) 
    include_directories(${CURSES_INCLUDE_DIRS})
    target_link_libraries(fastnetmon_client ${CURSES_LIBRARIES})
endif()

### Move this code to cmake module

# Try to find hiredis in a specific folder
find_path(HIREDIS_INCLUDES_FOLDER NAMES hiredis/hiredis.h PATHS "${HIREDIS_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)

# Try to find hiredis library path
find_library(HIREDIS_LIBRARY_PATH NAMES hiredis PATHS "${HIREDIS_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

if (HIREDIS_INCLUDES_FOLDER AND HIREDIS_LIBRARY_PATH) 
    message(STATUS "We found hiredis library ${HIREDIS_INCLUDES_FOLDER} ${HIREDIS_LIBRARY_PATH}")

    add_definitions(-DREDIS)
    include_directories(${HIREDIS_INCLUDES_FOLDER})
    target_link_libraries (fastnetmon ${HIREDIS_LIBRARY_PATH})
    target_link_libraries(fastnetmon_logic ${HIREDIS_LIBRARY_PATH})
else()
    message(STATUS "We can't find hiredis library and will disable Redis support")
endif()

set(ENABLE_OPENSSL_SUPPORT TRUE)
if (ENABLE_OPENSSL_SUPPORT)
    find_path(OPENSSL_INCLUDES_FOLDER NAMES "openssl/rsa.h" PATHS "${OPENSSL_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
    find_library(OPENSSL_LIBRARY_PATH NAMES ssl PATHS "${OPENSSL_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(OPENSSL_CRYPTO_LIBRARY_PATH NAMES crypto PATHS "${OPENSSL_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

    if (OPENSSL_INCLUDES_FOLDER AND OPENSSL_LIBRARY_PATH AND OPENSSL_CRYPTO_LIBRARY_PATH) 
        message(STATUS "We found OpenSSL library: ${OPENSSL_LIBRARY_PATH} ${OPENSSL_CRYPTO_LIBRARY_PATH}")
        include_directories(${OPENSSL_INCLUDES_FOLDER})
    else()
        message(FATAL_ERROR "Could not find OpenSSL library")
    endif()
endif()

SET(CAPNP_SUPPORT TRUE)

if (CAPNP_SUPPORT)
    find_library(CAPNP_LIBRARY_PATH NAMES capnp PATHS "${CAPNP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)
    find_library(CAPNP_KJ_LIBRARY_PATH NAMES kj PATHS "${CAPNP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

    if (CAPNP_LIBRARY_PATH AND CAPNP_KJ_LIBRARY_PATH)
        message(STATUS "We found capnp and kj libraries: ${CAPNP_LIBRARY_PATH} ${CAPNP_KJ_LIBRARY_PATH}")
    else()
        message(FATAL_ERROR "Could not find capnp libraries")
    endif()

    include_directories("${CAPNP_CUSTOM_INSTALL_PATH}/include")
endif()

target_link_libraries(simple_packet_capnp ${CAPNP_LIBRARY_PATH} ${CAPNP_KJ_LIBRARY_PATH})

# Link it with cap'n'p stuff
target_link_libraries(fast_library simple_packet_capnp)

### Find mongo-c
find_path(MONGOC_INCLUDES_FOLDER NAMES libmongoc-1.0/mongoc.h PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
find_library(MONGOC_LIBRARY_PATH NAMES mongoc-1.0 PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

### find bson
find_path(BSON_INCLUDES_FOLDER NAMES libbson-1.0/bson.h PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
find_library(BSON_LIBRARY_PATH NAMES bson-1.0 PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

if (MONGOC_INCLUDES_FOLDER AND MONGOC_LIBRARY_PATH AND BSON_INCLUDES_FOLDER AND BSON_LIBRARY_PATH)
    message(STATUS "We found mongo-c library ${MONGOC_INCLUDES_FOLDER} ${MONGOC_LIBRARY_PATH} ${BSON_INCLUDES_FOLDER} ${BSON_LIBRARY_PATH}")
    add_definitions(-DMONGO)

    # We add suffix name because cmake could not detect it correctly...
    include_directories("${MONGOC_INCLUDES_FOLDER}/libmongoc-1.0")
    include_directories("${BSON_INCLUDES_FOLDER}/libbson-1.0")

    target_link_libraries(fastnetmon ${MONGOC_LIBRARY_PATH} ${BSON_LIBRARY_PATH})
    target_link_libraries(fastnetmon_logic ${MONGOC_LIBRARY_PATH} ${BSON_LIBRARY_PATH})
else()
    message(FATAL_ERROR "We can't find Mongo C library")
endif()

### Look for libpcap

#find_path(LIBPCAP_INCLUDES_FOLDER NAMES pcap.h PATHS "${LIBPCAP_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)

#find_library(LIBPCAP_LIBRARY_PATH NAMES pcap PATHS "${LIBPCAP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

#if (LIBPCAP_INCLUDES_FOLDER AND LIBPCAP_LIBRARY_PATH) 
#    message(STATUS "We found pcap library ${LIBPCAP_LIBRARY_PATH}")

#    include_directories(${LIBPCAP_INCLUDES_FOLDER})
#else()
#    message(FATAL_ERROR "We can't find pcap library")    
#endif()

### Look for log4cpp

# Try to find log4cpp includes path
find_path(LOG4CPP_INCLUDES_FOLDER NAMES log4cpp/Appender.hh PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)

# Try to find log4cpp library path
find_library(LOG4CPP_LIBRARY_PATH NAMES log4cpp PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

if (LOG4CPP_INCLUDES_FOLDER AND LOG4CPP_LIBRARY_PATH)
    include_directories(${LOG4CPP_INCLUDES_FOLDER})
    message(STATUS "We have found log4cpp: ${LOG4CPP_LIBRARY_PATH}")
else()
    message(FATAL_ERROR "We can't find log4cpp. We can't build project")
endif()

### Look for jsonc

find_path(JSONC_INCLUDES_FOLDER NAMES json-c/json.h PATHS "${JSONC_CUSTOM_INSTALL_PATH}/include" NO_DEFAULT_PATH)
find_library(JSONC_LIBRARY_PATH NAMES json-c PATHS "${JSONC_CUSTOM_INSTALL_PATH}/lib" NO_DEFAULT_PATH)

if (JSONC_INCLUDES_FOLDER AND JSONC_LIBRARY_PATH)
    include_directories(${JSONC_INCLUDES_FOLDER}) 
    message(STATUS "We have found json-c library correctly: ${JSONC_LIBRARY_PATH}")
else()
    message(FATAL_ERROR "We can't find json-c library! Can't build project")
endif()

target_link_libraries(fast_library ${JSONC_LIBRARY_PATH})

target_link_libraries(fast_library ${OPENSSL_LIBRARY_PATH})
target_link_libraries(fast_library ${OPENSSL_CRYPTO_LIBRARY_PATH})

if (ENABLE_DPI_SUPPORT)
    target_link_libraries(fastnetmon fast_dpi)
endif()

target_link_libraries(fastnetmon ${LOG4CPP_LIBRARY_PATH})

target_link_libraries(fastnetmon ${CMAKE_THREAD_LIBS_INIT})

# Our libs
target_link_libraries(fastnetmon patricia)
target_link_libraries(fastnetmon fastnetmon_pcap_format)

target_link_libraries(fastnetmon ipfix_rfc)

target_link_libraries(fastnetmon_logic bgp_protocol fast_dpi exabgp_action)

# Link to our functions
target_link_libraries(fastnetmon fast_library)

# link to our unified parser
target_link_libraries(fastnetmon unified_parser)

if (ENABLE_PF_RING_SUPPORT)
    target_link_libraries(fastnetmon pfring_plugin)
endif()

target_link_libraries(fastnetmon ${OPENSSL_LIBRARY_PATH})
target_link_libraries(fastnetmon ${OPENSSL_CRYPTO_LIBRARY_PATH})

if (ENABLE_GOBGP_SUPPORT)
    target_link_libraries(fastnetmon gobgp_action)
endif()

target_link_libraries(fastnetmon exabgp_action)

if (ENABLE_AFPACKET_SUPPORT)
    target_link_libraries(fastnetmon afpacket_plugin)
endif()

target_link_libraries(fastnetmon sflow_plugin netflow_plugin pcap_plugin example_plugin)

target_link_libraries(fastnetmon fastnetmon_logic)

if (ENABLE_NETMAP_SUPPORT)
    target_link_libraries(fastnetmon netmap_plugin)
endif()

# cmake .. -DBUILD_PLUGIN_RUNNER=ON
if (BUILD_PLUGIN_RUNNER)
    add_executable(fastnetmon_plugin_runner plugin_runner.cpp)

    if (ENABLE_AFPACKET_SUPPORT) 
        target_link_libraries(fastnetmon_plugin_runner afpacket_plugin)
    endif()

    target_link_libraries(fastnetmon_plugin_runner ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(fastnetmon_plugin_runner patricia)
    target_link_libraries(fastnetmon_plugin_runner fastnetmon_pcap_format)
    target_link_libraries(fastnetmon_plugin_runner ${LOG4CPP_LIBRARY_PATH})
    target_link_libraries(fastnetmon_plugin_runner fast_library)

    # Add all plugins
    target_link_libraries(fastnetmon_plugin_runner sflow_plugin netflow_plugin pcap_plugin example_plugin)

    if (ENABLE_NETMAP_SUPPORT)
        target_link_libraries(fastnetmon_plugin_runner netmap_plugin)
    endif()

    if (ENABLE_PF_RING_SUPPORT)
        target_link_libraries(fastnetmon_plugin_runner ${PFRING_LIBRARIES})
        target_link_libraries(fastnetmon_plugin_runner pfring_plugin)
    endif()
endif()

# cmake .. -DBUILD_PCAP_READER=ON
if (BUILD_PCAP_READER)
    add_executable(fastnetmon_pcap_reader pcap_reader.cpp)

    target_link_libraries(fastnetmon_pcap_reader fastnetmon_packet_parser)
    target_link_libraries(fastnetmon_pcap_reader patricia)
    target_link_libraries(fastnetmon_pcap_reader fastnetmon_pcap_format)

    target_link_libraries(fastnetmon_pcap_reader fast_library)
    target_link_libraries(fastnetmon_pcap_reader ${LOG4CPP_LIBRARY_PATH})
    target_link_libraries(fastnetmon_pcap_reader netflow_plugin)   
    target_link_libraries(fastnetmon_pcap_reader sflow_plugin)

    if (ENABLE_NETMAP_SUPPORT)
        target_link_libraries(fastnetmon_pcap_reader netmap_plugin)
    endif()

    if (ENABLE_DPI_SUPPORT)
        target_link_libraries(fastnetmon_pcap_reader fast_dpi)
    endif()
endif()

# cmake -DBUILD_TESTS=ON ..
if (BUILD_TESTS) 
    add_executable(fastnetmon_tests fastnetmon_tests.cpp)
    target_link_libraries(fastnetmon_tests fast_library)
    target_link_libraries(fastnetmon_tests ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(fastnetmon_tests ${Boost_LIBRARIES})
    target_link_libraries(fastnetmon_tests ${LOG4CPP_LIBRARY_PATH})

    set(GOOGLE_TEST_INCLUDE_DIRS ${FASTNETMON_LIBRARIES_GLOBAL_PATH}/gtest/include)
    set(GOOGLE_TEST_LIBRARIES ${FASTNETMON_LIBRARIES_GLOBAL_PATH}/gtest/lib/libgtest.a ${FASTNETMON_LIBRARIES_GLOBAL_PATH}/gtest/lib/libgtest_main.a)

    # Compiled Google Library
    include_directories(${GOOGLE_TEST_INCLUDE_DIRS})
    target_link_libraries(fastnetmon_tests ${GOOGLE_TEST_LIBRARIES})
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" OR ${CMAKE_SYSTEM_NAME} STREQUAL "DragonFly")
    set(CMAKE_INSTALL_BINDIR "bin")
    set(CMAKE_INSTALL_SBINDIR "bin")
    set(CMAKE_INSTALL_SYSCONFDIR "etc")
else()
    set(CMAKE_INSTALL_BINDIR "/usr/bin")
    set(CMAKE_INSTALL_SBINDIR "/usr/sbin")
    set(CMAKE_INSTALL_SYSCONFDIR "/etc")
endif()

install(TARGETS fastnetmon DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(TARGETS fastnetmon_client DESTINATION "${CMAKE_INSTALL_BINDIR}")

install(FILES fastnetmon.conf DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

# Install blank files for networks list and whitelist
install(FILES networks_list DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")
install(FILES networks_whitelist DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

# man pages
install(FILES man/fastnetmon.1 DESTINATION /usr/share/man/man1)
install(FILES man/fastnetmon_client.1 DESTINATION /usr/share/man/man1)

# service files
if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    configure_file(fastnetmon.service.in "${CMAKE_CURRENT_BINARY_DIR}/fastnetmon.service" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/fastnetmon.service" DESTINATION ${CMAKE_INSTALL_SYSTEMD_SERVICEDIR})
endif()

if (${OS_ID} MATCHES debian|ubuntu)
install(FILES fastnetmon_init_script_debian_6_7 DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/init.d RENAME fastnetmon)
endif()

# Configure cpack package builder
# Run it with: cd build; cpack -G DEB ..
set(CPACK_PACKAGE_NAME "fastnetmon")
set(CPACK_PACKAGE_VENDOR "fastnetmon.com")
set(CPACK_PACKAGE_CONTACT "pavel.odintsov@gmail.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "FastNetMon - very fast DDoS analyzer with sflow/netflow/mirror support")
set(CPACK_PACKAGE_VERSION "1.1.2")
set(CPACK_PACKAGE_VERSION_MAJOR "1")
set(CPACK_PACKAGE_VERSION_MINOR "1")
set(CPACK_PACKAGE_VERSION_PATCH "2")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
# set(CPACK_PACKAGE_INSTALL_DIRECTORY "CPack Component Example")

# Specify config for deb package
# http://www.cmake.org/Wiki/CMake:CPackPackageGenerators#DEB_.28UNIX_only.29
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-thread-dev, libboost-system-dev, libboost-regex-dev, libpcap-dev, libnuma-dev, liblog4cpp5-dev")

# This must always be last!
include(CPack)
