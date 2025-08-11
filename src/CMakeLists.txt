# We upgraded it to support https://cmake.org/cmake/help/latest/policy/CMP0077.html
cmake_minimum_required (VERSION 3.13)

set(FASTNETMON_LIBRARIES_GLOBAL_PATH "/opt/fastnetmon-community/libraries")

# We need this options for generating compile_commands.json file
# It's required for clang static analyzer and autocompletion tools based on clang
# PVS uses it too
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

project(FastNetMon)

include(GNUInstallDirs)

include(CheckCXXCompilerFlag)
include(CheckLibraryExists)

# Enable it and fix all warnings
# add_definitions ("-Wall")

set (FASTNETMON_VERSION_MAJOR 1)
set (FASTNETMON_VERSION_MINOR 2)
set (FASTNETMON_VERSION_PATCH 9)

set(HIREDIS_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/hiredis_0_14")
set(LOG4CPP_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/log4cpp_1_1_4")
set(LIBPCAP_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/pcap_1_10_4")
set(MONGO_C_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/mongo_c_driver_1_23_0")
set(CAPNP_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/capnproto_0_8_0")
set(CLICKHOUSE_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/clickhouse_2_3_0")
set(OPENSSL_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/openssl_1_1_1q")
set(GRPC_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/grpc_1_49_2")
set(LIBBPF_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/bpf_1_0_1")
set(LIBELF_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/elfutils_0_186")
set(PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/protobuf_21_12")
set(ABSL_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/abseil_2024_01_16")
set(BOOST_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/boost_1_81_0")
set(GCC_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/gcc_12_1_0")
set(LIB_CPP_KAFKA_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/cppkafka_0_3_1")
set(LIB_RDKAFKA_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/rdkafka_1_7_0")
set(GTEST_INSTALL_PATH "${FASTNETMON_LIBRARIES_GLOBAL_PATH}/gtest_1_13_0")

# Enable time profiling for compilation phase
# https://stackoverflow.com/questions/5962285/cmake-compilation-statistics-per-transation-unit
# set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE "${CMAKE_COMMAND} -E time")

# -Wunused includes more warnings than -Wall
# In order to get a warning about an unused function parameter, you must either specify -Wextra -Wunused (note that -Wall implies -Wunused), or separately specify -Wunused-parameter.
# TODO: return -Wunused-parameter and address all warning later, I started it but did not finish as we have too many of them
# catch-value is documented here: https://patchwork.ozlabs.org/project/gcc/patch/tkrat.8c7b4260a533be2f@netcologne.de/#1680619
add_definitions("-Wreorder -Wunused -Wparentheses -Wimplicit-fallthrough -Wreturn-type -Wuninitialized -Winit-self -Wmaybe-uninitialized -Wcatch-value=3 -Wclass-memaccess")

# On Windows we need to build libgcc and libstdc++ statically to avoid need to carry dlls with us
if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  set(CMAKE_CXX_STANDARD_LIBRARIES "-static-libgcc -static-libstdc++ ${CMAKE_CXX_STANDARD_LIBRARIES}")
endif()

# We need this to avoid dependency on libwinpthread-1.dll
# Details: https://cmake.org/pipermail/cmake/2019-June/069611.html
if (MINGW)
  set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-Bstatic,--whole-archive -lwinpthread -Wl,--no-whole-archive")
endif()

# We use this approach instead of following:
# set (CMAKE_CXX_STANDARD 20)
# Because it allows us to specify intermediate releases and releases not yet supported by cmake
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --std=c++20")

# With this flag we can enable GoBGP build via console: cmake .. -DENABLE_GOBGP_SUPPORT=ON
option(ENABLE_GOBGP_SUPPORT "Enable GoBGP support build" ON)

# It can be disabled this way: cmake .. -DENABLE_PCAP_SUPPORT=OFF
option(ENABLE_PCAP_SUPPORT "Enable PCAP support" ON)

# We need to explicitly link with libabsl.
# We do not use it directly but gRPC uses it for libgpr and we need to link with absl explicitly to avoid linker errors like this:
# libgpr.so: undefined reference to symbol '_ZN4absl12lts_202103245Mutex4LockEv'
# /usr/lib64/libabsl_synchronization.so.2103.0.1: error adding symbols: DSO missing from command line
option(LINK_WITH_ABSL "Enable optonal linking with ABSL" OFF)

# Kafka support is optional and we do not enable it for build by default
option(KAFKA_SUPPORT "Enables Kafka support" OFF)

# We need to add it into include path as gRPC uses it include path
include_directories("${ABSL_INSTALL_PATH}/include")

option(DO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD "Disables use of libraries from system path" OFF)

if (DO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD)
    # We need to avoid using system path for libraries and includes search because we ship specific versions of our own libraries in package
    # And we need to avoid implicit fallbacks to system libraries as it will break dependencies
    set(DISABLE_DEFAULT_PATH_SEARCH_VAR "NO_DEFAULT_PATH")
else ()
    # Disable this logic and allow any paths
    set(DISABLE_DEFAULT_PATH_SEARCH_VAR "")
endif()

if (DO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD)
    message(STATUS "Build with custom Boost")

    set(Boost_NO_SYSTEM_PATHS ON)

    set(BOOST_INCLUDEDIR "${BOOST_INSTALL_PATH}")
    set(BOOST_LIBRARYDIR "${BOOST_INSTALL_PATH}/lib/")

    SET(Boost_DIR "${BOOST_INSTALL_PATH}/lib/cmake/Boost-1.81.0/")

    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wno-deprecated-declarations")

    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${BOOST_INSTALL_PATH}/lib;${GCC_INSTALL_PATH}/lib64")
endif()

# We use hardcoded RPATH for our libraries only when we compile against our custom libraries
if (DO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD) 

    # Specify full RPATH for build tree
    SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

    # Create builds in current folder with install RPATH
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

    # We need to manually set RPATH to each of our custom libraries
    # Otherwise our binaries will not able to find them as we use non standard path
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${HIREDIS_CUSTOM_INSTALL_PATH}/lib")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${LOG4CPP_CUSTOM_INSTALL_PATH}/lib")
    
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${MONGO_C_CUSTOM_INSTALL_PATH}/lib")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${MONGO_C_CUSTOM_INSTALL_PATH}/lib64")
    
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${GRPC_CUSTOM_INSTALL_PATH}/lib")

    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/lib")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/lib64")
    
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${CAPNP_CUSTOM_INSTALL_PATH}/lib")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${OPENSSL_CUSTOM_INSTALL_PATH}/lib")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${CLICKHOUSE_CUSTOM_INSTALL_PATH}/lib")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${LIBBPF_CUSTOM_INSTALL_PATH}/lib64")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${LIBELF_CUSTOM_INSTALL_PATH}/lib")

    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${LIB_CPP_KAFKA_INSTALL_PATH}/lib")
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${LIB_RDKAFKA_INSTALL_PATH}/lib")

    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_RPATH};${LIBPCAP_CUSTOM_INSTALL_PATH}/lib")
else()
   # We do not need any RPATH alterations when we want to link with system libraries (i.e. upstream builds for Debian or RedHat family)
endif()

message(STATUS "C++ default compilation flags: ${CMAKE_CXX_FLAGS}")
message(STATUS "C++ release compilation flags: ${CMAKE_CXX_FLAGS_RELEASE}")
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

# Short 8 symbol commit
execute_process(COMMAND git rev-list HEAD COMMAND head -n 1 COMMAND cut -c1-8 OUTPUT_VARIABLE GIT_LAST_COMMIT_HASH_SHORT OUTPUT_STRIP_TRAILING_WHITESPACE)

message(STATUS "Commit hash: ${GIT_LAST_COMMIT_HASH_SHORT}")

set(FASTNETMON_APPLICATION_VERSION "${FASTNETMON_VERSION_MAJOR}.${FASTNETMON_VERSION_MINOR}.${FASTNETMON_VERSION_PATCH} ${GIT_LAST_COMMIT_HASH_SHORT}")

# Set standard values which work for majority of platforms
set(FASTNETMON_PID_PATH "/var/run/fastnetmon.pid")
set(FASTNETMON_CONFIGURATION_PATH "/etc/fastnetmon.conf")
set(FASTNETMON_LOG_FILE_PATH "/var/log/fastnetmon.log")
set(FASTNETMON_ATTACK_DETAILS_FOLDER "/var/log/fastnetmon_attacks")
set(FASTNETMON_NOTIFY_SCRIPT_PATH_DEFAULT "/usr/local/bin/notify_about_attack.sh")
set(FASTNETMON_NETWORK_WHITELIST_PATH "/etc/networks_whitelist")
set(FASTNETMON_NETWORKS_LIST_PATH "/etc/networks_list")
set(FASTNETMON_BACKTRACE_PATH "/var/log/fastnetmon_backtrace.dump")
set(FASTNETMON_WHITELIST_RULES_PATH "/etc/whitelist_rules")

# For FreeBSD based platforms we need to adjust them
if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" OR ${CMAKE_SYSTEM_NAME} STREQUAL "DragonFly")
  set(FREEBSD_DEFAULT_PREFIX "/usr/local")

  set(FASTNETMON_PID_PATH "/var/run/fastnetmon/fastnetmon.pid")
  set(FASTNETMON_CONFIGURATION_PATH "${FREEBSD_DEFAULT_PREFIX}/etc/fastnetmon.conf")
  set(FASTNETMON_LOG_FILE_PATH "/var/log/fastnetmon/fastnetmon.log")
  set(FASTNETMON_ATTACK_DETAILS_FOLDER "/var/log/fastnetmon_attacks")
  set(FASTNETMON_NOTIFY_SCRIPT_PATH_DEFAULT "${FREEBSD_DEFAULT_PREFIX}/bin/notify_about_attack.sh")
  set(FASTNETMON_NETWORK_WHITELIST_PATH "${FREEBSD_DEFAULT_PREFIX}/etc/networks_whitelist")
  set(FASTNETMON_NETWORKS_LIST_PATH "${FREEBSD_DEFAULT_PREFIX}/etc/networks_list")
  set(FASTNETMON_BACKTRACE_PATH "/var/log/fastnetmon/fastnetmon_backtrace.dump")
endif()

configure_file(fast_platform.h.template "${PROJECT_SOURCE_DIR}/fast_platform.hpp")

# Use new Memory Model Aware Atomic Operations
# You could enable it using: cmake .. -DUSE_NEW_ATOMIC_BUILTINS=ON
# We use it for exotic platforms where we have no specific functions in atomics library: https://salsa.debian.org/debian/fastnetmon/-/blob/master/debian/rules#L11
if (USE_NEW_ATOMIC_BUILTINS)
    message(STATUS "Will use new memory model aware atomic builtins")
    add_definitions(-DUSE_NEW_ATOMIC_BUILTINS) 
endif() 

# Be default we do not link with it but we need it on platforms without native support for atomic operations
# On these platforms we will use logic emulated by libatomic
set(LINK_WITH_ATOMIC_LIBRARY OFF)

CHECK_CXX_SOURCE_COMPILES("
#include <cstdint>
int main() {
    uint64_t x = 1;
    __atomic_add_fetch(&x, 0, __ATOMIC_RELAXED);
    return x;
}
" HAVE__ATOMIC_ADD_FETCH)

if (HAVE__ATOMIC_ADD_FETCH)
    message(STATUS "We have __atomic_add_fetch on this platform")
else()
    message(STATUS "We have no __atomic_add_fetch, will try linking with libatomic")

    check_library_exists(atomic __atomic_add_fetch_8 "" HAVE_LIBATOMIC)

    if (HAVE_LIBATOMIC)
        message(STATUS "Linked with atomic library")
        set(LINK_WITH_ATOMIC_LIBRARY ON)
    else()
        message(STATUS "We have no support for __atomic_add_fetch in atomic library, skip linking")
    endif()
endif()

CHECK_CXX_SOURCE_COMPILES("
#include <cstdint>
int main() {
    uint64_t x = 1;
    __sync_fetch_and_add(&x, 1);
    return x;
}
" HAVE__SYNC_FETCH_AND_ADD)

if (HAVE__SYNC_FETCH_AND_ADD) 
    message(STATUS "We have __sync_fetch_and_add on this platform")
else()
    # We know that it happens for mipsel platform due to https://reviews.llvm.org/D45691
    message(STATUS "We have no __sync_fetch_and_add on this platform, will try linking with libatomic")
    
    check_library_exists(atomic __sync_fetch_and_add_8 "" HAVE_LIBATOMIC_SYNC_FETCH_AND_ADD)

    if (HAVE_LIBATOMIC_SYNC_FETCH_AND_ADD)
        message(STATUS "Linked with atomic library")
        set(LINK_WITH_ATOMIC_LIBRARY ON)
    else()
        message(STATUS "We have no support for __sync_fetch_and_add in atomic library, skip linking")
    endif()
endif()

option(ENABLE_NETMAP_SUPPORT "Enable Netmap support" OFF)

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

# It's enabled by default but can be disabled using: 
# cmake .. -DENABLE_CAPNP_SUPPORT=OFF
option(ENABLE_CAPNP_SUPPORT "Enable Cap'N'Proto support build" ON)

if (ENABLE_CAPNP_SUPPORT)

message(STATUS "We will build Cap'N'Proto support")

find_program(CAPNP_BINARY capnp PATHS "${CAPNP_CUSTOM_INSTALL_PATH}/bin" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

if (CAPNP_BINARY)
    message(STATUS "Found capnp compiler: ${CAPNP_BINARY}")
else()
    message(FATAL_ERROR "Can't find capnp compiler")
endif()

# We need to explicitly provide PATH for capnp to allow it to find capnpc-c++ 
SET(CAPNP_ENVIRONMENT "LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH}" "PATH=$ENV{PATH}:${CAPNP_CUSTOM_INSTALL_PATH}/bin")

# We cannot pass environment variables before tool call on Windows and we actually do need it
if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  SET(CAPNP_ENVIRONMENT "")
endif()

# Generate capnp bindings
ADD_CUSTOM_COMMAND(
    OUTPUT ${PROJECT_SOURCE_DIR}/simple_packet_capnp/simple_packet.capnp.c++
    DEPENDS ${PROJECT_SOURCE_DIR}/simple_packet_capnp/simple_packet.capnp
    COMMAND ${CAPNP_ENVIRONMENT} ${CAPNP_BINARY} compile --output c++:${PROJECT_SOURCE_DIR}/simple_packet_capnp --src-prefix=${PROJECT_SOURCE_DIR}/simple_packet_capnp ${PROJECT_SOURCE_DIR}/simple_packet_capnp/simple_packet.capnp
    COMMENT "Build Cap'n'Proto binding for C++"
)

add_library(simple_packet_capnp STATIC simple_packet_capnp/simple_packet.capnp.c++)

endif()

# It's disabled by default as we have no CLickhouse support in system repos on many platforms but can be enabled using: 
# cmake .. -DCLICKHOUSE_SUPPORT=ON
option(CLICKHOUSE_SUPPORT "Enable Cap'N'Proto support build" OFF)

if (CLICKHOUSE_SUPPORT)
    find_library(CLICKHOUSE_LIBRARY_PATH NAMES clickhouse-cpp-lib PATHS "${CLICKHOUSE_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    if (CLICKHOUSE_LIBRARY_PATH)
        message(STATUS "Found libclickhouse library: ${CLICKHOUSE_LIBRARY_PATH}")

	# Enable Clickhouse define in code
	add_definitions(-DCLICKHOUSE_SUPPORT)

    else()
        message(FATAL_ERROR "We could not find libclickhouse library")
    endif()

    include_directories("${CLICKHOUSE_CUSTOM_INSTALL_PATH}/include")
endif()

# Our LPM library
add_library(patricia STATIC libpatricia/patricia.cpp)

# Graphite metrics
add_library(graphite_metrics STATIC metrics/graphite.cpp)
target_link_libraries(fastnetmon graphite_metrics)

# InfluxDB metrics
add_library(influxdb_metrics STATIC metrics/influxdb.cpp)
target_link_libraries(fastnetmon influxdb_metrics)

# Clickhouse metrics
if (CLICKHOUSE_SUPPORT)
add_library(clickhouse_metrics STATIC metrics/clickhouse.cpp)
target_link_libraries(clickhouse_metrics ${CLICKHOUSE_LIBRARY_PATH})
target_link_libraries(fastnetmon clickhouse_metrics)
endif()

add_library(fastnetmon_pcap_format STATIC fastnetmon_pcap_format.cpp)

# Our tools library
add_library(fast_library STATIC fast_library.cpp)

# Our ipfix database library
add_library(ipfix_rfc STATIC ipfix_fields/ipfix_rfc.cpp)

# IPFIX collector as separate module
add_library(ipfix_collector STATIC netflow_plugin/ipfix_collector.cpp)
target_link_libraries(ipfix_collector ipfix_rfc)

# Netflow v9 collector as separate module
add_library(netflow_v9_collector STATIC netflow_plugin/netflow_v9_collector.cpp)

# Netflow v5 collector as separate module
add_library(netflow_v5_collector STATIC netflow_plugin/netflow_v5_collector.cpp)

add_library(bgp_protocol STATIC bgp_protocol.cpp)

# Here we store some service code for getting IP protocol name by number
add_library(iana_ip_protocols STATIC iana_ip_protocols.cpp)

# BGP Flow Spec
add_library(bgp_protocol_flow_spec STATIC bgp_protocol_flow_spec.cpp)
target_link_libraries(bgp_protocol_flow_spec iana_ip_protocols bgp_protocol)

# Our filtering library
add_library(filter STATIC filter.cpp)
target_link_libraries(filter bgp_protocol bgp_protocol_flow_spec)

# Our logic library
add_library(fastnetmon_logic STATIC fastnetmon_logic.cpp)

# API library
add_library(fastnetmon_api STATIC api.cpp)


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
endif()

# We need to check that kernel headers actually support it as it's relatively new thing

CHECK_CXX_SOURCE_COMPILES("
#include <linux/bpf.h> 
int main() {
    bpf_stats_type my_bpf_type;
    return 1;
}
" HAVE_BPF_STATS_TYPE)


if (${HAVE_BPF_STATS_TYPE})
    message(STATUS "Kernel has enum bpf_stats_type declared")
else()
    message(STATUS "Kernel does not have enum bpf_stats_type declared. Try to declare our own to address libbpf issue: https://github.com/libbpf/libbpf/issues/249")
    add_definitions(-DDECLARE_FAKE_BPF_STATS)
endif()

# We need to check that kernel headers actually include it


CHECK_CXX_SOURCE_COMPILES("
#include <linux/bpf.h>
int main() {
    bpf_link_type my_bpf_type;
    return 1;
}
" HAVE_BPF_LINK_TYPE)

if (${HAVE_BPF_LINK_TYPE})
    message(STATUS "Kernel has enum bpf_link_type declared")
else()
    message(STATUS "Kernel does not have enum bpf_link_type declared. Try to declare our own to address libbpf issue: https://github.com/libbpf/libbpf/issues/249")
    add_definitions(-DDECLARE_FAKE_BPF_LINK_TYPE)
endif()


# We enable XDP plugin build for all platforms which support it
# It can be disabled manually using flag: -DENABLE_AF_XDP_SUPPORT=FALSE
option(ENABLE_AF_XDP_SUPPORT "Enables build for AF_XDP" ON)

CHECK_CXX_SOURCE_COMPILES("
#include <linux/if_xdp.h> 
int main() {
    return 1;
}
" HAVE_AF_XDP)

# If XDP build enabled then we need to confirm that system has support for it
if (${ENABLE_AF_XDP_SUPPORT})

  if (${HAVE_AF_XDP})
      message(STATUS "Your system has support for AF_XDP and we will build XDP plugin")
  else()
      # It may be old Linux, macOS, FreeBSD or Windows
      message(STATUS "Your system does not support AF_XDP, disabling compilation of XDP plugin")
      set (ENABLE_AF_XDP_SUPPORT FALSE)
  endif()

endif()


if (ENABLE_AF_XDP_SUPPORT)
    add_definitions(-DFASTNETMON_ENABLE_AF_XDP)
    add_library(xdp_plugin STATIC xdp_plugin/xdp_collector.cpp)
    set(ENABLE_LIBBPF_SUPPORT TRUE)
    set(ENABLE_LIBELF_SUPPORT TRUE)
endif()

if (KAFKA_SUPPORT)
    # We need to enable it explicitly
    add_definitions(-DKAFKA)

    # cpp-kafka uses these header files from their header too
    include_directories("${LIB_RDKAFKA_INSTALL_PATH}/include")

    # cppkafka
    find_library(LIBKAFKA_CPP_LIBRARY_PATH names "cppkafka" PATHS "${LIB_CPP_KAFKA_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    include_directories("${LIB_CPP_KAFKA_INSTALL_PATH}/include")

    if (NOT LIBKAFKA_CPP_LIBRARY_PATH)
        message(FATAL_ERROR "Could not find cppkafka library")
    else()
        message(STATUS "Will use cppkafka library from ${LIBKAFKA_CPP_LIBRARY_PATH}")
    endif()

endif()

if (ENABLE_LIBELF_SUPPORT) 
    # We do not use it directly but we need it as dependency for libbpf
    # include_directories("${LIBELF_CUSTOM_INSTALL_PATH/include") 

    find_library(LIBELF_LIBRARY_PATH names "elf" PATHS "${LIBELF_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    if (NOT LIBELF_LIBRARY_PATH)
        message(FATAL_ERROR "Could not find libelf library")
    else()
        message(STATUS "Will use libelf library from ${LIBELF_LIBRARY_PATH}")
    endif()
endif()

if (ENABLE_LIBBPF_SUPPORT) 
    include_directories("${LIBBPF_CUSTOM_INSTALL_PATH}/include")

    find_library(LIBBPF_LIBRARY_PATH NAMES "bpf" PATHS "${LIBBPF_CUSTOM_INSTALL_PATH}/lib64" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    if (NOT LIBBPF_LIBRARY_PATH)
        message(FATAL_ERROR "Could not find libbpf library")
    else()
        message(STATUS "Will use libbpf from ${LIBBPF_LIBRARY_PATH}")
    endif()

endif()

### Look for libpcap

find_path(LIBPCAP_INCLUDES_FOLDER NAMES pcap.h PATHS "${LIBPCAP_CUSTOM_INSTALL_PATH}/include" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

find_library(LIBPCAP_LIBRARY_PATH NAMES pcap PATHS "${LIBPCAP_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

if (LIBPCAP_INCLUDES_FOLDER AND LIBPCAP_LIBRARY_PATH)
    message(STATUS "We found pcap library ${LIBPCAP_LIBRARY_PATH}")

    include_directories(${LIBPCAP_INCLUDES_FOLDER})
else()
    message(FATAL_ERROR "We can't find pcap library")
endif()


if (ENABLE_AF_XDP_SUPPORT)
    target_link_libraries(xdp_plugin ${LIBBPF_LIBRARY_PATH} ${LIBELF_LIBRARY_PATH})
endif()

# Library with data types for parsing network structures
add_library(network_data_structures STATIC network_data_structures.cpp)

# Speed counters lib
add_library(speed_counters STATIC speed_counters.cpp)
target_link_libraries(speed_counters fast_library)

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

# Netflow templates
add_library(netflow_template STATIC netflow_plugin/netflow_template.cpp)

# netflow library
add_library(netflow STATIC netflow_plugin/netflow.cpp)

# netflow plugin
add_library(netflow_plugin STATIC netflow_plugin/netflow_collector.cpp)
target_link_libraries(netflow_plugin ipfix_collector netflow_v9_collector netflow_v5_collector netflow netflow_template)

if (ENABLE_PCAP_SUPPORT) 
  # pcap plugin
  add_library(pcap_plugin STATIC pcap_plugin/pcap_collector.cpp)
  target_link_libraries(pcap_plugin ${LIBPCAP_LIBRARY_PATH})
endif()

find_package(Threads)

add_library(exabgp_action STATIC actions/exabgp_action.cpp)

if (LINK_WITH_ABSL)
    find_package(absl REQUIRED ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    # TODO: check that we actually found it. Otherwise trigger fatal erorr
endif()

if (ENABLE_PCAP_SUPPORT)
    add_definitions(-DENABLE_PCAP)
endif()

if (ENABLE_GOBGP_SUPPORT)
    add_definitions(-DENABLE_GOBGP)

    # GoBGP client library
    add_library(gobgp_client STATIC gobgp_client/gobgp_client.cpp)

    add_library(gobgp_action STATIC actions/gobgp_action.cpp)

    # We use find_package for Windows as our approach for *nix platforms leads to bunch of linking errors
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
      # Will be great to use this approach for all builds but it's relatively tricky to accomplish
      # Debian 11 has no cmake files in official gRPC packages and only Debian Sid got them: https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1006237
      # gRPC bug tracker entry: https://github.com/grpc/grpc/issues/29977
      # https://packages.debian.org/sid/amd64/libgrpc-dev/filelist
      # Fedora has cmake files: https://packages.fedoraproject.org/pkgs/grpc/grpc-devel/fedora-38.html#files
      # Epel 9 has cmake files: https://packages.fedoraproject.org/pkgs/grpc/grpc-devel/epel-9.html#files
      # Both latest Ubuntu 22.04 and 22.10 does not offer it in official package: https://packages.ubuntu.com/kinetic/amd64/libgrpc-dev/filelist
      # As Ubuntu and Debian our main platforms we will keep old logic for them until LTS / stable versions of Ubuntu and Debian receive it
      # We need to offer smooth developer experience and allow options to build FastNetMon at least on these platforms without using custom compiled libraries 
      find_package(gRPC CONFIG REQUIRED ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
    
      if (gRPC_FOUND)
        message(STATUS "Found gRPC")
      else()
        message(FATAL_ERROR "NOT Found gRPC module")
      endif()

        target_link_libraries(gobgp_client gRPC::grpc gRPC::grpc++)

        target_link_libraries(gobgp_action gRPC::grpc gRPC::grpc++ gobgp_client)

    else()

      find_path(GRPC_INCLUDES_FOLDER NAMES grpc/grpc.h PATHS "${GRPC_CUSTOM_INSTALL_PATH}/include" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
      find_library(GRPC_LIBRARY_GRPC_PATH NAMES grpc PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
      find_library(GRPC_LIBRARY_GPR_PATH NAMES gpr PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
      find_library(GRPC_LIBRARY_GRPC_CPP_PATH NAMES grpc++ PATHS "${GRPC_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR}) 

      if (GRPC_INCLUDES_FOLDER AND GRPC_LIBRARY_GRPC_PATH AND GRPC_LIBRARY_GPR_PATH AND GRPC_LIBRARY_GRPC_CPP_PATH)
        include_directories(${GRPC_INCLUDES_FOLDER})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GRPC_PATH})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GPR_PATH})
        target_link_libraries(gobgp_action ${GRPC_LIBRARY_GRPC_CPP_PATH})
        target_link_libraries(gobgp_action gobgp_client)

        target_link_libraries(gobgp_client ${GRPC_LIBRARY_GRPC_PATH})
        target_link_libraries(gobgp_client ${GRPC_LIBRARY_GPR_PATH})
        target_link_libraries(gobgp_client ${GRPC_LIBRARY_GRPC_CPP_PATH})

	    message(STATUS "Found gRPC library: ${GRPC_LIBRARY_GRPC_PATH} ${GRPC_LIBRARY_GPR_PATH} ${GRPC_LIBRARY_GRPC_CPP_PATH}")
      else()
        message(FATAL_ERROR "Could not find gRPC library")
      endif()

    endif()

    if (LINK_WITH_ABSL)
        target_link_libraries(gobgp_action absl::base absl::synchronization)
    endif()

    if (DO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD)
      # We add our custom path to Protobuf to top of search_list used by find_package: https://cmake.org/cmake/help/latest/variable/CMAKE_PREFIX_PATH.html
      # This approach has advantage over Protobuf_DIR which requires us to set direct path to cmake folder of custom built dependency
      # which resides in vendor specific folder with name lib which may be lib64 on CentOS platforms:
      # protobuf_21_12/lib/cmake/protobuf or  protobuf_21_12/lib64/cmake/protobuf on CentOS 
      list(APPEND CMAKE_PREFIX_PATH ${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}) 
    endif()

    # Apparently it's required to set this flag because without this flag set it cannot find protoc when custom library path is in use
    # https://github.com/protocolbuffers/protobuf/issues/1931
    set(protobuf_MODULE_COMPATIBLE true)

    # Switch to use to configuration supplied by custom Protobuf installation as it may be better
    find_package(Protobuf CONFIG)

    if (NOT Protobuf_FOUND)
      # Fall back to module supplied by cmake to search for Protobuf
      # https://cmake.org/cmake/help/latest/module/FindProtobuf.html
      find_package(Protobuf MODULE REQUIRED)
    endif()

    if (Protobuf_FOUND)
      message(STATUS "Found Protobuf ${Protobuf_VERSION}")

      # Empty checks are very tricky in cmake:
      # https://cmake.org/pipermail/cmake/2011-October/046939.html
      if ("${Protobuf_PROTOC_EXECUTABLE}" STREQUAL "")
        message(FATAL_ERROR "Protobuf was found but we did not find protoc")
      endif()

      message(STATUS "Found Protobuf compiler: '${Protobuf_PROTOC_EXECUTABLE}'")

      # We need to explicitly provide paths for our dependency libraries in environment variable LD_LIBRARY_PATH as we use non system path for them
      # CentOS uses lib64 but Debian / Ubuntu still use lib for Protobuf, that's why we keep both of them
      set(ENV{LD_LIBRARY_PATH} "${GCC_INSTALL_PATH}/lib64:${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/lib:${PROTOCOL_BUFFERS_CUSTOM_INSTALL_PATH}/lib64:${GRPC_CUSTOM_INSTALL_PATH}/lib")

      message(STATUS "Protobuf include directory: ${Protobuf_INCLUDE_DIRS}") 

      include_directories(${Protobuf_INCLUDE_DIRS})
    else()
      message(FATAL_ERROR "NOT Found Protobuf module")
    endif()

    target_link_libraries(gobgp_action protobuf::libprotobuf)

    # Search for gRPC plugin for Protobuf, it's just binary
    find_program(GRPC_CPP_PLUGIN grpc_cpp_plugin PATHS "${GRPC_CUSTOM_INSTALL_PATH}/bin" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    if (GRPC_CPP_PLUGIN) 
        message(STATUS "Found Protobuf gRPC compiler plugin: ${GRPC_CPP_PLUGIN}")
    else()
        message(FATAL_ERROR "Can't find Protobuf gRPC compiler plugin")
    endif()

    message(STATUS "Building protobuf and gRPC mappings for C++")

    execute_process(COMMAND ${Protobuf_PROTOC_EXECUTABLE} -I ${PROJECT_SOURCE_DIR}/gobgp_client --grpc_out=${PROJECT_SOURCE_DIR}/gobgp_client --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROJECT_SOURCE_DIR}/gobgp_client/gobgp.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code for gobgp.proto gRPC: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    execute_process(COMMAND ${Protobuf_PROTOC_EXECUTABLE} -I  ${PROJECT_SOURCE_DIR}/gobgp_client --cpp_out=${PROJECT_SOURCE_DIR}/gobgp_client ${PROJECT_SOURCE_DIR}/gobgp_client/gobgp.proto ${PROJECT_SOURCE_DIR}/gobgp_client/attribute.proto  ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code for gobgp.proto and attribute.proto Protobuf: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    message(STATUS "Building Protobuf bindings for C++ for Flow Data")

    execute_process(COMMAND ${Protobuf_PROTOC_EXECUTABLE} -I ${PROJECT_SOURCE_DIR}/traffic_output_formats/protobuf --cpp_out=${PROJECT_SOURCE_DIR}/traffic_output_formats/protobuf ${PROJECT_SOURCE_DIR}/traffic_output_formats/protobuf/traffic_data.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code for FlowData Protobuf: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")
    
    # Build Flow Data binary 
    add_library(traffic_data_library STATIC traffic_output_formats/protobuf/traffic_data.pb.cc)

    add_library(protobuf_traffic_format STATIC traffic_output_formats/protobuf/protobuf_traffic_format.cpp)
    target_link_libraries(protobuf_traffic_format traffic_data_library)

    # Build gRPC and protocol buffers libraries and link they to gobgp_action
    add_library(gobgp_api_client_pb_cc STATIC gobgp_client/gobgp.pb.cc)
    add_library(gobgp_api_client_grpc_pb_cc STATIC gobgp_client/gobgp.grpc.pb.cc)

    # It does not work without on Windows but works fine on *nix
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
      target_link_libraries(gobgp_api_client_grpc_pb_cc gRPC::grpc gRPC::grpc++)
    endif()

    target_link_libraries(gobgp_action gobgp_api_client_pb_cc)
    target_link_libraries(gobgp_action gobgp_api_client_grpc_pb_cc)

    # Add attributes
    add_library(attribute_pb_cc STATIC gobgp_client/attribute.pb.cc)

    target_link_libraries(attribute_pb_cc protobuf::libprotobuf)

    target_link_libraries(gobgp_action attribute_pb_cc)

    # FastNetMon API
    add_definitions(-DFASTNETMON_API)    

    execute_process(COMMAND ${Protobuf_PROTOC_EXECUTABLE} -I ${PROJECT_SOURCE_DIR} --grpc_out=${PROJECT_SOURCE_DIR} --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN} ${PROJECT_SOURCE_DIR}/fastnetmon_internal_api.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Protoc return code for gRPC fastnetmon_internal_api.proto: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    execute_process(COMMAND ${Protobuf_PROTOC_EXECUTABLE} -I ${PROJECT_SOURCE_DIR} --cpp_out=${PROJECT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/fastnetmon_internal_api.proto ERROR_VARIABLE PROTOC_STDERR RESULT_VARIABLE PROTOC_RETURN_CODE OUTPUT_STRIP_TRAILING_WHITESPACE) 

    message(STATUS "Protoc return code for Protobuf fastnetmon_internal_api.proto: ${PROTOC_RETURN_CODE} std err: ${PROTOC_STDERR}")

    add_library(fastnetmon_grpc_pb_cc STATIC fastnetmon_internal_api.grpc.pb.cc)
    add_library(fastnetmon_pb_cc STATIC fastnetmon_internal_api.pb.cc)

    add_executable(fastnetmon_api_client fastnetmon_api_client.cpp)

    if (LINK_WITH_ABSL)
        target_link_libraries(fastnetmon_api_client  absl::base absl::synchronization)
    endif()

    # We use another way to specify dependencies for Windows as our standard approach clearly does not work
    # https://www.f-ax.de/dev/2020/11/08/grpc-plugin-cmake-support.html
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
      target_link_libraries(fastnetmon_api_client gRPC::grpc gRPC::grpc++)
    else()
      target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GPR_PATH})
      target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GRPC_CPP_PATH})
      target_link_libraries(fastnetmon_api_client ${GRPC_LIBRARY_GRPC_PATH})
    endif()

    target_link_libraries(fastnetmon_api_client fastnetmon_grpc_pb_cc)
    target_link_libraries(fastnetmon_api_client fastnetmon_pb_cc)

    target_link_libraries(fastnetmon_api_client protobuf::libprotobuf)

    if (KAFKA_SUPPORT)
        target_link_libraries(fastnetmon ${LIBKAFKA_CPP_LIBRARY_PATH})
    endif()

    if (${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
      target_link_libraries(fastnetmon gRPC::grpc gRPC::grpc++)
    else()
      target_link_libraries(fastnetmon ${GRPC_LIBRARY_GPR_PATH})
      target_link_libraries(fastnetmon ${GRPC_LIBRARY_GRPC_CPP_PATH})
      target_link_libraries(fastnetmon ${GRPC_LIBRARY_GRPC_PATH})
    endif()

    target_link_libraries(fastnetmon fastnetmon_grpc_pb_cc)
    target_link_libraries(fastnetmon fastnetmon_pb_cc)

    target_link_libraries(fastnetmon protobuf::libprotobuf)
endif()

# example plugin
add_library(example_plugin STATIC example_plugin/example_collector.cpp)

if (ENABLE_NETMAP_SUPPORT)
    # Netmap plugin
    set(NETMAP_INCLUDE_DIRS "netmap_plugin/netmap_includes")
    include_directories(${NETMAP_INCLUDE_DIRS})
    add_library(netmap_plugin STATIC netmap_plugin/netmap_collector.cpp)
endif()

# Client tool
add_executable(fastnetmon_client fastnetmon_client.cpp)

# Find boost: http://www.cmake.org/cmake/help/v3.0/module/FindBoost.html

# Enable detailed errors
set(Boost_DETAILED_FAILURE_MSG ON)
# set(Boost_DEBUG ON)

# Boost.System is a library that, in essence, defines four classes to identify errors. All four classes were added to the standard library with C++11. If your development environment supports C++11, you don’t need to use Boost.System. However, since many Boost libraries use Boost.System, you might encounter Boost.System through those other libraries.
# Boost.System is a library that, in essence, defines four classes to identify errors. All four classes were added to the standard library with C++11. If your development environment supports C++11, you don’t need to use Boost.System. However, since many Boost libraries use Boost.System, you might encounter Boost.System through those other libraries.
# TODO: we may not need system at all
find_package(Boost COMPONENTS serialization thread regex program_options OPTIONAL_COMPONENTS system REQUIRED ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

if(Boost_FOUND)
    message(STATUS "Found Boost: ${Boost_LIBRARIES} ${Boost_INCLUDE_DIRS}")

    # We can get separate library paths for each library too
    message(STATUS "Found Boost library program_options: ${Boost_PROGRAM_OPTIONS_LIBRARY}")

    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(fastnetmon ${Boost_LIBRARIES})
    target_link_libraries(fast_library ${Boost_LIBRARIES})
    target_link_libraries(fastnetmon_client ${Boost_PROGRAM_OPTIONS_LIBRARY})
endif()

target_link_libraries(fast_library patricia)
target_link_libraries(fast_library fastnetmon_pcap_format)
target_link_libraries(fast_library iana_ip_protocols)

# Try to find ncurses library
find_package(Curses REQUIRED)

if(CURSES_FOUND)
    message(STATUS "Found curses library: ${CURSES_LIBRARIES}")
    message(STATUS "Found curses includes: ${CURSES_INCLUDE_DIRS}")

    include_directories(${CURSES_INCLUDE_DIRS})
    target_link_libraries(fastnetmon_client ${CURSES_LIBRARIES})
else()
    message(STATUS "We did not find curses library")
endif()

### Move this code to cmake module

# Try to find hiredis in a specific folder
find_path(HIREDIS_INCLUDES_FOLDER NAMES hiredis/hiredis.h PATHS "${HIREDIS_CUSTOM_INSTALL_PATH}/include" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

# Try to find hiredis library path
find_library(HIREDIS_LIBRARY_PATH NAMES hiredis PATHS "${HIREDIS_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

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
    find_path(OPENSSL_INCLUDES_FOLDER NAMES "openssl/rsa.h" PATHS "${OPENSSL_CUSTOM_INSTALL_PATH}/include" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
    
    # Check that we found headers
    if (OPENSSL_INCLUDES_FOLDER) 
        message(STATUS "We found OpenSSL library headers: ${OPENSSL_INCLUDES_FOLDER}")
        include_directories(${OPENSSL_INCLUDES_FOLDER})
    else()
        message(FATAL_ERROR "Could not find OpenSSL headers")
    endif()

    find_library(OPENSSL_LIBRARY_PATH NAMES ssl PATHS "${OPENSSL_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
    find_library(OPENSSL_CRYPTO_LIBRARY_PATH NAMES crypto PATHS "${OPENSSL_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    # Check that we found libraries
    if (OPENSSL_LIBRARY_PATH AND OPENSSL_CRYPTO_LIBRARY_PATH)
        message(STATUS "We found OpenSSL library: ${OPENSSL_LIBRARY_PATH} ${OPENSSL_CRYPTO_LIBRARY_PATH}")
    else()
        message(FATAL_ERROR "Could not find OpenSSL libraries")
    endif()
endif()

if (ENABLE_CAPNP_SUPPORT)
    add_definitions(-DENABLE_CAPNP)

    find_library(CAPNP_LIBRARY_PATH NAMES capnp PATHS "${CAPNP_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
    find_library(CAPNP_KJ_LIBRARY_PATH NAMES kj PATHS "${CAPNP_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    if (CAPNP_LIBRARY_PATH AND CAPNP_KJ_LIBRARY_PATH)
        message(STATUS "We found capnp and kj libraries: ${CAPNP_LIBRARY_PATH} ${CAPNP_KJ_LIBRARY_PATH}")
    else()
        message(FATAL_ERROR "Could not find capnp libraries")
    endif()

    include_directories("${CAPNP_CUSTOM_INSTALL_PATH}/include")

    target_link_libraries(simple_packet_capnp ${CAPNP_LIBRARY_PATH} ${CAPNP_KJ_LIBRARY_PATH})

    # Link it with cap'n'p stuff
    target_link_libraries(fast_library simple_packet_capnp)

endif()


# With this flag we can control MongoDB build via console: cmake .. -DENABLE_MONGODB_SUPPORT=ON
option(ENABLE_MONGODB_SUPPORT "Enable MongoDB support build" ON)

if (ENABLE_MONGODB_SUPPORT) 

    ### Find mongo-c
    find_path(MONGOC_INCLUDES_FOLDER NAMES libmongoc-1.0/mongoc.h PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/include" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
    find_library(MONGOC_LIBRARY_PATH NAMES mongoc-1.0 PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    ### find bson
    find_path(BSON_INCLUDES_FOLDER NAMES libbson-1.0/bson.h PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/include" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
    find_library(BSON_LIBRARY_PATH NAMES bson-1.0 PATHS "${MONGO_C_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

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

endif()

### Look for log4cpp

# Try to find log4cpp includes path
find_path(LOG4CPP_INCLUDES_FOLDER NAMES log4cpp/Appender.hh PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/include" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

# Try to find log4cpp library path
find_library(LOG4CPP_LIBRARY_PATH NAMES log4cpp PATHS "${LOG4CPP_CUSTOM_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

if (LOG4CPP_INCLUDES_FOLDER AND LOG4CPP_LIBRARY_PATH)
    include_directories(${LOG4CPP_INCLUDES_FOLDER})
    message(STATUS "We have found log4cpp: ${LOG4CPP_LIBRARY_PATH}")
else()
    message(FATAL_ERROR "We can't find log4cpp. We can't build project")
endif()

target_link_libraries(fast_library ${OPENSSL_LIBRARY_PATH})
target_link_libraries(fast_library ${OPENSSL_CRYPTO_LIBRARY_PATH})

target_link_libraries(fastnetmon ${LOG4CPP_LIBRARY_PATH})

target_link_libraries(fastnetmon ${CMAKE_THREAD_LIBS_INIT})

target_link_libraries(fastnetmon fastnetmon_api)

# We need it for boost::stacktrace
# To address undefined reference to symbol 'dladdr@@GLIBC_2.2.5
target_link_libraries(fastnetmon ${CMAKE_DL_LIBS})

# Our libs
target_link_libraries(fastnetmon patricia)
target_link_libraries(fastnetmon fastnetmon_pcap_format)

target_link_libraries(fastnetmon ipfix_rfc)

target_link_libraries(fastnetmon_logic filter bgp_protocol bgp_protocol_flow_spec exabgp_action)

target_link_libraries(fastnetmon_logic protobuf_traffic_format)

target_link_libraries(fastnetmon_logic speed_counters)

# Link to our functions
target_link_libraries(fastnetmon fast_library)



# link to our unified parser
target_link_libraries(fastnetmon ${OPENSSL_LIBRARY_PATH})
target_link_libraries(fastnetmon ${OPENSSL_CRYPTO_LIBRARY_PATH})

if (ENABLE_GOBGP_SUPPORT)
    target_link_libraries(fastnetmon gobgp_action)
endif()

target_link_libraries(fastnetmon exabgp_action)

if (ENABLE_AFPACKET_SUPPORT)
    target_link_libraries(fastnetmon afpacket_plugin)
endif()

if (ENABLE_AF_XDP_SUPPORT) 
    target_link_libraries(fastnetmon xdp_plugin)
endif()

target_link_libraries(fastnetmon sflow_plugin netflow_plugin example_plugin)

if (ENABLE_PCAP_SUPPORT)
target_link_libraries(fastnetmon pcap_plugin)
endif()

target_link_libraries(fastnetmon fastnetmon_logic)

if (ENABLE_NETMAP_SUPPORT)
    target_link_libraries(fastnetmon netmap_plugin)
endif()

# According to YunQiang Su debian-mips@lists.debian.org 
# Due to the limitation of gnu ld, -latomic should be put after library which calls it
# I decided that keeping it here as very last dependency is pretty good option to guarantee it
if (LINK_WITH_ATOMIC_LIBRARY) 
    target_link_libraries(fastnetmon atomic)
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
endif()

# cmake .. -DBUILD_PCAP_READER=ON
if (BUILD_PCAP_READER)
    add_executable(fastnetmon_pcap_reader pcap_reader.cpp)

    target_link_libraries(fastnetmon_pcap_reader patricia)
    target_link_libraries(fastnetmon_pcap_reader fastnetmon_pcap_format)

    target_link_libraries(fastnetmon_pcap_reader fast_library)
    target_link_libraries(fastnetmon_pcap_reader ${LOG4CPP_LIBRARY_PATH})
    target_link_libraries(fastnetmon_pcap_reader netflow_plugin)   
    target_link_libraries(fastnetmon_pcap_reader sflow_plugin)

    if (ENABLE_NETMAP_SUPPORT)
        target_link_libraries(fastnetmon_pcap_reader netmap_plugin)
    endif()
endif()

# cmake -DBUILD_TESTS=ON ..
if (BUILD_TESTS) 
    add_executable(fastnetmon_tests fastnetmon_tests.cpp)
    target_link_libraries(fastnetmon_tests fast_library)
    target_link_libraries(fastnetmon_tests ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(fastnetmon_tests ${Boost_LIBRARIES})
    target_link_libraries(fastnetmon_tests ${LOG4CPP_LIBRARY_PATH})

    find_library(GTEST_LIBRARY_PATH names "gtest" PATHS "${GTEST_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})
    
    if (GTEST_LIBRARY_PATH) 
        message(STATUS "Found gTest library: ${GTEST_LIBRARY_PATH}")
    else()
        message(FATAL_ERROR "Can't find gTest library")
    endif()

    find_library(GTEST_MAIN_LIBRARY_PATH names "gtest_main" PATHS "${GTEST_INSTALL_PATH}/lib" ${DISABLE_DEFAULT_PATH_SEARCH_VAR})

    if (GTEST_MAIN_LIBRARY_PATH)
        message(STATUS "Found gTest main library: ${GTEST_MAIN_LIBRARY_PATH}")
    else()
        message(FATAL_ERROR "Can't find gTest main library")
    endif()


    set(GOOGLE_TEST_INCLUDE_DIRS "${GTEST_INSTALL_PATH}/include")

    # Compiled Google Library
    include_directories(${GOOGLE_TEST_INCLUDE_DIRS})
    target_link_libraries(fastnetmon_tests ${GTEST_LIBRARY_PATH} ${GTEST_MAIN_LIBRARY_PATH})

    add_executable(traffic_structures_tests tests/traffic_structures_performance_tests.cpp)
    target_link_libraries(traffic_structures_tests ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${LOG4CPP_LIBRARY_PATH} fast_library)

    add_executable(traffic_structures_tests_real_traffic tests/traffic_structures_performance_tests_real_traffic.cpp)
    target_link_libraries(traffic_structures_tests_real_traffic ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${LOG4CPP_LIBRARY_PATH} fast_library)

    add_executable(speed_counters_performance_test tests/speed_counters_performance_test.cpp)
    target_link_libraries(speed_counters_performance_test ${Boost_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} fast_library ${LOG4CPP_LIBRARY_PATH} speed_counters)

    add_executable(patricia_performance_tests tests/patricia_performance_tests.cpp)
    target_link_libraries(patricia_performance_tests patricia fast_library ${LOG4CPP_LIBRARY_PATH})
endif()

# Check default values prepared by CMAKE for us
message(STATUS "Install BINDIR path: ${CMAKE_INSTALL_BINDIR}")
message(STATUS "Install SBINDIR path: ${CMAKE_INSTALL_SBINDIR}")
message(STATUS "Install SYSCONFDIR path: ${CMAKE_INSTALL_SYSCONFDIR}")
message(STATUS "Install MANDIR path: ${CMAKE_INSTALL_MANDIR}")

# We use this flag on Debian upstream builds because we apparently need absolute paths here
# But for Homebrew we need option to disable it and use relative paths
# cmake .. -DSET_ABSOLUTE_INSTALL_PATH=OFF
option(SET_ABSOLUTE_INSTALL_PATH "Enables use of absolute install paths" ON)

if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" OR ${CMAKE_SYSTEM_NAME} STREQUAL "DragonFly")
    set(CMAKE_INSTALL_BINDIR "bin")
    set(CMAKE_INSTALL_SBINDIR "bin")
    set(CMAKE_INSTALL_SYSCONFDIR "etc")
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    if (SET_ABSOLUTE_INSTALL_PATH)
        set(CMAKE_INSTALL_BINDIR "/usr/bin")
        set(CMAKE_INSTALL_SBINDIR "/usr/sbin")
        set(CMAKE_INSTALL_SYSCONFDIR "/etc")
        set(CMAKE_INSTALL_MANDIR "/usr/share/man")
    endif()
elseif (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    message(STATUS "We run on Apple platform")
else()
    message(STATUS "We run on platform ${CMAKE_SYSTEM_NAME} and we do not touch install paths")
    # Do not touch these variables and use default values
endif()

install(TARGETS fastnetmon DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(TARGETS fastnetmon_client DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(TARGETS fastnetmon_api_client DESTINATION "${CMAKE_INSTALL_BINDIR}")

install(FILES fastnetmon.conf DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

# Install blank files for networks list and whitelist
install(FILES networks_list DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")
install(FILES networks_whitelist DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}")

# man pages
install(FILES man/fastnetmon.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
install(FILES man/fastnetmon_client.1 DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)

if (SET_ABSOLUTE_INSTALL_PATH)
    # Unfortunately, we have no cross-platform option to install systemd units in current versions of cmake
    set(CMAKE_INSTALL_SYSTEMD_SERVICEDIR "/lib/systemd/system"  CACHE PATH "Location for systemd service files")

    # Generate unit file
    if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
        configure_file(fastnetmon.service.in "${CMAKE_CURRENT_BINARY_DIR}/fastnetmon.service" @ONLY)
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/fastnetmon.service" DESTINATION ${CMAKE_INSTALL_SYSTEMD_SERVICEDIR})
    endif()
else()
    # We have no relative standard path for installation, skip any actions
endif()

# For Debian packages build please use our logic from upstream: https://salsa.debian.org/debian/fastnetmon

# Configure cpack package builder
# Run it with: cd build; cpack -G DEB ..
set(CPACK_PACKAGE_NAME "fastnetmon")
set(CPACK_PACKAGE_VENDOR "github.com/pavel-odintsov/fastnetmon")
set(CPACK_PACKAGE_CONTACT "pavel.odintsov@gmail.com")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "FastNetMon - very fast DoS/DDoS detector with sFlow/Netflow/mirror support")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "")
# set(CPACK_PACKAGE_INSTALL_DIRECTORY "CPack Component Example")

if (NOT DO_NOT_USE_SYSTEM_LIBRARIES_FOR_BUILD)

# Specify config for deb package
# http://www.cmake.org/Wiki/CMake:CPackPackageGenerators#DEB_.28UNIX_only.29
# These dependencies are for Debian Bullseye
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libboost-thread-dev, libboost-system-dev, libboost-regex-dev, libpcap-dev, libnuma-dev, liblog4cpp5-dev, libgrpc10, libgrpc++1, libcapnp-0.7.0, libmongoc-1.0-0, libbson-1.0-0, libboost-program-options1.74.0")

endif()

# This must always be last!
include(CPack)

# Fuzz test with AFL++
if (ENABLE_FUZZ_TEST)
        add_executable(parse_sflow_v5_packet_fuzz tests/fuzz/parse_sflow_v5_packet_fuzz.cpp)
        target_link_libraries(parse_sflow_v5_packet_fuzz sflow_plugin netflow_plugin example_plugin fastnetmon_logic ${LOG4CPP_LIBRARY_PATH})
             
        add_executable(process_netflow_packet_v5_fuzz tests/fuzz/process_netflow_packet_v5_fuzz.cpp)
        target_link_libraries(process_netflow_packet_v5_fuzz  sflow_plugin netflow_plugin example_plugin fastnetmon_logic ${LOG4CPP_LIBRARY_PATH})
endif()

# Chaged interface socket to console input
if (ENABLE_FUZZ_TEST_DESOCK)
        target_link_libraries(fastnetmon desock) 
endif()
      
      
