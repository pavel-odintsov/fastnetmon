cmake_minimum_required (VERSION 2.8)

# cmake versions:
# Debian 6 - 2.8.2
# Debian 7 - 2.8.9
# CentOS 6 - 2.8.12

# We should set compiler before project() call 
if (ENABLE_BUILD_IN_CPP_11_CUSTOM_ENVIRONMENT)
    # We use custom compiler too
    set(CMAKE_C_COMPILER "/opt/gcc520/bin/gcc")
    set(CMAKE_CXX_COMPILER "/opt/gcc520/bin/g++")
endif()

project(FastNetMon)

# Unfortunately, Debian Squeeze haven't support for this feature
# It added in 2.8.5 release: http://www.cmake.org/cmake/help/v2.8.5/cmake.html
# Get convinient paths for all system folders: http://www.cmake.org/gitweb?p=cmake.git;a=commitdiff;h=a262fe09
# include(GNUInstallDirs)

# Enable it and fix all warnigns!
# add_definitions ("-Wall")

set (FASTNETMON_VERSION_MAJOR 1)
set (FASTNETMON_VERSION_MINOR 1)

# cmake -DENABLE_BUILD_IN_CPP_11_CUSTOM_ENVIRONMENT=ON .. 
if (ENABLE_BUILD_IN_CPP_11_CUSTOM_ENVIRONMENT)
    set(BOOST_INCLUDEDIR "/opt/boost_1_58_0")
    set(BOOST_LIBRARYDIR "/opt/boost_1_58_0/stage/lib/")

    # It's really nice part of this custom build process :)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -std=c++11")

    # Disable warning from Boost when compiling with gcc 5.2
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wno-deprecated-declarations")
 
    # Specify full RPATH for build tree
    SET(CMAKE_SKIP_BUILD_RPATH  FALSE)

    # Create builds in current folder with install RPATH
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)

    SET(CMAKE_INSTALL_RPATH "/opt/gcc520/lib64;/opt/boost_1_58_0/stage/lib;/opt/libhiredis_0_13/lib;/opt/log4cpp1.1.1/lib;/opt/luajit_2.0.4/lib;/opt/ndpi/lib;/opt/pf_ring_6.0.3/lib;/opt/json-c-0.12/lib")
endif()

# It's pretty safe and provide big speedup for our packet processor and patricia code
set(CMAKE_C_FLAGS_RELEASE "-O2")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

set(HIREDIS_CUSTOM_INSTALL_PATH "/opt/libhiredis_0_13")
set(LOG4CPP_CUSTOM_INSTALL_PATH "/opt/log4cpp1.1.1")
set(JSONC_CUSTOM_INSTALL_PATH "/opt/json-c-0.12")
set(PFRING_CUSTOM_INSTALL_PATH "/opt/pf_ring_6.0.3")
set(LIBPCAP_CUSTOM_INSTALL_PATH "/opt/libpcap_1.7.4")

set(FASTNETMON_PROFILER OFF)

set(FASTNETMON_PROFILE_FLAGS "-g -pg")

if (NOT CMAKE_BUILD_TYPE) 
    message(STATUS "Setting build type to Release as none was specified.")
    set(CMAKE_BUILD_TYPE Release)
endif()

if (FASTNETMON_PROFILER) 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
endif()

set(FASTNETMON_APPLICATION_VERSION "1.1.3 master")
configure_file(fast_platform.h.template "${PROJECT_SOURCE_DIR}/fast_platform.h")

# With this flag we can diable PF_RING build via console: cmake .. -DDISABLE_PF_RING_SUPPORT=ON
if (NOT DISABLE_PF_RING_SUPPORT) 
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        message(STATUS "You are running Linux and we can build PF_RING support")
        set (ENABLE_PFRING_SUPPORT ON)
    else()
        message(WARNING "You are running not an Linux and we can't build PF_RING support")
    endif() 
endif()

if (ENABLE_PFRING_SUPPORT)
    # work around for broken 6.0.3 (which in reality very old 6.0.3) from ntop packages
    #if (WE_USE_PFRING_FROM_NTOP)
    #    add_definitions(-DWE_USE_PFRING_FROM_NTOP) 
    #endif()

    if (WE_USE_PFRING_FROM_NTOP)
        # Because ntop will add libs and headers to global paths
        set(PFRING_LIBRARIES pfring) 
    else() 
        # Set path to manually compiled PF_RING
        set(PFRING_INCLUDE_DIRS "${PFRING_CUSTOM_INSTALL_PATH}/include")
        set(PFRING_LIBRARIES pfring)
        link_directories("${PFRING_CUSTOM_INSTALL_PATH}/lib")
    endif()

    add_definitions(-DPF_RING)

    if (EXISTS "${PFRING_CUSTOM_INSTALL_PATH}/include/pfring_zc.h" OR EXISTS "/usr/local/include/pfring_zc.h")
        message(STATUS "We found PF_RING ZC headers and will build PF_RING ZC support")
        # Enable ZC support
        add_definitions(-DPF_RING_ZC)
    else()
        message(WARNING "We can't find PF_RING ZC header pfring_zc.h in folder /opt/pf_ring/include. Will not compile ZC support") 
    endif()

    include_directories(${PFRING_INCLUDE_DIRS})

    message(STATUS "We have enabled PF_RING's hardware filtering option")
endif()

# Our LPM library
add_library(patricia STATIC libpatricia/patricia.c)

add_library(fastnetmon_pcap_format STATIC fastnetmon_pcap_format.cpp)

# Our tools library
add_library(fast_library STATIC fast_library.cpp)

# Our ipfix database library
add_library(ipfix_rfc STATIC ipfix_rfc.cpp)

# Our packet parser
add_library(fastnetmon_packet_parser STATIC fastnetmon_packet_parser.c)

# -DENABLE_SNABBSWITCH_SUPPORT=ON ..
# Please also comment out line: set(ENABLE_LUA_SUPPORT yes) if you want SnabbSwitch support
if (ENABLE_SNABBSWITCH_SUPPORT) 
    add_definitions(-DSNABB_SWITCH)
    add_library(snabbswitch_plugin STATIC snabbswitch_plugin/snabbswitch_collector.cpp)

    link_directories(/usr/src/snabbswitch/src)
    target_link_libraries(snabbswitch_plugin snabb)
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    # We have issues with AF_PACKET in old kernels and remote it from default build now
    #message(STATUS "You are running Linux and we can build AF_PACKET support")
    #set (ENABLE_AFPACKET_SUPPORT ON)
endif()

# -DENABLE_AFPACKET_SUPPORT=ON ..
if (ENABLE_AFPACKET_SUPPORT)
   add_definitions(-DFASTNETMON_ENABLE_AFPACKET) 

    add_library(afpacket_plugin STATIC afpacket_plugin/afpacket_collector.cpp)
endif()

# sFLOW plugin
add_library(sflow_plugin STATIC sflow_plugin/sflow_collector.cpp) 

# netflow plugin
add_library(netflow_plugin STATIC netflow_plugin/netflow_collector.cpp)
target_link_libraries(netflow_plugin ipfix_rfc)

set(ENABLE_DPI_SUPPORT YES)
if (ENABLE_DPI_SUPPORT) 
    message(STATUS "We will enable nDPI support")

    add_library(fast_dpi STATIC fast_dpi.cpp)

    set(NDPI_INCLUDE_DIRS "/opt/ndpi/include/libndpi-1.7.0")
    set(NDPI_LIBRARIES "ndpi")

    link_directories("/opt/ndpi/lib")
    include_directories(${NDPI_INCLUDE_DIRS})

    add_definitions(-DENABLE_DPI)

    target_link_libraries(fast_dpi ${NDPI_LIBRARIES})
endif()

# We do not enable it by default, it's testing feature
# If you want it please build with:
# cmake -DENABLE_LUA_SUPPORT=ON .. 
set(ENABLE_LUA_SUPPORT yes)
if (ENABLE_LUA_SUPPORT)
    message(STATUS "We will enable LuaJIT support")

    add_definitions(-DENABLE_LUA_HOOKS)

    link_directories("/opt/luajit_2.0.4/lib")
    include_directories("/opt/luajit_2.0.4/include")
 
    target_link_libraries(netflow_plugin luajit-5.1)
    target_link_libraries(sflow_plugin luajit-5.1)
    target_link_libraries(fast_library luajit-5.1)
endif()

# pcap plugin
add_library(pcap_plugin STATIC pcap_plugin/pcap_collector.cpp)
target_link_libraries(pcap_plugin pcap)

find_package(Threads)

if (ENABLE_PFRING_SUPPORT) 
    add_library(pfring_plugin STATIC pfring_plugin/pfring_collector.cpp)
    target_link_libraries(pfring_plugin ${PFRING_LIBRARIES})
    target_link_libraries(pfring_plugin numa)
    target_link_libraries(pfring_plugin ${CMAKE_THREAD_LIBS_INIT})

    # Add action for hardware filetring
    add_library(pfring_hardware_filter_action STATIC actions/pfring_hardware_filter_action.cpp)
endif()

# example plugin
add_library(example_plugin STATIC example_plugin/example_collector.cpp)

# Netmap plugin
set(NETMAP_INCLUDE_DIRS "netmap_plugin/netmap_includes")
include_directories(${NETMAP_INCLUDE_DIRS})
add_library(netmap_plugin STATIC netmap_plugin/netmap_collector.cpp)
target_link_libraries(netmap_plugin fastnetmon_packet_parser)

# Main tool
add_executable(fastnetmon fastnetmon.cpp)

# Client tool
add_executable(fastnetmon_client fastnetmon_client.cpp)

# Find boost: http://www.cmake.org/cmake/help/v3.0/module/FindBoost.html

# Enable detailed errors
set(Boost_DETAILED_FAILURE_MSG ON)

find_package(Boost COMPONENTS thread regex program_options system REQUIRED)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(fastnetmon ${Boost_LIBRARIES})
    target_link_libraries(fast_library ${Boost_LIBRARIES})
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
    message(STATUS "We found hiredis library and will build Redis support ${HIREDIS_INCLUDES_FOLDER} ${HIREDIS_LIBRARY_PATH}")

    add_definitions(-DREDIS)
    include_directories(${HIREDIS_INCLUDES_FOLDER})
    target_link_libraries (fastnetmon ${HIREDIS_LIBRARY_PATH})
else()
    message(STATUS "We can't find hiredis library and will disable Redis support")
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
    message(STATUS "We have found log4cpp and will build project")
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

if (ENABLE_DPI_SUPPORT)
    target_link_libraries(fastnetmon fast_dpi)
endif()

target_link_libraries(fastnetmon ${LOG4CPP_LIBRARY_PATH})

target_link_libraries(fastnetmon ${CMAKE_THREAD_LIBS_INIT})

if (ENABLE_LUA_SUPPORT)
    target_link_libraries(fast_library luajit-5.1) 
    target_link_libraries(fastnetmon luajit-5.1)
endif()

# Our libs
target_link_libraries(fastnetmon patricia)
target_link_libraries(fastnetmon fastnetmon_pcap_format)

target_link_libraries(fastnetmon ipfix_rfc)

# Link to our functions
target_link_libraries(fastnetmon fast_library)

if (ENABLE_PFRING_SUPPORT)
    target_link_libraries(fastnetmon pfring_plugin)
    # Link hardware filter too
    target_link_libraries(fastnetmon pfring_hardware_filter_action)
endif()

if (ENABLE_SNABBSWITCH_SUPPORT)
    target_link_libraries(fastnetmon snabbswitch_plugin)
endif()

if (ENABLE_AFPACKET_SUPPORT)
    target_link_libraries(fastnetmon afpacket_plugin)
endif()

target_link_libraries(fastnetmon sflow_plugin netflow_plugin pcap_plugin example_plugin netmap_plugin)

# cmake .. -DBUILD_PLUGIN_RUNNER=ON
if (BUILD_PLUGIN_RUNNER)
    add_executable(fastnetmon_plugin_runner plugin_runner.cpp)

    if (ENABLE_SNABBSWITCH_SUPPORT) 
        target_link_libraries(fastnetmon_plugin_runner snabbswitch_plugin)
    endif()

    if (ENABLE_AFPACKET_SUPPORT) 
        target_link_libraries(fastnetmon_plugin_runner afpacket_plugin)
    endif()

    target_link_libraries(fastnetmon_plugin_runner ${CMAKE_THREAD_LIBS_INIT})
    target_link_libraries(fastnetmon_plugin_runner patricia)
    target_link_libraries(fastnetmon_plugin_runner fastnetmon_pcap_format)
    target_link_libraries(fastnetmon_plugin_runner ${LOG4CPP_LIBRARY_PATH})
    target_link_libraries(fastnetmon_plugin_runner fast_library)

    # Add all plugins
    target_link_libraries(fastnetmon_plugin_runner sflow_plugin netflow_plugin pcap_plugin example_plugin netmap_plugin)

    if (ENABLE_PFRING_SUPPORT)
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
    target_link_libraries(fastnetmon_pcap_reader netmap_plugin)

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

    set(GOOGLE_TEST_INCLUDE_DIRS /opt/gtest/include)
    set(GOOGLE_TEST_LIBRARIES /opt/gtest/lib/libgtest.a /opt/gtest/lib/libgtest_main.a)

    # Compiled Google Library
    include_directories(${GOOGLE_TEST_INCLUDE_DIRS})
    target_link_libraries(fastnetmon_tests ${GOOGLE_TEST_LIBRARIES})
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "FreeBSD" OR ${CMAKE_SYSTEM_NAME} STREQUAL "DragonFly")
    install(TARGETS fastnetmon DESTINATION bin)
    install(TARGETS fastnetmon_client DESTINATION bin)

    install(FILES fastnetmon.conf DESTINATION etc)

    # Install blank files for networks list and whitelist
    install(FILES networks_list DESTINATION etc)
    install(FILES networks_whitelist DESTINATION etc)
else()
    # Linux
    install(TARGETS fastnetmon DESTINATION /usr/sbin)
    install(TARGETS fastnetmon_client DESTINATION /usr/bin)

    install(FILES fastnetmon.conf DESTINATION /etc)

    # Install blank files for networks list and whitelist
    install(FILES networks_list DESTINATION /etc)
    install(FILES networks_whitelist DESTINATION /etc) 
endif()

# man pages
install(FILES man/fastnetmon.1 DESTINATION /usr/share/man/man1)
install(FILES man/fastnetmon_client.1 DESTINATION /usr/share/man/man1)

# Configure cpack package builder
# Run it with: cd build; cpack -G DEB ..
set(CPACK_PACKAGE_NAME "fastnetmon")
set(CPACK_PACKAGE_VENDOR "vps2fast.com")
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
