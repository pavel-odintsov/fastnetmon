cmake_minimum_required (VERSION 2.8)

# cmake versions:
# Debian 6 - 2.8.2
# Debian 7 - 2.8.9
# CentOS 6 - 2.8.12

project(FastNetMon)

set (Tutorial_VERSION_MAJOR 1)
set (Tutorial_VERSION_MINOR 1)

# It's pretty safe and provide big speedup for our packet processor and patricia code
set(CMAKE_C_FLAGS "-O2")
set(CMAKE_CXX_FLAGS "-O2")

set(FASTNETMON_PROFILER OFF)

set(FASTNETMON_PROFILE_FLAGS "-g -pg")

if (FASTNETMON_PROFILER) 
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} ${FASTNETMON_PROFILE_FLAGS}")
endif()

# With this flag we can diable PF_RING build via console: cmake .. -DDISABLE_PF_RING_SUPPORT=ON
if (NOT DISABLE_PF_RING_SUPPORT) 
    if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
        message("You are running Linux and we can build PF_RING support")
        set (ENABLE_PFRING_SUPPORT ON)
    else()
        message("You are running not an Linux and we can't build PF_RING support")
    endif() 
endif()

if (ENABLE_PFRING_SUPPORT)
    # Set path to home compiled PF_RING
    set(PFRING_INCLUDE_DIRS /opt/pf_ring/include)
    set(PFRING_LIBRARIES /opt/pf_ring/lib/libpfring.so)
    add_definitions(-DPF_RING)

    include_directories(${PFRING_INCLUDE_DIRS})
endif()

# If you need hardware locking features
# add_definitions(-DHWFILTER_LOCKING)

# Our LPM library
add_library(patricia STATIC libpatricia/patricia.c)

# sFLOW plugin
add_library(sflow_plugin STATIC sflow_plugin/sflow_collector.cpp) 

# netflow plugin
add_library(netflow_plugin STATIC netflow_plugin/netflow_collector.cpp)

# pcap plugin
add_library(pcap_plugin STATIC pcap_plugin/pcap_collector.cpp)
target_link_libraries(pcap_plugin pcap)

if (ENABLE_PFRING_SUPPORT) 
    add_library(pfring_plugin STATIC pfring_plugin/pfring_collector.cpp)
    target_link_libraries(pfring_plugin ${PFRING_LIBRARIES})
    target_link_libraries(pfring_plugin numa)
    target_link_libraries(pfring_plugin pthread)
endif()

# example plugin
add_library(example_plugin STATIC example_plugin/example_collector.cpp)

# Main tool
add_executable(fastnetmon fastnetmon.cpp)

# Client tool
add_executable(fastnetmon_client fastnetmon_client.cpp)

# Find boost: http://www.cmake.org/cmake/help/v3.0/module/FindBoost.html

# Disable cmake script from Boost package becaus it is broken: http://public.kitware.com/Bug/view.php?id=15270
set(Boost_NO_BOOST_CMAKE ON)
# Enable detailed errors
set(Boost_DETAILED_FAILURE_MSG ON)

find_package(Boost COMPONENTS thread regex system REQUIRED)

if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(fastnetmon ${Boost_LIBRARIES})
endif()

# Try to find ncurses library
find_package(Curses REQUIRED)

if(CURSES_FOUND) 
    include_directories(${CURSES_INCLUDE_DIRS})
    target_link_libraries(fastnetmon_client ${CURSES_LIBRARIES})
endif()

# Standard path for Linux
set(LOG4CPP_LIBRARY_PATH log4cpp)

# Non standard path on platforms where we compile log4cpp from sources
if (WE_USE_CUSTOM_LOG4CPP) 
    set(LOG4CPP_LIBRARY_PATH /opt/log4cpp1.1.1/lib/liblog4cpp.so)
    include_directories(/opt/log4cpp1.1.1/include) 
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Darwin")
    # This path is default when log4cpp installed from ports
    set(LOG4CPP_LIBRARY_PATH /opt/local/lib/liblog4cpp.dylib)
endif()

target_link_libraries(fastnetmon ${LOG4CPP_LIBRARY_PATH})

target_link_libraries(fastnetmon pthread)

# Our libs
target_link_libraries(fastnetmon patricia)

# Our plugins
target_link_libraries(fastnetmon sflow_plugin)

if (ENABLE_PFRING_SUPPORT)
target_link_libraries(fastnetmon pfring_plugin)
endif()

target_link_libraries(fastnetmon netflow_plugin)
target_link_libraries(fastnetmon pcap_plugin)
target_link_libraries(fastnetmon example_plugin)

