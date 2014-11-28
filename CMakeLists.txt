cmake_minimum_required (VERSION 2.8)

# Debian 6 - 2.8.2
# Debian 7 - 2.8.9
# CentOS 6 - 2.8.12

project(FastNetMon)

set (Tutorial_VERSION_MAJOR 1)
set (Tutorial_VERSION_MINOR 0)

add_definitions(-DENABLE_CONNTRACKING)
add_definitions(-DPF_RING)

add_library(libpatricia STATIC libpatricia/patricia.c)

add_executable(fastnetmon fastnetmon.cpp)

# Find boost: http://www.cmake.org/cmake/help/v3.0/module/FindBoost.html
find_package(Boost COMPONENTS threads regex)
if(Boost_FOUND)
    include_directories(${Boost_INCLUDE_DIRS})
    target_link_libraries(fastnetmon ${Boost_LIBRARIES})
endif()

target_link_libraries(fastnetmon boost_regex)
target_link_libraries(fastnetmon boost_thread)
target_link_libraries(fastnetmon log4cpp)
target_link_libraries(fastnetmon numa)
target_link_libraries(fastnetmon ncurses)
target_link_libraries(fastnetmon pthread)
target_link_libraries(fastnetmon libpatricia)

include_directories(/opt/pf_ring/include)
target_link_libraries(fastnetmon /opt/pf_ring/lib/libpfring.so)

include_directories(/opt/pf_ring/include)
