#pragma once

// This file consist of all important plugins which could be usefult for plugin
// development

// For support uint32_t, uint16_t
#include <sys/types.h>

#include "all_logcpp_libraries.hpp"

#include "fast_library.hpp"

#include "fast_platform.hpp"

// Get log4cpp logger from main programme
extern log4cpp::Category& logger;

// Access to inaccurate but fast time
extern time_t current_inaccurate_time;
