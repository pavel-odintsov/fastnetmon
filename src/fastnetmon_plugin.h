#pragma once

// This file consist of all important plugins which could be usefult for plugin
// development

// For support uint32_t, uint16_t
#include <sys/types.h>

#include "all_logcpp_libraries.h"

#include "fast_library.h"

#include "fast_platform.h"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;
