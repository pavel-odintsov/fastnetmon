#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/Priority.hh"

#include "fast_library.h"

// Get log4cpp logger from main programm
extern log4cpp::Category& logger;

// Global configuration map
extern std::map<std::string, std::string> configuration_map;
