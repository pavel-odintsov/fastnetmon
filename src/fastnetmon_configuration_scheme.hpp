#pragma once

#include <boost/serialization/nvp.hpp>
#include <map>
#include <sstream>
#include <vector>

#include "fastnetmon_networks.hpp"

class fastnetmon_configuration_t {
    public:
    bool clickhouse_metrics{ false };
    std::string clickhouse_metrics_database{ "fastnetmon" };
    std::string clickhouse_metrics_username{ "default" };
    std::string clickhouse_metrics_password{ "" };
    std::string clickhouse_metrics_host{ "127.0.0.1" };
    unsigned int clickhouse_metrics_port{ 9000 };
    unsigned int clickhouse_metrics_push_period{ 1 };
};

