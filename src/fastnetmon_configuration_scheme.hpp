#pragma once

#include <boost/serialization/nvp.hpp>
#include <map>
#include <sstream>
#include <vector>

#include "fastnetmon_networks.hpp"

class fastnetmon_configuration_t {
    public:
    // Clickhouse metrics
    bool clickhouse_metrics{ false };
    std::string clickhouse_metrics_database{ "fastnetmon" };
    std::string clickhouse_metrics_username{ "default" };
    std::string clickhouse_metrics_password{ "" };
    std::string clickhouse_metrics_host{ "127.0.0.1" };
    unsigned int clickhouse_metrics_port{ 9000 };
    unsigned int clickhouse_metrics_push_period{ 1 };

    // InfluxDB metrics
    bool influxdb{ false };
    std::string influxdb_database{ "fastnetmon" };
    std::string influxdb_host{ "127.0.0.1" };
    unsigned int influxdb_port{ 8086 };
    std::string influxdb_user{ "fastnetmon" };
    std::string influxdb_password{ "fastnetmon" };
    bool influxdb_auth{ false };
    unsigned int influxdb_push_period{ 1 };

    // Graphtie metrics
    bool graphite{ false };
    std::string graphite_host{ "127.0.0.1" };
    unsigned int graphite_port{ 2003 };
    std::string graphite_prefix{ "fastnetmon" };
    unsigned int graphite_push_period{ 1 };
};

