#pragma once

#include <string>
#include <vector>

#include "../fastnetmon_types.hpp"

void send_grafana_alert(std::string title, std::string text, std::vector<std::string>& tags);

void influxdb_push_thread();
