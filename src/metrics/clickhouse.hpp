#pragma once

#include <clickhouse/client.h>

#include "../fastnetmon_types.hpp"
#include "../fastnetmon_configuration_scheme.hpp"

void clickhouse_push_thread();

bool push_network_traffic_counters_to_clickhouse();
bool push_total_traffic_counters_to_clickhouse();
bool push_hosts_traffic_counters_to_clickhouse();

bool init_clickhouse_for_metrics(fastnetmon_configuration_t& fastnetmon_global_configuration,
                                 clickhouse::Client*& clickhouse_metrics_client);
