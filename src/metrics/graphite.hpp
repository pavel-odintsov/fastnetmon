#pragma once

void graphite_push_thread();
bool push_total_traffic_counters_to_graphite();
bool push_network_traffic_counters_to_graphite();
bool push_hosts_traffic_counters_to_graphite();

