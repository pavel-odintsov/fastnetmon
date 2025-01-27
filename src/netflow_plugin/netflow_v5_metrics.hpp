#pragma once

std::string netflow_v5_total_packets_desc = "Total number of Netflow v5 UDP packets received";
uint64_t netflow_v5_total_packets         = 0;

std::string netflow_v5_total_flows_desc = "Total number of Netflow v5 flows (multiple in each packet)";
uint64_t netflow_v5_total_flows         = 0;

std::string netflow5_duration_less_15_seconds_desc = "Netflow v5 flows with duration less then 15 seconds";
uint64_t netflow5_duration_less_15_seconds         = 0;

std::string netflow5_duration_less_30_seconds_desc = "Netflow v5 flows with duration less then 30 seconds";
uint64_t netflow5_duration_less_30_seconds         = 0;

std::string netflow5_duration_less_60_seconds_desc = "Netflow v5 flows with duration less then 60 seconds";
uint64_t netflow5_duration_less_60_seconds         = 0;

std::string netflow5_duration_less_90_seconds_desc = "Netflow v5 flows with duration less then 90 seconds";
uint64_t netflow5_duration_less_90_seconds         = 0;

std::string netflow5_duration_less_180_seconds_desc = "Netflow v5 flows with duration less then 180 seconds";
uint64_t netflow5_duration_less_180_seconds         = 0;

std::string netflow5_duration_exceed_180_seconds_desc = "Netflow v5 flows with duration more then 180 seconds";
uint64_t netflow5_duration_exceed_180_seconds         = 0;
