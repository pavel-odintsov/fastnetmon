--- src/fastnetmon.cpp.orig	2023-03-01 14:23:34 UTC
+++ src/fastnetmon.cpp
@@ -12,8 +12,8 @@
 #include <unistd.h>
 
 #include <arpa/inet.h>
-#include <net/if_arp.h> // struct arphdr
-#include <netinet/if_ether.h>
+//#include <net/if_arp.h> // struct arphdr
+//#include <netinet/if_ether.h>
 #include <netinet/in.h>
 #include <netinet/ip.h>
 #include <netinet/ip_icmp.h>
@@ -161,7 +161,7 @@ unsigned int stats_thread_initial_call_delay = 30;
 std::string reporting_server = "community-stats.fastnetmon.com";
 
 // Path to temporarily store backtrace when fatal failure happened
-std::string backtrace_path = "/var/log/fastnetmon_backtrace.dump";
+std::string backtrace_path = "/var/log/fastnetmon/fastnetmon_backtrace.dump";
 
 // Each this seconds we will check about available data in bucket
 unsigned int check_for_availible_for_processing_packets_buckets = 1;
@@ -435,7 +435,7 @@ std::string exabgp_community_subnet = "";
 std::string exabgp_community_host   = "";
 
 
-std::string exabgp_command_pipe = "/var/run/exabgp.cmd";
+std::string exabgp_command_pipe = "/var/run/fastnetmon/exabgp.cmd";
 std::string exabgp_next_hop     = "";
 
 // Graphite monitoring
@@ -519,7 +519,7 @@ void sigpipe_handler_for_popen(int signo) {
 #ifdef GEOIP
 bool geoip_init() {
     // load GeoIP ASN database to memory
-    geo_ip = GeoIP_open("/root/fastnetmon/GeoIPASNum.dat", GEOIP_MEMORY_CACHE);
+    geo_ip = GeoIP_open("/usr/local/share/fastnetmon/GeoIPASNum.dat", GEOIP_MEMORY_CACHE);
 
     if (geo_ip == NULL) {
         return false;
