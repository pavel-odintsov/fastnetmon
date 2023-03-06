--- src/fast_endianless.hpp.orig	2023-03-04 15:33:46 UTC
+++ src/fast_endianless.hpp
@@ -12,6 +12,7 @@
 // For be64toh and htobe64
 #if defined(__FreeBSD__) || defined(__DragonFly__)
 #include <sys/endian.h>
+#include <cstdint>
 #endif
 
 // Linux standard functions for endian conversions are ugly because there are no checks about arguments length
