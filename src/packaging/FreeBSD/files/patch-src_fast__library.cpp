--- src/fast_library.cpp.orig	2023-03-05 11:34:07 UTC
+++ src/fast_library.cpp
@@ -1249,7 +1249,11 @@ bool get_interface_number_by_device_name(int socket_fd
         return false;
     }
 
-    interface_number = ifr.ifr_ifindex;
+    #ifdef __FreeBSD__
+      interface_number = ifr.ifr_ifru.ifru_index;
+    #else
+      interface_number = ifr.ifr_ifindex;
+    #endif
 #else
     /* Fallback to if_nametoindex(3) otherwise. */
     interface_number = if_nametoindex(interface_name.c_str());
