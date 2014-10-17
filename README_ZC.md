Как обеспечить работу с PF_RING в режиме ZC и обрабатывать до 14 MPPS?

Нужно наложить следующие патчи:

1. Включаем REENTRANT_MODE, чтобы можно было выбирать пакеты из нескольких потоков и не крашить PF_RING 
```C
-unsigned int num_threads = 1;
+unsigned int num_threads = 8;
```

2. Активируем многопоточную выборку пакетов:
```c
-    pfring_loop(pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);
+    boost::thread* my_calc_threads[8];
+
+    for (int number_of_thread=0; number_of_thread<8; number_of_thread++) {
+        my_calc_threads[number_of_thread] = new boost::thread(pfring_loop, pf_ring_descr, parse_packet_pf_ring, (u_char*)NULL, wait_for_packet);
+    } 
```

3. Раскомментируем парсер пакетов, так как в режиме ZC он отключен и именно он производит основную нагрузку на систему:
```C
// pfring_parse_pkt((u_char*)p, (struct pfring_pkthdr*)h, 5, 0, 0);
```
