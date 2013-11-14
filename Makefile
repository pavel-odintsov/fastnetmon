all: fastnetmon

ENGINE = ULOG2
#ENGINE = PCAP

REDIS_SUPPORT = yes

# we use C++ 11 threads. We must include pthread library due gcc bug
LIBS +=  -lpthread

DEFINES += -D$(ENGINE)

ifeq ($(REDIS_SUPPORT), yes)
 LIBS +=  -lhiredis
 DEFINES += -DREDIS
endif

ifeq ($(ENGINE), PCAP)
 LIBS = -lpcap
endif

fastnetmon: libipulog.o fastnetmon.o
	g++ libipulog.o fastnetmon.o -o fastnetmon $(LIBS)
libipulog.o: libipulog.c
	g++ -c libipulog.c    -o libipulog.o -Wno-write-strings
fastnetmon.o: fastnetmon.cpp
	g++ $(DEFINES) -c fastnetmon.cpp -o fastnetmon.o -std=c++11
clean:
	rm -f libipulog.o fastnetmon.o fastnetmon
