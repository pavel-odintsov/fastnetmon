all: fastnetmon

# User parameters
ENGINE = PF_RING
#ENGINE = ULOG2
#ENGINE = PCAP
#ENGINE = PF_RING
REDIS_SUPPORT = yes

GEOIP_SUPPORT = yes

# Develoepr parameters
ENABLE_DEBUG = no
ENABLE_PROFILER = no

# Code
ifeq ($(ENABLE_DEBUG), yes)
 BUILD_FLAGS += -g
endif

ifeq ($(ENABLE_PROFILER), yes)
 BUILD_FLAGS += -pg
endif

# we use C++ 11 threads. We must include pthread library due gcc bug
LIBS +=  -lpthread

DEFINES += -D$(ENGINE)

ifeq ($(GEOIP_SUPPORT), yes)
 DEFINES += -DGEOIP
 LIBS += -lGeoIP
endif

ifeq ($(REDIS_SUPPORT), yes)
 LIBS +=  -lhiredis
 DEFINES += -DREDIS
endif

ifeq ($(ENGINE), PCAP)
 LIBS += -lpcap
endif

# add path to PF_RING headers
ifeq ($(ENGINE), PF_RING)
 HEADERS += -I/opt/pf_ring/include 
 LIBS += -lpfring
 LIBS += -lnuma
 # for clock_gettime
 LIBS += -lrt
 LIBS_PATH += -L/opt/pf_ring/lib
endif

fastnetmon: libipulog.o fastnetmon.o
	g++ libipulog.o fastnetmon.o -o fastnetmon $(LIBS_PATH) $(LIBS) $(BUILD_FLAGS)
libipulog.o: libipulog.c
	g++ -c libipulog.c    -o libipulog.o -Wno-write-strings
fastnetmon.o: fastnetmon.cpp
	g++ $(DEFINES) $(HEADERS) -c fastnetmon.cpp -o fastnetmon.o -std=c++11 $(BUILD_FLAGS)
clean:
	rm -f libipulog.o fastnetmon.o fastnetmon
