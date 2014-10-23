all: fastnetmon

# User parameters
ENGINE = PF_RING
#ENGINE = ULOG2
#ENGINE = PCAP
#ENGINE = PF_RING
# Redis support broken now, sorry :(
REDIS_SUPPORT = no

GEOIP_SUPPORT = no

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

# We should add pthread as last argument: http://stackoverflow.com/questions/6919534/problem-linking-to-boost-thread
# we use C++ 11 threads. We must include pthread library due gcc bug
LIBS +=  -lpthread

# We need ncurses
LIBS += -lncurses

# It's support libs for ncurses
LIBS += -ltermcap
LIBS += -lgpm

# Logger
LIBS += -llog4cpp

# Boost threads
LIBS += -lboost_thread 

# Boost System
LIBS += -lboost_system

# Boost regular expressions
LIBS += -lboost_regex

# If you need dynamic compile, please comment this line
# STATIC = -static

# incompatible with static linkage
#DEFINES += -DENABLE_TBB
#LIBS += -ltbb

# removed -std=c++11 for fastnetmon.o
COMPILER = g++
# COMPILER = clang
cppcheck:
	cppcheck --enable=all -DPF_RING -DREDIS $(HEADERS) fastnetmon.cpp
fastnetmon: fastnetmon.o libpatricia/patricia.o lru_cache/lru_cache.o
	$(COMPILER) $(STATIC) libpatricia/patricia.o lru_cache/lru_cache.o fastnetmon.o -o fastnetmon $(LIBS_PATH) $(LIBS) $(BUILD_FLAGS) -pthread 
libpatricia/patricia.o: libpatricia/patricia.c
	gcc -c libpatricia/patricia.c -o libpatricia/patricia.o -Wno-write-strings -lstdc++ 
lru_cache/lru_cache.o: lru_cache/lru_cache.cpp
	$(COMPILER) -c -D_REENTRANT lru_cache/lru_cache.cpp -o lru_cache/lru_cache.o
fastnetmon.o: fastnetmon.cpp
	$(COMPILER) $(STATIC) $(DEFINES) $(HEADERS) -c fastnetmon.cpp -o fastnetmon.o $(BUILD_FLAGS)
clean:
	rm -f fastnetmon.o libpatricia/patricia.o lru_cache/lru_cache.o
