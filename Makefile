all: fastnetmon

# User parameters
ENGINE = PF_RING
#ENGINE = ULOG2
#ENGINE = PCAP
#ENGINE = PF_RING
REDIS_SUPPORT = yes

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

# If you need dynamic compile, please comment this line
#STATIC = -static

cppcheck:
	cppcheck --enable=all -DPF_RING -DREDIS $(HEADERS) fastnetmon.cpp
fastnetmon: libipulog.o fastnetmon.o libpatricia/patricia.o
	g++ $(STATIC) libipulog.o libpatricia/patricia.o fastnetmon.o -o fastnetmon $(LIBS_PATH) $(LIBS) $(BUILD_FLAGS) -pthread 
libipulog.o: libipulog.c
	g++ $(STATIC) -c libipulog.c -o libipulog.o -Wno-write-strings
libpatricia/patricia.o: libpatricia/patricia.c
	gcc -c libpatricia/patricia.c -o libpatricia/patricia.o -Wno-write-strings -fpermissive -lstdc++ 
fastnetmon.o: fastnetmon.cpp
	g++ $(STATIC) $(DEFINES) $(HEADERS) -c fastnetmon.cpp -o fastnetmon.o -std=c++11 $(BUILD_FLAGS)
clean:
	rm -f libipulog.o fastnetmon.o fastnetmon libpatricia/patricia.o
