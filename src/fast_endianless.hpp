#pragma once

#include <arpa/inet.h>

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
// Source: https://gist.github.com/pavel-odintsov/d13684600423d1c5e64e
#define be64toh(x) OSSwapBigToHostInt64(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#endif

// For be64toh and htobe64
#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/endian.h>
#endif

// Linux standard functions for endian conversions are ugly because there are no checks about arguments length
// And you could accidentally use ntohs (suitable only for 16 bit) for 32 or 64 bit value and nobody will warning you
// With this wrapper functions it's pretty complicated to use them for incorrect length type! :)

// Type safe versions of ntohl, ntohs with type control
inline uint16_t fast_ntoh(uint16_t value) {
    return ntohs(value);
}

inline uint32_t fast_ntoh(uint32_t value) {
    return ntohl(value);
}

inline int32_t fast_ntoh(int32_t value) {
    return ntohl(value);
}

// network (big endian) byte order to host byte order
inline uint64_t fast_ntoh(uint64_t value) {
    return be64toh(value);
}

// Type safe version of htonl, htons
inline uint16_t fast_hton(uint16_t value) {
    return htons(value);
}

inline uint32_t fast_hton(uint32_t value) {
    return htonl(value);
}

inline int32_t fast_hton(int32_t value) {
    return htonl(value);
}

inline uint64_t fast_hton(uint64_t value) {
    // host to big endian (network byte order)
    return htobe64(value);
}

// Explicitly remove all other types to avoid implicit conversion
template <class T> void fast_ntoh(T) = delete;

template <class T> void fast_hton(T) = delete;
