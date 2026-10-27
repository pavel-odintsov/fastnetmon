#!/usr/bin/env python3
"""Write the M126 attack pcap: one UDP packet to each victim.

tcpreplay loops the two frames at a fixed rate on the lab's mirror
interface, so each victim sees half the replay rate in packets per second.

    python3 make_attack_pcap.py OUT.pcap
"""

import ipaddress
import struct
import sys

V4_SRC, V4_DST = "198.51.100.10", "203.0.113.7"
V6_SRC, V6_DST = "2001:db8:bad::10", "2001:db8:66::7"
ETH_SRC = bytes.fromhex("020000000126")
ETH_DST = bytes.fromhex("020000000127")
PAYLOAD = b"m126-attack-" + bytes(20)


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def udp(src: bytes, dst: bytes, proto_len_pseudo: bytes) -> bytes:
    length = 8 + len(PAYLOAD)
    header = struct.pack("!HHHH", 40000, 9, length, 0)
    csum = checksum(src + dst + proto_len_pseudo + header + PAYLOAD) or 0xFFFF
    return struct.pack("!HHHH", 40000, 9, length, csum) + PAYLOAD


def ipv4_frame() -> bytes:
    src = ipaddress.IPv4Address(V4_SRC).packed
    dst = ipaddress.IPv4Address(V4_DST).packed
    seg = udp(src, dst, struct.pack("!BBH", 0, 17, 8 + len(PAYLOAD)))
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(seg), 0, 0, 64, 17, 0, src, dst)
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return ETH_DST + ETH_SRC + b"\x08\x00" + hdr + seg


def ipv6_frame() -> bytes:
    src = ipaddress.IPv6Address(V6_SRC).packed
    dst = ipaddress.IPv6Address(V6_DST).packed
    seg = udp(src, dst, struct.pack("!I3xB", 8 + len(PAYLOAD), 17))
    hdr = struct.pack("!IHBB16s16s", 0x60000000, len(seg), 17, 64, src, dst)
    return ETH_DST + ETH_SRC + b"\x86\xdd" + hdr + seg


def main() -> None:
    with open(sys.argv[1], "wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate((ipv4_frame(), ipv6_frame())):
            out.write(struct.pack("<IIII", 0, i, len(frame), len(frame)) + frame)


if __name__ == "__main__":
    main()
