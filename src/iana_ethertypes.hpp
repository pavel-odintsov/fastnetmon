#pragma once
enum IanaEthertype : unsigned int {

    IanaEthertypeIPv4 = 2048,
    IanaEthertypeARP  = 2054,
    // This one is not IANA certified, it's draft: https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03#section-4.2
    IanaEthertypeERSPAN          = 0x88BE,
    IanaEthertypeVLAN            = 33024,
    IanaEthertypeIPv6            = 34525,
    IanaEthertypeMPLS_unicast    = 34887,
    IanaEthertypeMPLS_multicast  = 34888,
    IanaEthertypePPPoE_discovery = 34915,
    IanaEthertypePPPoE_session   = 34916,
};
