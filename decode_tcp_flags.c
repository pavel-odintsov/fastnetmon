#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <sstream> 
#include <iostream>
#include <string>
#include <vector>

using namespace std;

string print_flags(uint8_t flag_value);

// http://stackoverflow.com/questions/14528233/bit-masking-in-c-how-to-get-first-bit-of-a-byte
int extract_bit_value(uint8_t num, int bit) {
    if (bit > 0 && bit <= 8) {
        return ( (num >> (bit-1)) & 1 );
    } else {
        return 0;
    }
}

string print_tcp_flags(uint8_t flag_value) {
    // cod from pfring.h
    // (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
    // (tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
    // (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

    /*
        // Required for decoding tcp flags
        #define TH_FIN_MULTIPLIER   0x01
        #define TH_SYN_MULTIPLIER   0x02
        #define TH_RST_MULTIPLIER   0x04
        #define TH_PUSH_MULTIPLIER  0x08
        #define TH_ACK_MULTIPLIER   0x10
        #define TH_URG_MULTIPLIER   0x20
    */

    vector<string> all_flags;

    if (extract_bit_value(flag_value, 1)) {
        all_flags.push_back("fin");
    }
    
    if (extract_bit_value(flag_value, 2)) {
        all_flags.push_back("syn");
    }   

    if (extract_bit_value(flag_value, 3)) {
        all_flags.push_back("rst");
    }   

    if (extract_bit_value(flag_value, 4)) {
        all_flags.push_back("psh");
    }   

    if (extract_bit_value(flag_value, 5)) {
        all_flags.push_back("ack");
    }    

    if (extract_bit_value(flag_value, 6)) {
        all_flags.push_back("urg");
    }   

    
    stringstream flags_as_string;

    for(std::vector<string>::iterator it = all_flags.begin(); it != all_flags.end(); ++it) {
        flags_as_string<<*it;
    }

    return flags_as_string.str();
}

int main() {
    uint8_t flag = 16;
    std::cout<<print_flags(16);
    return 0;
}
