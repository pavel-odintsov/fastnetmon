#include <stdio.h>
#include <stdlib.h>

#include <stdint.h>
#include <sstream> 
#include <iostream>
#include <string>

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

string print_flags(uint8_t flag_value) {
    // (tcp->fin * TH_FIN_MULTIPLIER) + (tcp->syn * TH_SYN_MULTIPLIER) +
    //  (tcp->rst * TH_RST_MULTIPLIER) + (tcp->psh * TH_PUSH_MULTIPLIER) +
    //  (tcp->ack * TH_ACK_MULTIPLIER) + (tcp->urg * TH_URG_MULTIPLIER);

    /*
        // Required for decoding tcp flags
        #define TH_FIN_MULTIPLIER   0x01
        #define TH_SYN_MULTIPLIER   0x02
        #define TH_RST_MULTIPLIER   0x04
        #define TH_PUSH_MULTIPLIER  0x08
        #define TH_ACK_MULTIPLIER   0x10
        #define TH_URG_MULTIPLIER   0x20
    */

    stringstream flags_as_string;

    if (extract_bit_value(flag_value, 1)) {
        flags_as_string<<"fin ";
    }
    
    if (extract_bit_value(flag_value, 2)) {
        flags_as_string<<"syn ";
    }   

    if (extract_bit_value(flag_value, 3)) {
        flags_as_string<<"rst ";
    }   

    if (extract_bit_value(flag_value, 4)) {
        flags_as_string<<"psh ";
    }   

    if (extract_bit_value(flag_value, 5)) {
        flags_as_string<<"ack ";
    }    

    if (extract_bit_value(flag_value, 6)) {
        flags_as_string<<"urg ";
    }   

    return flags_as_string.str();
}

int main() {
    uint8_t flag = 16;
    std::cout<<print_flags(16);
    return 0;
}
