#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <utility>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <algorithm>
#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>
#include <utility>
#include <sstream>

#include <boost/algorithm/string.hpp>

using namespace std;

vector<string> exec(string cmd) {
    vector<string> output_list;

    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return output_list;

    char buffer[256];
    std::string result = "";
    while (!feof(pipe)) {
        if (fgets(buffer, 256, pipe) != NULL) {
            size_t newbuflen = strlen(buffer);

            // remove newline at the end
            if (buffer[newbuflen - 1] == '\n') {
                buffer[newbuflen - 1] = '\0';
            }

            output_list.push_back(buffer);
        }
    }

    pclose(pipe);
    return output_list;
}


typedef pair<uint32_t, uint32_t> subnet;

bool belongs_to_networks(vector<subnet>& networks_list, uint32_t ip) {
    for (vector<subnet>::iterator ii = networks_list.begin(); ii != networks_list.end(); ++ii) {

        if ((ip & (*ii).second) == ((*ii).first & (*ii).second)) {
            return true;
        }
    }

    return false;
}

uint32_t convert_ip_as_string_to_uint(string ip) {
    struct in_addr ip_addr;
    inet_aton(ip.c_str(), &ip_addr);

    // in network byte order
    return ip_addr.s_addr;
}

uint32_t convert_cidr_to_binary_netmask(int cidr) {
    uint32_t binary_netmask = 0xFFFFFFFF;
    binary_netmask = binary_netmask << (32 - cidr);
    // htonl from host byte order to network
    // ntohl from network byte order to host

    // I suppose we need network byte order here
    return htonl(binary_netmask);
}

int get_bit(uint32_t number, uint32_t ip) {
    return 1;
}

typedef struct leaf {
    bool bit;
    struct leaf* right, *left;
} tree_leaf;

#include <bitset>
void insert_prefix_bitwise_tree(tree_leaf* root, string subnet, int cidr_mask) {
    uint32_t netmask_as_int = convert_ip_as_string_to_uint(subnet);

    // std::cout<<std::bitset<32>(netmask_as_int)<<endl;

    // ntogl: network byte order to host, htonl - host to network
    netmask_as_int = ntohl(netmask_as_int);

    // intruduce temporary pointer
    tree_leaf* temp_root = root;

    // Iterate over significant subnet bits and ignore other
    for (int i = 31; i >= 32 - cidr_mask; i--) {
        uint32_t result_bit = netmask_as_int & (1 << i);
        bool bit = result_bit == 0 ? false : true;
        // cout<<"Insert: "<<bit<<" from position "<<i<<endl;

        // from the left - zeros, from the rigth - ones

        // We could have index or we could haven't indes. We check only child leafs of root,
        // we do not check root
        if (bit) {
            // check rigth subntree
            if (temp_root->right != NULL) {
                // Elemelnt already there, just switch pointer
                temp_root = temp_root->right;
            } else {
                // No element here, we should create it
                tree_leaf* new_leaf = new tree_leaf;
                new_leaf->right = new_leaf->left = NULL;
                new_leaf->bit = bit;

                temp_root->right = new_leaf;

                temp_root = new_leaf;
            }

        } else {
            // check left subtree
            if (temp_root->left != NULL) {
                // Elemelnt already there, just switch pointer
                temp_root = temp_root->left;
            } else {
                // No element here, we should create it
                tree_leaf* new_leaf = new tree_leaf;
                new_leaf->right = new_leaf->left = NULL;
                new_leaf->bit = bit;

                temp_root->left = new_leaf;

                temp_root = new_leaf;
            }
        }
    }

    // #include <bitset>
    // std::cout<<bitset<32>(netmask_as_int)<<endl;
}

bool fast_ip_lookup(tree_leaf* root, uint32_t ip) {
    // introduce temporary pointer
    tree_leaf* temp_root = root;

    // Blank tree or tree with only root is blank, we can't find nothing in it
    if (temp_root == NULL or (temp_root->left == NULL && temp_root->right == NULL)) {
        return false;
    }

    // convert to host byte order
    ip = ntohl(ip);

    int bits_matched = 0;
    for (int i = 31; i >= 0; i--) {
        // cout<<"bit"<<i<<endl;

        uint32_t result_bit = ip & (1 << i);
        bool bit = result_bit == 0 ? false : true;

        // Current node is terminal node
        if ((temp_root->left == NULL && temp_root->right == NULL)) {
            if (bits_matched > 0) {
                // if we havent child elemets (leaf is terinal) and we have match for single bit at lease
                // thus, we found mask!
                // std::cout<<"Bits matched: "<<bits_matched<<endl;
                return true;
            } else {
                // traversal and we haven't found anything
                return false;
            }
        }

        if (bit) {
            if (temp_root->right != NULL) {
                temp_root = temp_root->right;
                bits_matched++;
            } else {
                if (temp_root->left != NULL) {
                    return false;
                } else {
                    // already checked above
                }
            }
        } else {
            if (temp_root->left != NULL) {
                temp_root = temp_root->left;
                bits_matched++;
            } else {
                if (temp_root->right != NULL) {
                    return false;
                } else {
                    // already checked above
                }
            }
        }
    }

    // We will repeat same checks as in begin of function. But we need it because 
    // we could pass cycle and do not hit any terminals - both childs become zeroes
    if ((temp_root->left == NULL && temp_root->right == NULL)) {
        if (bits_matched > 0) {
            // if we havent child elemets (leaf is terinal) and we have match for single bit at lease
            // thus, we found mask!
            // std::cout<<"Bits matched: "<<bits_matched<<endl;
            return true;
        } else {
            // traversal finished and we haven't found anything
            return false;
        }
    }

    // This point must not achieved in any cases!
    return false;
}

void dump_ip_lookup_tree(tree_leaf* root) {
}

int main() {
    /* Create tree root */
    tree_leaf* root = new tree_leaf;
    root->left = root->right = NULL;

    // uint32_t ip_127 = convert_ip_as_string_to_uint("127.0.0.3");
    // uint32_t ip_159 = convert_ip_as_string_to_uint("159.253.17.1");
    // uint32_t ip_8   = convert_ip_as_string_to_uint("255.8.8.8");

    // insert_prefix_bitwise_tree(root, "159.253.17.0", 24);
    // insert_prefix_bitwise_tree(root, "159.253.16.0", 24);
    // insert_prefix_bitwise_tree(root, "127.0.0.1",    24);
    // insert_prefix_bitwise_tree(root, "255.8.8.8",      32);

    // std::cout<<fast_ip_lookup(root, ip_127)<<endl;
    // std::cout<<fast_ip_lookup(root, ip_159)<<endl;
    // std::cout<<fast_ip_lookup(root, ip_8)<<endl;

    vector<string> networks_list_as_string;
    vector<subnet> our_networks;

    vector<string> network_list_from_config = exec("cat /etc/networks_list");
    networks_list_as_string.insert(networks_list_as_string.end(), network_list_from_config.begin(),
                                   network_list_from_config.end());

    for (vector<string>::iterator ii = networks_list_as_string.begin();
         ii != networks_list_as_string.end(); ++ii) {
        vector<string> subnet_as_string;
        split(subnet_as_string, *ii, boost::is_any_of("/"), boost::token_compress_on);
        int cidr = atoi(subnet_as_string[1].c_str());

        uint32_t subnet_as_int = convert_ip_as_string_to_uint(subnet_as_string[0]);
        uint32_t netmask_as_int = convert_cidr_to_binary_netmask(cidr);

        insert_prefix_bitwise_tree(root, subnet_as_string[0], cidr);

        subnet current_subnet = std::make_pair(subnet_as_int, netmask_as_int);

        our_networks.push_back(current_subnet);
    }

    uint32_t my_ip = convert_ip_as_string_to_uint("192.0.0.192");

    // my_ip = ntohl(my_ip);
    // std::bitset<32> x(my_ip);
    // std::cout<<x;
    for (int i = 0; i < 10000000; i++) {
        belongs_to_networks(our_networks, my_ip);
    }

    for (int i = 0; i < 10000000; i++) {
        fast_ip_lookup(root, my_ip);
    }
}
