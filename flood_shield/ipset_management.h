#ifndef _IPSET_MANAGEMENT_H
#define _IPSET_MANAGEMENT_H

typedef enum {IPSET_BLOCK, IPSET_UNBLOCK} ipset_action;
int manage_ip_ban(const char* blacklist_name, const char* ip_addr, ipset_action action);

#endif
