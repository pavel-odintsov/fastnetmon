#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "ipset_management.h"

extern "C" {
    // #include <libipset/debug.h>             /* D() */
    #include <libipset/data.h>              /* enum ipset_data */
    #include <libipset/parse.h>             /* ipset_parse_* */
    #include <libipset/session.h>           /* ipset_session_* */
    #include <libipset/types.h>             /* struct ipset_type */
    #include <libipset/ui.h>                /* core options, commands */
    #include <libipset/utils.h>             /* STREQ */
}

/*
int main() {
    manage_ip_ban("blacklist", "8.8.8.8", IPSET_BLOCK);
    sleep(20);
    manage_ip_ban("blacklist", "8.8.8.8", IPSET_UNBLOCK);
}
*/

int manage_ip_ban(const char* blacklist_name, const char* ip_addr, ipset_action action) {
    /* Load set types */
    ipset_load_types();

    struct ipset_session *session = ipset_session_init(printf);

    if (session == NULL) {
        //printf("Can't init session");
        return 1;
    }

    int ipset_parse_setname_ret = ipset_parse_setname(session, IPSET_SETNAME, blacklist_name);

    if (ipset_parse_setname_ret < 0) {
        //printf("Can't check name");
        return 2;
    }

    enum ipset_cmd command = IPSET_CMD_ADD;

    if (action == IPSET_BLOCK) {
        command = IPSET_CMD_ADD;
    } else if (action == IPSET_UNBLOCK) {
        command = IPSET_CMD_DEL;
    } else {
        // printf("Unexpected action");
        return 3;
    }

    const struct ipset_type *type = ipset_type_get(session, command);

    if (type == NULL) {
        //printf("ipset type get failed: %s\n", ipset_session_error(session));
        return 4;
    }

    // We should convert second argument to enum because bug in ipset, it fixed in upstream
    int ipset_parse_elem_ret = ipset_parse_elem(session, (ipset_opt)type->last_elem_optional, ip_addr);

    if (ipset_parse_elem_ret < 0) {
        // printf("Can't call ipset_parse_elem, error: %d\n", ipset_parse_elem_ret);
        // printf("Error: %s", ipset_session_error(session));

        return 5;
    }

    // 777 - line number; Can be any
    int ret = ipset_cmd(session, command, 777);

    if (ret < 0) {
        //printf("Can't ipset_cmd");
        return 6;
    }

    int commit_ret = ipset_commit(session);

    if (commit_ret < 0) {
        //printf("ipset_commit failed\n");
        return 7;
    }

    //printf("Executed correctly\n");

    ipset_session_fini(session);

    return 0;
}
