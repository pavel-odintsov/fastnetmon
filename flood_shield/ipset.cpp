#include <stdlib.h>
#include <stdio.h>

// #include <libipset/debug.h>             /* D() */
#include <libipset/data.h>              /* enum ipset_data */
#include <libipset/parse.h>             /* ipset_parse_* */
#include <libipset/session.h>           /* ipset_session_* */
#include <libipset/types.h>             /* struct ipset_type */
#include <libipset/ui.h>                /* core options, commands */
#include <libipset/utils.h>             /* STREQ */

int ban_ip(char* blacklist_name, char* ip_addr);

int main() {
    ban_ip("blacklist", "10.10.10.1");
}

int ban_ip(char* blacklist_name, char* ip_addr) {
    struct ipset_session *session = ipset_session_init(printf);

    if (session == NULL) {
        printf("Can't init session");
        exit(1);
    }

    int ipset_parse_setname_ret = ipset_parse_setname(session, IPSET_SETNAME, blacklist_name);

    if (ipset_parse_setname_ret < 0) {
        printf("Can't check name");
        exit(1);
    }

    const struct ipset_type *type = ipset_type_get(session, IPSET_CMD_ADD);

    if (type == NULL) {
        printf("ipset type get failed");
        exit(1);
    }


    printf("bool value:%d\n", type->last_elem_optional);
    int ipset_parse_elem_ret = ipset_parse_elem(session, (ipset_opt)0, ip_addr);

    if (ipset_parse_elem_ret < 0) {
        printf("Can't call ipset_parse_elem");
        exit(1);
    }

    // 777 - line number
    int ret = ipset_cmd(session, IPSET_CMD_ADD, 777);

    if (ret < 0) {
        printf("Can't ipset_cmd");
    }

    ipset_session_fini(session);

    return 0;
}
