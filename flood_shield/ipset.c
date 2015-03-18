#include <stdlib.h>
#include <stdio.h>

extern "C" {
    // #include <libipset/debug.h>             /* D() */
    #include <libipset/data.h>              /* enum ipset_data */
    #include <libipset/parse.h>             /* ipset_parse_* */
    #include <libipset/session.h>           /* ipset_session_* */
    #include <libipset/types.h>             /* struct ipset_type */
    #include <libipset/ui.h>                /* core options, commands */
    #include <libipset/utils.h>             /* STREQ */
}

int ban_ip(const char* blacklist_name, const char* ip_addr);

int main() {
    ban_ip("blacklist", "7.7.7.7");
}

int ban_ip(const char* blacklist_name, const char* ip_addr) {
    /* Load set types */
    ipset_load_types();

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
        printf("ipset type get failed: %s\n", ipset_session_error(session));
        exit(1);
    }

    // We should convert second argument to enum because bug in ipset, it fixed in upstream
    int ipset_parse_elem_ret = ipset_parse_elem(session, (ipset_opt)type->last_elem_optional, ip_addr);

    if (ipset_parse_elem_ret < 0) {
        printf("Can't call ipset_parse_elem, error: %d\n", ipset_parse_elem_ret);
        printf("Error: %s", ipset_session_error(session));

        exit(1);
    }

    // 777 - line number
    int ret = ipset_cmd(session, IPSET_CMD_ADD, 777);

    if (ret < 0) {
        printf("Can't ipset_cmd");

        exit(1);
    }

    int commit_ret = ipset_commit(session);

    if (commit_ret < 0) {
        printf("ipset_commit failed\n");
        exit(1);
    }

    printf("Executed correctly\n");

    ipset_session_fini(session);

    return 0;
}
