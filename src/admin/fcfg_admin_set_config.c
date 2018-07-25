static bool show_usage = false;

static void usage(char *program)
{
    fprintf(stderr, "Usage: %s options, the options as:\n"
            "\t -h help\n"
            "\t -u <username>\n"
            "\t -s <secret-key>\n"
            "\t -c <config-filename>\n"
            "\t -e <config-env>\n"
            "\t -n <config-name>\n"
            "\t -v <config-value>\n"
            "\n", program);
}

static void parse_args(int argc, char **argv)
{
    int ch;

    while ((ch = getopt(argc, argv, "hu:s:c:e:n:v:")) != -1) {
        switch (ch) {
            case 'u':
                g_fcfg_admin_vars.username = optarg;
                break;
            case 's':
                g_fcfg_admin_vars.secret_key = optarg;
                break;
            case 'c':
                g_fcfg_admin_set_vars.config_filename = optarg;
                break;
            case 'e':
                g_fcfg_admin_set_vars.confg_env = optarg;
                break;
            case 'n':
                g_fcfg_admin_set_vars.config_name = optarg;
                break;
            case 'v':
                g_fcfg_admin_set_vars.config_value = optarg;
                break;
            case 'h':
            default:
                show_usage = true;
                usage(argv[0]);
                break;
        }
    }
}

void fcfg_set_admin_set_config(FCFGProtoSetConfigReq *fcfg_set_config_proto,
        int *body_len)
{
    fcfg_set_config_proto->env_len = strlen(g_fcfg_admin_set_vars.config_env);
    fcfg_set_config_proto->name_len = strlen(g_fcfg_admin_set_vars.config_name);
    fcfg_set_config_proto->value_len = strlen(g_fcfg_admin_set_vars.config_value);
    memcpy(fcfg_set_config_proto->env, g_fcfg_admin_set_vars.env,
            fcfg_set_config_proto->env_len);
    memcpy(fcfg_set_config_proto->name + fcfg_set_config_proto->env_len,
            g_fcfg_admin_set_vars.name,
            fcfg_set_config_proto->name_len);
    memcpy(fcfg_set_config_proto->value +
            fcfg_set_config_proto->env_len +
            fcfg_set_config_proto->name_len,
            g_fcfg_admin_set_vars.value,
            fcfg_set_config_proto->value_len);
    *body_len = sizeof(fcfg_set_config_proto->env_len) +
                sizeof(fcfg_set_config_proto->name_len) +
                sizeof(fcfg_set_config_proto->value_len) +
                fcfg_set_config_proto->env_len +
                fcfg_set_config_proto->name_len +
                fcfg_set_config_proto->value_len;
}

int fcfg_admin_set_config ()
{
    int ret;
    char buff[1024];
    int body_len;
    int size;
    FCFGResponseInfo resp_info;
    FCFGProtoHeader *fcfg_header_proto;
    FCFGProtoSetConfigReq *fcfg_set_config_proto;

    fcfg_header_proto = (FCFGProtoHeader *)buff;
    fcfg_set_config_proto = (FCFGProtoSetConfigReq *)(buff + sizeof(FCFGProtoHeader));
    fcfg_set_admin_set_config(fcfg_set_config_proto, &body_len);
    fcfg_set_admin_header(fcfg_header_proto, FCFG_PROTO_SET_CONFIG_REQ, body_len);
    size = sizeof(FCFGProtoHeader) + body_len;
    ret = send_and_recv_response_header(g_fcfg_admin_set_vars.join_conn, buff, size, &resp_info,
            g_fcfg_admin_set_vars.network_timeout, g_fcfg_admin_set_vars.connect_timeout);
    if (ret) {
        fprintf(stderr, "send_and_recv_response_header fail. ret:%d, %s\n",
                ret, strerror(ret));
        return ret;
    }
    ret = fcfg_admin_check_response(join_conn, &resp_info, g_fcfg_admin_set_vars.network_timeout);
    if (ret) {
        fprintf(stderr, "set config fail.err info: %s\n",
                resp_info.error.message);
    } else {
        fprintf(stderr, "set config success !\n");
    }

    return ret;
}

int main (int argc, char **agrv)
{
    int ret;

    if (argc < 5) {
        usage(agrv[0]);
        return 1;
    }
    parse_args(argc, argv);
    if (show_usage) {
        usage(agrv[0]);
        return 0;
    }

    ret = fcfg_admin_set_load_config(config_file);
    if (ret) {
        fprintf(stderr, "fcfg_admin_set_load_config fail:%s, ret:%d, %s",
                ret, strerror(ret), config_file);
        return ret;
    }


    if (ret = conn_pool_connect_server(&g_fcfg_admin_set_vars.join_conn,
                g_fcfg_admin_set_vars.connect_timeout) != 0) {
        return ret;
    }

    if (ret = fcfg_send_admin_join_request(&g_fcfg_admin_set_vars.join_conn,
            g_fcfg_admin_set_vars.network_timeout,
            g_fcfg_admin_set_vars.connect_timeout) != 0) {
        return ret;
    }

    ret = fcfg_admin_set_config();
    if (g_fcfg_admin_set_vars.join_conn.sock >= 0) {
        conn_pool_disconnect_server(&g_fcfg_admin_set_vars.join_conn);
    }
}
