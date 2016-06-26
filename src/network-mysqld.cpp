

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>

#ifdef HAVE_SYS_FILIO_H
/**
 * required for FIONREAD on solaris
 */
#include <sys/filio.h>
#endif

#ifndef _WIN32
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h> /** inet_ntoa */
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <netdb.h>
#include <unistd.h>
#else
#include <winsock2.h>
#include <io.h>
#define ioctl ioctlsocket
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif

#include <glib.h>

#include <mysql.h>
#include <mysqld_error.h>

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-conn-pool.h"
#include "resultset_merge.h"
#include "perf_monitor.h"
#include "partition.h"
#include "network-mysqld-proxy.h"

#ifdef _WIN32
extern volatile int agent_shutdown;
#else
extern volatile sig_atomic_t agent_shutdown;
#endif

#define		DEBUG_GLIB_MEM	1

#ifdef _WIN32
#define E_NET_CONNRESET WSAECONNRESET
#define E_NET_WOULDBLOCK WSAEWOULDBLOCK
#else
#define E_NET_CONNRESET ECONNRESET
#if EWOULDBLOCK == EAGAIN
/**
 * some system make EAGAIN == EWOULDBLOCK which would lead to a 
 * error in the case handling
 *
 * set it to -1 as this error should never happen
 */
#define E_NET_WOULDBLOCK -1
#else
#define E_NET_WOULDBLOCK EWOULDBLOCK
#endif
#endif

#define C(x) x, sizeof(x) - 1

#define  BIGQUERY  (100 * 1024)

char *sz_state[] = {
    "CON_STATE_INIT", // 0
    "CON_STATE_SEND_HANDSHAKE",
    "CON_STATE_READ_AUTH",
    "CON_STATE_CREATE_AUTH_RESPONSE", // 5
    "CON_STATE_SEND_AUTH_RESULT",
    "CON_STATE_READ_AUTH_OLD_PASSWORD",
    "CON_STATE_SEND_AUTH_OLD_PASSWORD",
    "CON_STATE_READ_QUERY", // 10
    "CON_STATE_SEND_QUERY",
    "CON_STATE_SEND_SINGLE_QUERY_RESULT",
    "CON_STATE_READ_SINGLE_QUERY_RESULT",
    "CON_STATE_READ_QUERY_RESULT",
    "CON_STATE_SEND_QUERY_RESULT",

    "CON_STATE_CLOSE_CLIENT",
    "CON_STATE_SEND_ERROR", // 15
    "CON_STATE_ERROR",
    "CON_STATE_MULTIPART_SEND_AUTH_OLD_PASSWORD",
    "CON_STATE_MULTIPART_SEND_QUERY",
    "CON_STATE_GET_SERVER_LIST",
    "CON_STATE_GET_SERVER_CONNECTION_LIST",
    "CON_STATE_PROCESS_READ_QUERY"
};

char *sz_async_state[] = {
    "CON_STATE_ASYNC_INIT", // 0
    "CON_STATE_ASYNC_READ_HANDSHAKE",
    "CON_STATE_ASYNC_CREATE_AUTH",
    "CON_STATE_ASYNC_SEND_AUTH",
    "CON_STATE_ASYNC_READ_AUTH_RESULT",
    "CON_STATE_ASYNC_SELECT_DB",
    "CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD",
    "CON_STATE_ASYNC_SEND_AUTH_OLD_PASSWORD",
    "CON_STATE_ASYNC_ERROR",
    "CON_STATE_ASYNC_NONE"
};

char *sz_rw_state[] = {
    "NET_RW_STATE_NONE", // 0
    "NET_RW_STATE_WRITE",
    "NET_RW_STATE_READ",
    "NET_STATE_READ", // normal inline read
    "NET_RW_STATE_ERROR"
};

static void network_mysqld_con_async_writeread(int event_fd, short events, void *user_data);

retval_t plugin_call_cleanup(network_mysqld *srv, network_mysqld_con *con) {
    NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;

    func = con->plugins.con_cleanup;

    if (!func) return RET_SUCCESS;

    return (*func)(srv, con);
}

network_mysqld_con *network_mysqld_con_init(network_mysqld *srv) {
    network_mysqld_con *con;

    con = g_new0(network_mysqld_con, 1);

    con->srv = srv;

    g_ptr_array_add(srv->cons, con);

    //log_debug("%s.%d:network_mysqld_con_init", __FILE__, __LINE__);
    con->servers = g_ptr_array_new();
    con->cache_servers = g_ptr_array_new();
    con->sql_tokens = NULL;
    con->server_hostnames = NULL;

    return con;
}

void msbackend_free(network_mysqld_con *con);

void network_mysqld_con_free(network_mysqld_con *con) {
    MULTIPART_DATA *pmd;

    if (!con) return;

    free_gstring_ptr_array(con->server_hostnames);

    if (con->servers) {
        //log_debug("network_mysqld_con_free %d", con->servers->len);

        // remove all of the connections and put them back in the pool
        proxy_remove_server_connections(con->srv, con);

        size_t index = 0;
        for (index = 0; index < con->servers->len; index++) {
            pmd = (MULTIPART_DATA*) con->servers->pdata[index];
            pmd_free(pmd);
        }
        g_ptr_array_free(con->servers, TRUE);

        for (index = 0; index < con->cache_servers->len; index++) {
            pmd = (MULTIPART_DATA*) con->cache_servers->pdata[index];
            pmd_free(pmd);
        }
        g_ptr_array_free(con->cache_servers, TRUE);
    }

    // do NOT free server handle, this is part of the servers array and
    // the above code has added it back to the pool
    // if (con->server) network_socket_free(con->server);

    if (con->client) network_socket_free(con->client);

    /* we are still in the conns-array */

    //free SQL token list 
    if (con->sql_tokens != NULL) {
        sql_tokens_free(con->sql_tokens);
        con->sql_tokens = NULL;
    }

    g_ptr_array_remove_fast(con->srv->cons, con);

    msbackend_free(con);

    g_free(con);
}

void network_config_free(backend_config *config) {
    if (config) {
        if (config->default_username)
            g_string_free(config->default_username, TRUE);

        if (config->default_password)
            g_string_free(config->default_password, TRUE);

        if (config->default_db)
            g_string_free(config->default_db, TRUE);

        g_free(config);
    }
}

void network_mysqld_async_con_state_free(struct server_connection_state * con) {
    if (!con)
        return;

    // remove the server_connection_state object from the array
    proxy_connection_pool_del(con);

    if (con) {
        if (con->server)
            network_socket_free(con->server);

        // the config is not owned by the server_connection_state, it
        // is only pointing to the connection server config
        //if ( con->config )
        //	network_config_free( con->config );

        if (con->plugin_con_state)
            plugin_con_state_free((plugin_con_state *) (con->plugin_con_state));
        g_free(con);
    }
}

/**
 * the free functions used by g_hash_table_new_full()
 */
static void network_mysqld_tables_free_void(void *s) {
    network_mysqld_table_free((network_mysqld_table *) s);
}

network_mysqld *network_mysqld_init() {
    network_mysqld *m;

    m = g_new0(network_mysqld, 1);

    m->event_base = NULL;

    m->tables = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, network_mysqld_tables_free_void);

    m->cons = g_ptr_array_new();

    m->backend_pool = g_ptr_array_new();

    return m;
}

/**
 * converts a byte stream into a printable and readable form in both
 * hex and ascii.  the return pointer is a malloced and must be (freed)
 * by the caller.
 */

char *ConvertBufToHex(const unsigned char *pBuf, unsigned int *iLength) {
    int iMallocLen = 1 + (*iLength * 3) + ((*iLength / 8) + 1) + 1 + (*iLength * 3) + 1;
    char *pData = (char *) malloc(iMallocLen);
    char *pHexBuf = pData;
    unsigned int uiIndex = 0;
    char cBuf[5];
    char cAscii[1 + 8 * 3 + 1];
    char *pAscii = cAscii;
    int iAsciiLength = 0;

    memset((void*) pData, 0, iMallocLen);
    memset((void*) cAscii, 0, sizeof (cAscii));

    for (uiIndex = 0;
            uiIndex < *iLength;
            uiIndex++) {
        if ((uiIndex % 8) == 0) {
            iAsciiLength = strlen(cAscii);
            strcat(pHexBuf, cAscii);
            pHexBuf += iAsciiLength;
            memset((void*) cAscii, 0, sizeof (cAscii));
            pAscii = cAscii;

            pHexBuf[0] = '\n';
            pHexBuf++;
        }
        memset((void*) cBuf, 0, sizeof (cBuf));

        if ((pBuf[uiIndex] > 30) && (pBuf[uiIndex] < 127))
            sprintf(pAscii, " %c", pBuf[uiIndex]);
        else
            strcpy(pAscii, " .");
        pAscii += 2;

        sprintf(cBuf, "%02x ", pBuf[uiIndex]);

        strcpy(pHexBuf, cBuf);
        pHexBuf += 3;
    }

    iAsciiLength = strlen(cAscii);
    if (iAsciiLength > 0) {
        strcpy(pHexBuf, cAscii);
        pHexBuf += iAsciiLength;
    }

    *iLength = (uint) (pHexBuf - pData);
    g_assert(*iLength < (uint) iMallocLen);
    return pData;
}

/**
 * init libevent
 *
 * kqueue has to be called after the fork() of daemonize
 *
 */
void network_mysqld_init_libevent(network_mysqld *m) {

    const char *user = get_config_string("DB_USER");
    const char *passwd = get_config_string("DB_PASSWD");

    if (!user || !passwd) {
        log_info("user name or password is not configured. exiting ...\n");
        exit(1);
    }

    m->event_base = (event_base *) event_init();

    // fill in some bogus data for now
    m->db_config.default_username = g_string_new(NULL);
    g_string_append(m->db_config.default_username, user);
    m->db_config.default_password = g_string_new(NULL);
    g_string_append_len(m->db_config.default_password, passwd, strlen(passwd) + 1);
    m->db_config.default_db = g_string_new(NULL);
    g_string_append(m->db_config.default_db, "test");
    m->db_config.client_flags = DEFAULT_FLAGS;
    m->db_config.charset = DEFAULT_CHARSET;
    m->db_config.max_conn_pool = get_config_max_conn_pool_size();

}

/**
 * free the global scope
 *
 * closes all open connections
 */
void network_mysqld_free(network_mysqld *m) {
    guint i;

    if (!m) return;

    for (i = 0; i < m->cons->len; i++) {
        network_mysqld_con *con = (network_mysqld_con *) (m->cons->pdata[i]);

        plugin_call_cleanup(m, con);
        network_mysqld_con_free(con);
    }

    g_ptr_array_free(m->cons, TRUE);

    g_hash_table_destroy(m->tables);

    if (m->config.proxy.backend_addresses) {
        for (i = 0; m->config.proxy.backend_addresses[i]; i++) {
            g_free(m->config.proxy.backend_addresses[i]);
        }
        g_free(m->config.proxy.backend_addresses);
    }

    if (m->config.proxy.address) {
        network_mysqld_proxy_free(NULL);

        g_free(m->config.proxy.address);
    }
    if (m->config.admin.address) {
        g_free(m->config.admin.address);
    }
#ifdef HAVE_EVENT_BASE_FREE
    /* only recent versions have this call */
    event_base_free(m->event_base);
#endif

    if (NULL != m->db_config.default_username)
        g_string_free(m->db_config.default_username, TRUE);

    if (NULL != m->db_config.default_password)
        g_string_free(m->db_config.default_password, TRUE);

    if (NULL != m->db_config.default_db)
        g_string_free(m->db_config.default_db, TRUE);

    for (i = 0; i < m->backend_pool->len; i++) {
        backend_t *backend = (backend_t *) (m->backend_pool->pdata[i]);
        backend_free(backend);
    }

    g_ptr_array_free(m->backend_pool, TRUE);

    g_free(m);
}

/**
 * connect to the proxy backend */
int network_mysqld_con_set_address(network_address *addr, gchar *address) {
    gchar *s;
    guint port;

    //log_debug("%s.%d: network_mysqld_con_set_address(%s)\n", __FILE__, __LINE__, address);

    /* split the address:port */
    if (NULL != (s = strchr(address, ':'))) {
        port = strtoul(s + 1, NULL, 10);

        if (port == 0) {
            log_error("<ip>:<port>, port is invalid or 0, has to be > 0, got '%s'", address);
            return -1;
        }
        if (port > 65535) {
            log_error("<ip>:<port>, port is too large, has to be < 65536, got '%s'", address);

            return -1;
        }

        memset(&addr->addr.ipv4, 0, sizeof (struct sockaddr_in));

        if (address == s ||
                0 == strcmp("0.0.0.0", address)) {
            /* no ip */
            addr->addr.ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            struct hostent *he;

            *s = '\0';
            he = gethostbyname(address);
            *s = ':';

            if (NULL == he) {
                log_error("resolving proxy-address '%s' failed: ", address);
            }

            g_assert(he->h_addrtype == AF_INET);
            g_assert(he->h_length == sizeof (struct in_addr));

            memcpy(&(addr->addr.ipv4.sin_addr.s_addr), he->h_addr_list[0], he->h_length);
        }

        addr->addr.ipv4.sin_family = AF_INET;
        addr->addr.ipv4.sin_port = htons(port);
        addr->len = sizeof (struct sockaddr_in);
        addr->str = g_strdup(address);
#ifdef HAVE_SYS_UN_H
    } else if (address[0] == '/') {
        if (strlen(address) >= sizeof (addr->addr.un.sun_path) - 1) {
            log_error("unix-path is too long: %s", address);
            return -1;
        }

        addr->addr.un.sun_family = AF_UNIX;
        strcpy(addr->addr.un.sun_path, address);
        addr->len = sizeof (struct sockaddr_un);
        addr->str = g_strdup(address);
#endif
    } else {
        /* might be a unix socket */
        log_error("%s.%d: network_mysqld_con_set_address(%s) failed: address has to be <ip>:<port> for TCP or a absolute path starting with / for Unix sockets",
                __FILE__, __LINE__,
                address);
        return -1;
    }

    return 0;
}

/**
 * connect to the address defined in con->addr
 *
 * @see network_mysqld_set_address 
 */
int network_mysqld_con_connect(network_mysqld *srv, network_socket * con) {
    int val = 1;

    //log_debug("%s.%d: con_connect\n", __FILE__, __LINE__ );

    g_assert(con->addr.len);

    /**
     * con->addr.addr.ipv4.sin_family is always mapped to the same field 
     * even if it is not a IPv4 address as we use a union
     */
    if (-1 == (con->fd = socket(con->addr.addr.ipv4.sin_family, SOCK_STREAM, 0))) {
        log_error("%s.%d: socket(%s) failed: %s",
                __FILE__, __LINE__,
                con->addr.str, strerror(errno));
        return -1;
    }

    setsockopt(con->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof (val));

    // define a starting point for the connection
    START_PERF(con, con->addr.str, PF_CONNECT);

    if (-1 == connect(con->fd, (struct sockaddr *) &(con->addr.addr), con->addr.len)) {
        log_error("%s.%d: connect(%s) failed: %s",
                __FILE__, __LINE__,
                con->addr.str,
                strerror(errno));
        return -1;
    }

    return 0;
}

int network_mysqld_con_bind(network_socket * con) {
    int val = 1;

    g_assert(con->addr.len);

    if (-1 == (con->fd = socket(con->addr.addr.ipv4.sin_family, SOCK_STREAM, 0))) {
        log_error("%s.%d: socket(%s) failed: %s",
                __FILE__, __LINE__,
                con->addr.str, strerror(errno));
        return -1;
    }

    setsockopt(con->fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof (val));
    setsockopt(con->fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof (val));

    if (-1 == bind(con->fd, (struct sockaddr *) &(con->addr.addr), con->addr.len)) {
        log_error("%s.%d: bind(%s) failed: %s",
                __FILE__, __LINE__,
                con->addr.str,
                strerror(errno));
        return -1;
    }

    if (-1 == listen(con->fd, 8)) {
        log_error("%s.%d: listen() failed: %s",
                __FILE__, __LINE__,
                strerror(errno));
        return -1;
    }

    return 0;
}

void dump_str(const char *msg, const unsigned char *s, size_t len) {
    GString *hex;
    size_t i;

    hex = g_string_new(NULL);

    for (i = 0; i < len; i++) {
        g_string_append_printf(hex, "%02x", s[i]);

        if ((i + 1) % 16 == 0) {
            g_string_append(hex, "\n");
        } else {
            g_string_append_c(hex, ' ');
        }

    }

    log_info("(%s): %s", msg, hex->str);

    g_string_free(hex, TRUE);

}

int network_mysqld_con_send_ok_full(network_socket *con, guint64 affected_rows, guint64 insert_id, guint16 server_status, guint16 warnings, gchar *msg) {
    GString *packet = g_string_new(NULL);

    network_mysqld_proto_append_int8(packet, 0); /* no fields */
    network_mysqld_proto_append_lenenc_int(packet, affected_rows);
    network_mysqld_proto_append_lenenc_int(packet, insert_id);
    network_mysqld_proto_append_int16(packet, server_status); /* autocommit */
    network_mysqld_proto_append_int16(packet, warnings); /* no warnings */

    if (msg != NULL)
        network_mysqld_proto_append_lenenc_string(packet, msg); /* msg */

    network_queue_append(con->send_queue, packet->str, packet->len, con->packet_id);

    g_string_free(packet, TRUE);

    return 0;
}

int network_mysqld_con_send_ok(network_socket *con) {
    return network_mysqld_con_send_ok_full(con, 0, 0, 0x0002, 0, NULL);
}

int network_mysqld_con_send_command(network_socket *con, int cmd, const char *arg) {

    GString *packet = g_string_new(NULL);

    network_mysqld_proto_append_int8(packet, cmd);
    network_mysqld_proto_append_lenenc_string(packet, arg);

    network_queue_append(con->send_queue, packet->str, packet->len, con->packet_id);
    g_string_free(packet, TRUE);

    return 0;
}

int network_mysqld_con_send_select_db(network_socket *con, const char *db) {

    GString *packet = g_string_new(NULL);

    network_mysqld_proto_append_int8(packet, strlen(db) + 1);
    network_mysqld_proto_append_int8(packet, 0);
    network_mysqld_proto_append_int8(packet, 0);
    network_mysqld_proto_append_int8(packet, 0);
    network_mysqld_proto_append_int8(packet, 2);
    g_string_append(packet, db);

    g_queue_push_tail(con->send_queue->chunks, packet);

    return 0;
}

/**
 * send a error packet to the client connection
 *
 * @note the sqlstate has to match the SQL standard. If no matching SQL state is known, leave it at NULL
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 * @param errorcode   mysql error-code we want to send
 * @param sqlstate    if none-NULL, 5-char SQL state to send, if NULL, default SQL state is used
 *
 * @return 0 on success
 */
int network_mysqld_con_send_error_full(network_socket *con, const char *errmsg, gsize errmsg_len, guint errorcode, const gchar *sqlstate) {
    GString *packet;

    packet = g_string_sized_new(10 + errmsg_len);

    network_mysqld_proto_append_int8(packet, 0xff); /* ERR */
    network_mysqld_proto_append_int16(packet, errorcode); /* errorcode */
    g_string_append_c(packet, '#');
    if (!sqlstate) {
        g_string_append_len(packet, C("07000"));
    } else {
        g_string_append_len(packet, sqlstate, 5);
    }

    if (errmsg_len < 512) {
        g_string_append_len(packet, errmsg, errmsg_len);
    } else {
        /* truncate the err-msg */
        g_string_append_len(packet, errmsg, 512);
    }

    network_queue_append(con->send_queue, packet->str, packet->len, con->packet_id);

    g_string_free(packet, TRUE);

    return 0;
}

/**
 * send a error-packet to the client connection
 *
 * errorcode is 1000, sqlstate is NULL
 *
 * @param con         the client connection
 * @param errmsg      the error message
 * @param errmsg_len  byte-len of the error-message
 *
 * @see network_mysqld_con_send_error_full
 */
int network_mysqld_con_send_error(network_socket *con, const char *errmsg, gsize errmsg_len) {
    return network_mysqld_con_send_error_full(con, errmsg, errmsg_len, ER_UNKNOWN_ERROR, NULL);
}

static void dump_raw_data(int fd, const char *buff, unsigned int len) {
    char *pData = ConvertBufToHex((const unsigned char *) buff, &len);

    char *row = pData;
    int i = 0;
    while (row) {
        char *newline = strchr(row, '\n');
        if (newline) {
            *newline = 0;
            newline++;
        }
        log_info("SOCKET=%d: RAW DATA(%d): %s\n", fd, i++, row);
        row = newline;
    }

    log_info("SOCKET=%d: RAW DATA end.\n", fd);

    free(pData);
}

static retval_t network_mysqld_write_raw(int fd, const char *buff, int len, int *nbytes_sent) {
    *nbytes_sent = send(fd, buff, len, 0);

    if (*nbytes_sent == -1) {
        switch (errno) {
            case EAGAIN:
                return RET_WAIT_FOR_EVENT;
            default:
                log_error("%s.%d: write() failed: %s", __FILE__, __LINE__,
                        strerror(errno));
                return RET_ERROR;
        }
    }

    if (get_config_log_raw_data()) {
        log_info("SOCKET=%d: %d bytes actually sent, %d left.\n", fd, *nbytes_sent, len - *nbytes_sent);
        dump_raw_data(fd, buff, *nbytes_sent);
    } else
        log_debug("SOCKET=%d: %d bytes actually sent, %d left.\n", fd, *nbytes_sent, len - *nbytes_sent);

    return RET_SUCCESS;
}

static retval_t network_mysqld_buffered_write(network_socket *con) {
    if (con->send_buff_left == 0) {
        // copy content into send buffer

        if (con->send_queue->chunks->length == 0)
            return RET_SUCCESS;

        con->send_buff_offset = 0;
        size_t len = sizeof (con->send_buff);

        for (GList *chunk = con->send_queue->chunks->head; chunk;) {
            GString *s = (GString *) (chunk->data);
            if (s->len <= len) {
                memcpy(con->send_buff + con->send_buff_left, s->str, s->len);
                con->send_buff_left += s->len;
                len -= s->len;

                g_string_free(s, TRUE);
                g_queue_delete_link(con->send_queue->chunks, chunk);
                chunk = con->send_queue->chunks->head;
            } else
                break;
        }

        // we do not expect packet larger than 64K now
        g_assert(con->send_buff_left);
    }


    if (con->send_buff_left) {
        int len;
        log_debug("%s.%d: SOCKET=%d, try to send %d bytes using send_buff.\n",
                __FILE__, __LINE__, con->fd, con->send_buff_left);
        retval_t rv =
                network_mysqld_write_raw(con->fd,
                con->send_buff + con->send_buff_offset,
                con->send_buff_left, &len);

        if (rv != RET_SUCCESS)
            return rv;

        con->send_buff_offset += len;
        con->send_buff_left -= len;
        con->last_write_time = time(NULL);

        return (con->send_queue->chunks->length || (con->send_buff_left > 0)) ?
                RET_WAIT_FOR_EVENT : RET_SUCCESS;
    }

    return RET_SUCCESS;
}

retval_t network_mysqld_write_len(network_socket *con) {

    if (con->send_buff_left > 0)
        return network_mysqld_buffered_write(con);

    if (con->send_queue->chunks->length == 0)
        return RET_SUCCESS;

    GList *chunk = con->send_queue->chunks->head;
    GString *s = (GString *) (chunk->data);
    if (s->len < sizeof (con->send_buff))
        return network_mysqld_buffered_write(con);
    else {
        // if the packet is big enough, send packet directly
        //
        int len;

        g_assert(con->send_queue->offset < s->len);

        log_debug("%s.%d: SOCKET=%d, try to send %u bytes directly.\n",
                __FILE__, __LINE__, con->fd, s->len - con->send_queue->offset);

        retval_t rv =
                network_mysqld_write_raw(con->fd,
                s->str + con->send_queue->offset,
                s->len - con->send_queue->offset, &len);

        if (rv != RET_SUCCESS)
            return rv;

        con->send_queue->offset += len;
        con->last_write_time = time(NULL);

        if (con->send_queue->offset == s->len) {
            g_string_free(s, TRUE);

            g_queue_delete_link(con->send_queue->chunks, chunk);
            con->send_queue->offset = 0;

            chunk = con->send_queue->chunks->head;
            return chunk != NULL ? RET_WAIT_FOR_EVENT : RET_SUCCESS;
        } else {
            return RET_WAIT_FOR_EVENT;
        }
    }

    return RET_SUCCESS;
}

retval_t network_mysqld_read(network_socket *con, int *is_finished) {
    char buff[64 * 1024];

    if (is_finished)
        *is_finished = 0;

    int len = recv(con->fd, buff, sizeof (buff), 0);

    if (len > 0) {
        con->bytes_recved += len;

        if (get_config_log_raw_data()) {
            log_info("SOCKET=%d: recved %d bytes.\n", con->fd, len);
            dump_raw_data(con->fd, buff, len);
        } else {
            log_debug("SOCKET=%d: recved %d bytes.\n", con->fd, len);
        }
    }

    // check errors first
    if (len == -1) {
        switch (errno) {
            case EAGAIN:
                return RET_WAIT_FOR_EVENT;
            default:
                log_error("%s: recv() failed: %s (errno=%d)", G_STRLOC, strerror(errno), errno);
                return RET_ERROR;
        }
    } else if (len == 0)
        return RET_WAIT_FOR_EVENT;

    GString *packet = NULL;
    if ((con->recv_queue->chunks == NULL) ||
            (con->recv_queue->chunks->tail == NULL)) {
        con->packet_len = PACKET_LEN_UNSET;
        packet = NULL;
    } else
        packet = (GString *) (con->recv_queue->chunks->tail->data);

    char *ptr = buff;
    char *buff_end = buff + len;

    // check if we need to finish the last packet first
    //
    if (packet != NULL) {
        if (packet->len + len < NET_HEADER_SIZE) {
            // we do not have the full packet header
            //
            g_string_append_len(packet, ptr, len);
            return RET_WAIT_FOR_EVENT;
        }

        if (packet->len < NET_HEADER_SIZE) {
            // copy the header first so we can check the packet len
            //
            int header_left = NET_HEADER_SIZE - packet->len;
            g_string_append_len(packet, ptr, header_left);
            con->packet_len =
                    network_mysqld_proto_get_header((unsigned char *) (packet->str));
            con->packet_id = (unsigned char) (packet->str[3]);
            ptr += header_left;
        }

        int packet_left = con->packet_len - (packet->len - NET_HEADER_SIZE);
        if (ptr + packet_left <= buff_end) {
            // we have received the whole packet
            //
            g_string_append_len(packet, ptr, packet_left);
            ptr += packet_left;

            if (is_finished) {
                proxy_read_query_result_is_finished(con, is_finished);
                if (*is_finished)
                    log_debug("result set done for socket %d.\n", con->fd);
            }
        } else {
            g_string_append_len(packet, ptr, buff_end - ptr);
            return RET_WAIT_FOR_EVENT;
        }
    }

    //read whole packets or at least the header
    //
    while (ptr + NET_HEADER_SIZE <= buff_end) {
        // we have the packet header at least
        //
        con->packet_len = network_mysqld_proto_get_header((unsigned char *) ptr);
        con->packet_id = (unsigned char) (ptr[3]);
        if (ptr + NET_HEADER_SIZE + con->packet_len <= buff_end) {
            // the whole packet is available
            //
            GString *pkt = g_string_new_len(ptr, NET_HEADER_SIZE +
                    con->packet_len);
            network_queue_append_chunk(con->recv_queue, pkt);
            ptr += NET_HEADER_SIZE + con->packet_len;

            if (is_finished) {
                proxy_read_query_result_is_finished(con, is_finished);
                if (*is_finished)
                    log_debug("SOCKET=%d: results done.\n", con->fd);
            }
        } else {
            // only partial packet is available
            GString *pkt = g_string_new_len(ptr, buff_end - ptr);
            network_queue_append_chunk(con->recv_queue, pkt);
            return RET_WAIT_FOR_EVENT;
        }
    }

    if (ptr < buff_end) {
        // we only have partial packet header
        //
        con->packet_len = PACKET_LEN_UNSET;
        GString *pkt = g_string_new_len(ptr, buff_end - ptr);
        network_queue_append_chunk(con->recv_queue, pkt);
        return RET_WAIT_FOR_EVENT;
    }

    return RET_SUCCESS;
}

retval_t network_mysqld_write(network_mysqld *srv, network_socket *con) {
    retval_t ret;
    int corked;

#ifdef TCP_CORK
    corked = 1;
    setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof (corked));
#endif
    ret = network_mysqld_write_len(con);
#ifdef TCP_CORK
    corked = 0;
    setsockopt(con->fd, IPPROTO_TCP, TCP_CORK, &corked, sizeof (corked));
#endif

    return ret;
}

/**
 * call the hooks of the plugins for each state
 *
 * if the plugin doesn't implement a hook, we provide a default operation
 */
retval_t plugin_call(network_mysqld *srv, network_mysqld_con *con, int state) {
    NETWORK_MYSQLD_PLUGIN_FUNC(func) = NULL;

    switch (state) {
        case CON_STATE_INIT:
            func = con->plugins.con_init;

            if (!func) { /* default implementation */
                con->state = CON_STATE_SEND_HANDSHAKE;
            }
            break;

        case CON_STATE_SEND_HANDSHAKE:
            func = con->plugins.con_send_handshake;

            if (!func) { /* default implementation */

                con->state = CON_STATE_READ_AUTH;
            }

            break;
        case CON_STATE_READ_AUTH:
            func = con->plugins.con_read_auth;
            break;

        case CON_STATE_CREATE_AUTH_RESPONSE:
            func = con->plugins.con_create_auth_result;

            if (!func) { /* default implementation */
                con->state = CON_STATE_SEND_AUTH_RESULT;
            }
            break;
        case CON_STATE_SEND_AUTH_RESULT:
            func = con->plugins.con_send_auth_result;

            if (!func) { /* default implementation */
                switch (con->parse.state.auth_result.state) {
                    case MYSQLD_PACKET_OK:
                        con->state = CON_STATE_READ_QUERY;
                        break;
                    case MYSQLD_PACKET_ERR:
                        con->state = CON_STATE_ERROR;
                        log_warning("%s.%d: error in response for SEND_AUTH_RESULT: %02x",
                                __FILE__, __LINE__,
                                con->parse.state.auth_result.state);

                        break;
                    case MYSQLD_PACKET_EOF:
                        /**
                         * the MySQL 4.0 hash in a MySQL 4.1+ connection
                         */
                        con->state = CON_STATE_READ_AUTH_OLD_PASSWORD;
                        break;
                    default:
                        log_error("%s.%d: unexpected state for SEND_AUTH_RESULT: %02x",
                                __FILE__, __LINE__,
                                con->parse.state.auth_result.state);
                }
            }
            break;
        case CON_STATE_READ_AUTH_OLD_PASSWORD:
        {
            /** move the packet to the send queue */
            GString *packet;
            GList *chunk;
            network_socket *recv_sock, *send_sock;

            recv_sock = con->client;
            send_sock = con->server;

            if (NULL == con->server) {
                /**
                 * we have to auth against same backend as we did before
                 * but the user changed it
                 */

                log_info("%s.%d: (lua) read-auth-old-password failed as backend_ndx got reset.", __FILE__, __LINE__);

                network_mysqld_con_send_error(con->client, C("(lua) read-auth-old-password failed as backend_ndx got reset."));
                con->state = CON_STATE_SEND_ERROR;
                break;
            }

            chunk = recv_sock->recv_queue->chunks->head;
            packet = (GString *) (chunk->data);

            /* we aren't finished yet */
            if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE) return RET_SUCCESS;

            network_queue_append_chunk(send_sock->send_queue, packet);

            recv_sock->packet_len = PACKET_LEN_UNSET;
            g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

            /**
             * send it out to the client 
             */
            con->state = CON_STATE_SEND_AUTH_OLD_PASSWORD;
            break;
        }
        case CON_STATE_SEND_AUTH_OLD_PASSWORD:
            /**
             * data is at the server, read the response next 
             */
            con->state = CON_STATE_CREATE_AUTH_RESPONSE;
            break;
        case CON_STATE_MULTIPART_SEND_AUTH_OLD_PASSWORD:
            break;
        case CON_STATE_READ_QUERY:
            func = con->plugins.con_read_query;
            break;
        case CON_STATE_GET_SERVER_LIST:
            func = con->plugins.con_get_server_list;
            break;
        case CON_STATE_GET_SERVER_CONNECTION_LIST:
            func = con->plugins.con_get_server_connection_list;
            break;
        case CON_STATE_READ_QUERY_RESULT:
            func = con->plugins.con_read_query_result;
            break;
        case CON_STATE_SEND_QUERY_RESULT:
            func = con->plugins.con_send_query_result;

            if (!func) { /* default implementation */
                con->state = CON_STATE_READ_QUERY;
            }
            break;
        default:
            log_error("%s.%d: unhandled state: %d",
                    __FILE__, __LINE__,
                    state);
    }
    if (!func) return RET_SUCCESS;

    return (*func)(srv, con);
}

/*
        The purpose of this section is to handle asynchronous server communication
        without the main code processing logic for both writing and then reading
    afterwards.  This could have been put into the main loop code but it's
        more manageable now.
 */

typedef struct tag_writeread_data {
    struct event_base *event_base;
    network_socket *server;
    network_mysqld *srv;
    network_mysqld_con *client;
} writeread_data;

/*
        create the writeread_data structure
 */
static writeread_data * create_writeread_data(network_mysqld *srv, network_socket *sock, network_mysqld_con *client) {
    writeread_data *data = g_new0(writeread_data, 1);
    data->event_base = srv->event_base;
    data->server = sock;
    data->srv = srv;
    data->client = client;
    return data;
}

/*
        free the writeread_data structure
 */
void free_writeread_data(writeread_data *data) {
    if (data != NULL)
        g_free(data);
}

static const char *get_event_name(int events) {
    static char name[64];
    name[0] = 0;

    if (events & EV_TIMEOUT)
        strcat(name, "|EV_TIMEOUT");
    if (events & EV_READ)
        strcat(name, "|EV_READ");
    if (events & EV_WRITE)
        strcat(name, "|EV_WRITE");
    if (events & EV_SIGNAL)
        strcat(name, "|EV_SIGNAL");
    if (events & EV_PERSIST)
        strcat(name, "|EV_PERSIST");

    if (name[0] == '\0')
        return "NONE";
    else
        return name + 1;
}

static void add_async_writeread_event(writeread_data *ev_struct,
        short ev_type,
        struct timeval *timeout) {
    event_set(&(ev_struct->server->event), ev_struct->server->fd, ev_type,
            network_mysqld_con_async_writeread, ev_struct);
    event_base_set(ev_struct->event_base, &(ev_struct->server->event));
    log_debug("%s.%d: adding event %s for SOCKET=%d\n",
            __FILE__, __LINE__,
            get_event_name(ev_type), ev_struct->server->fd);
    event_add(&(ev_struct->server->event), timeout);
}

static void create_async_writeread_event(network_mysqld *srv,
        network_socket *server_sock,
        short ev_type,
        struct timeval *timeout,
        network_mysqld_con *client) {
    writeread_data * temp_data = create_writeread_data(srv, server_sock, client);
    add_async_writeread_event(temp_data, ev_type, timeout);
}

/*
        Purpose: handle asynchronous server communication, used when communication 
        to multiple servers where a write is performed and maybe a read is 
        required before completing an operation.  Set flags to indicate READ 
        is required.  Flag will be set to indicate operation has completed.

        @param	user_data - will be a network_socket * object
 */
void network_mysqld_con_async_writeread(int event_fd, short events, void *user_data) {
    int ostate;
    writeread_data *data = (writeread_data*) user_data;
    network_socket *con = data->server;
    //network_mysqld *srv = data->srv;
    network_mysqld_con *client = data->client;

    if (con == NULL) {
        log_debug("%s.%d: invalid event_fd(%p) events(%d) ud(%p)", __FILE__, __LINE__, event_fd, events, user_data);
        return;
    }

    if (events == EV_READ) {
        int b = -1;
        int i;

        //if (ioctl(event_fd), FIONREAD, &b)) 
        if ((i = ioctl(con->fd, FIONREAD, &b))) {
            log_error("ioctl(%d, FIONREAD, ...)failed: %s", event_fd, strerror(errno));
            con->rw.state = NET_RW_STATE_ERROR;
        } else if (b != 0) {
            con->to_read = b;
        } else {
            log_error("%s:%d ioctl(%d) connection error(SOCKET=%d): %s", __FILE__, __LINE__, i, event_fd, strerror(errno));
            con->rw.state = NET_RW_STATE_ERROR;
        }
    }

    do {
        ostate = con->rw.state;

#if 1
        if (con->rw.state == NET_RW_STATE_WRITE)
            log_debug("%s.%d: state = %s(%d) event_fd(%p) events(%d) ud(%p)", __FILE__, __LINE__, sz_rw_state[con->rw.state], con->rw.state, event_fd, events, user_data);

#endif

        switch (con->rw.state) {
            case NET_RW_STATE_ERROR:
            case NET_RW_STATE_FINISHED:
            {
                if (events == EV_READ && client) {
                    client->num_pending_servers--;
                    log_debug("%s.%d: number of pending backend replies for client SOCKET=%d is %d\n",
                            __FILE__, __LINE__, client->client->fd,
                            client->num_pending_servers);
                    if (client->num_pending_servers == 0) {
                        // we have got all the servers replies
                        network_mysqld_con_handle(-1, 0, client);
                    }
                }
                // socket closed??? what happened, free the data pointer
                free_writeread_data(data);

                // return to make sure we don't use the data pointer
                return;
            }
            case NET_RW_STATE_WRITE:
            {
                switch (network_mysqld_write_len(con)) {
                    case RET_SUCCESS:
                    {
                        // if we wrote, then we wrote write_count, set to 0 then
                        con->rw.write_count = 0;

                        END_PERF(con, PF_SEND);

                        // check to determine if we need to perform a read now
                        if (con->rw.read_after_write) {
                            con->rw.state = NET_RW_STATE_READ;
                            events = EV_READ;
                            START_PERF(con, con->addr.str, PF_RECV);
                        } else
                            con->rw.state = NET_RW_STATE_FINISHED;
                        break;
                    }
                    case RET_WAIT_FOR_EVENT:
                        add_async_writeread_event(data, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        // store the error
                        con->rw.last_errno = errno;

                        // change the state
                        con->rw.state = NET_RW_STATE_ERROR;

                        log_debug("%s.%d: network_mysqld_write_len(NET_RW_STATE_WRITE) returned an error %s", __FILE__, __LINE__, strerror(errno));
                        break;
                }
                break;
            }
            case NET_RW_STATE_READ:
            {
                int is_finished = 0;
                int ret = 0;

                ret = network_mysqld_read(con, &is_finished);

                switch (ret) {
                    case RET_SUCCESS:
                    {
                        // decrement or set to 0?
                        con->rw.read_after_write = 0;

                        if (is_finished) {
                            con->rw.state = NET_RW_STATE_FINISHED;
                            END_PERF(con, PF_RECV | PF_PRINT);
                        } else {
                            add_async_writeread_event(data, EV_READ, NULL);
                        }
                        break;
                    }
                    case RET_WAIT_FOR_EVENT:
                        add_async_writeread_event(data, EV_READ, NULL);
                        return;
                    case RET_ERROR:
                        // store the error
                        con->rw.last_errno = errno;

                        // change the state
                        con->rw.state = NET_RW_STATE_ERROR;

                        log_error("%s.%d: SOCKET=%d network_mysqld_read(NET_RW_STATE_READ) returned an error: %s",
                                __FILE__, __LINE__, con->fd, strerror(errno));
                        break;
                }

                break;
            }
            default:
                break;
        }

        if (NET_RW_STATE_FINISHED == con->rw.state) {
            if (events == EV_READ && client) {
                client->num_pending_servers--;
                log_debug("%s.%d: SOCKET=%d: number of pending replies is %d.\n",
                        __FILE__, __LINE__, client->client->fd,
                        client->num_pending_servers);

                if (client->num_pending_servers == 0) {
                    // we have got all the servers replies
                    network_mysqld_con_handle(-1, 0, client);
                }
            }
            free_writeread_data(data);
            return;
        }

    } while (con && (con->rw.state != NET_RW_STATE_NONE));
}

// check if the connection is waiting for the client's reply
// we simply close the connection otherwise

static int waiting_for_client_reply(network_mysqld_con *con) {
    switch (con->state) {
        case CON_STATE_READ_AUTH:
        case CON_STATE_READ_AUTH_OLD_PASSWORD:
        case CON_STATE_READ_QUERY:
        case CON_STATE_READ_SINGLE_QUERY_RESULT:
            return 1;

        default:
            return 0;
    }
    return 0;
}

static std::string get_query_string(network_mysqld_con *con) {

    std::string sql;
    for (size_t i = 0; i < con->sql_tokens->len; i++) {
        sql_token *tok = (sql_token *) (con->sql_tokens->pdata[i]);
        if (!sql.empty())
            sql.append(" ");
        sql.append(tok->text->str);
    }

    return sql;
}

/**
 * handle the different states of the MySQL CLIENT ONLY protocol.  The
 * client and server are now detached in the event loop.  SpockProxy is in
 * it's own right a MySql database and handles client authentication.
 */
void network_mysqld_con_handle(int event_fd, short events, void *user_data) {
#define WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
	log_debug("%s.%d SOCKET=%d: wait for event=%s, state=%s.", \
            __FILE__, __LINE__, ev_struct->fd, get_event_name(ev_type), sz_state[con->state]);\
	event_set(&(ev_struct->event), ev_struct->fd, ev_type, network_mysqld_con_handle, user_data); \
	event_base_set(srv->event_base, &(ev_struct->event));\
	event_add(&(ev_struct->event), timeout);

    int ostate;
    network_mysqld_con *con = (network_mysqld_con *) user_data;
    network_mysqld *srv = con->srv;

    if (srv == NULL) {
        log_error("%s.%d: ERROR_FIX_ME event_fd(%p) events(%d) ud(%p) state(%s) srv = NULL",
                __FILE__, __LINE__, event_fd, events, sz_state[con->state], user_data);
        return;
    }

    if ((-1 != event_fd) && (con->client != NULL) && (event_fd != con->client->fd) && (EV_TIMEOUT == events)) {
        log_error("%s.%d: EV_TIMEOUT event_fd(%p) events(%d) ud(%p) unexpected event for server",
                __FILE__, __LINE__, event_fd, events, user_data);
        return;
    }

    if (events == EV_READ) {
        int b = -1;

        log_debug("%s.%d SOCKET=%d: got event EV_READ.",
                __FILE__, __LINE__, event_fd);

        if (ioctl(event_fd, FIONREAD, &b)) {
            log_error("ioctl(%d, FIONREAD, ...) failed: %s", event_fd, strerror(errno));

            con->state = CON_STATE_ERROR;
        } else if (b != 0 && waiting_for_client_reply(con)) {
            if (con->client && event_fd == con->client->fd) {
                con->client->to_read = b;
            } else if (con->server && event_fd == con->server->fd) {
                con->server->to_read = b;
            } else {
                log_debug("%s.%d: EV_READ event_fd(%p) events(%d) ud(%p) unexpected event for client/server",
                        __FILE__, __LINE__, event_fd, events, user_data);
                return;
            }
        } else {
            if (con->client && event_fd == con->client->fd) {
                /* the client closed the connection, let's keep the server side open */
                con->state = CON_STATE_CLOSE_CLIENT;
            } else {

                log_warning("%s.%d: EV_READ event_fd(%p) events(%d) unexpected event, con state=%s clientfd=%d serverfd=%d errno=%d, %s",
                        __FILE__, __LINE__, event_fd, events, sz_state[con->state],
                        con->client ? con->client->fd : 0, con->server ? con->server->fd : 0, errno, strerror(errno));
                con->state = CON_STATE_ERROR;
            }
        }
    } else if (EV_WRITE == events) {
        log_debug("%s.%d: EV_WRITE event_fd(%p) events(%d)",
                __FILE__, __LINE__, event_fd, events);
    } else if (events == EV_TIMEOUT) {
        log_debug("%s.%d: EV_TIMEOUT event_fd(%p) events(%d)",
                __FILE__, __LINE__, event_fd, events);

        if (con->state == CON_STATE_READ_QUERY && (con->client != NULL) &&
                con->client->fd == event_fd) {
            log_warning("client connection socket=%d has been idle for too long, closing ...\n", event_fd);
            con->state = CON_STATE_CLOSE_CLIENT;
        }
    }

    do {
        ostate = con->state;

        log_debug("%s.%d SOCKET=%d: state=%s, event_fd=%d, events=%s.",
                __FILE__, __LINE__, con->client ? con->client->fd : 0,
                sz_state[con->state], event_fd, get_event_name(events));

        switch (con->state) {
            case CON_STATE_ERROR:
            {
                /* we can't go on, close the connection */
                plugin_call_cleanup(srv, con);
                network_mysqld_con_free(con);
                con = NULL;
                return;
            }
            case CON_STATE_CLOSE_CLIENT:
            {
                /* the server connection is still fine, 
                 * let's keep it open for reuse */
                plugin_call_cleanup(srv, con);
                network_mysqld_con_free(con);
                con = NULL;

                // memory profiling
                if (0)
                    g_mem_profile();

                return;
            }
            case CON_STATE_INIT:
            {
                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        /**
                         * no luck, let's close the connection
                         */
                        log_error("%s.%d: plugin_call(CON_STATE_INIT) != RET_SUCCESS", __FILE__, __LINE__);
                        con->state = CON_STATE_ERROR;
                        break;
                }

                break;
            }
            case CON_STATE_SEND_HANDSHAKE:
            {
                /* PROXY -------> CLIENT */
                /* send the hand-shake to the client and wait for a response */

                // define a starting point for the connection
                START_PERF(con->client, con->client->addr.str, PF_CONNECT);

                switch (network_mysqld_write(srv, con->client)) {
                    case RET_SUCCESS:
                        break;
                    case RET_WAIT_FOR_EVENT:
                        WAIT_FOR_EVENT(con->client, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        log_debug("%s.%d: network_mysqld_write(CON_STATE_SEND_HANDSHAKE) returned an error", __FILE__, __LINE__);
                        break;
                }

                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_error("%s.%d: plugin_call(CON_STATE_SEND_HANDSHAKE) != RET_SUCCESS", __FILE__, __LINE__);
                        break;
                }

                con->state = CON_STATE_READ_AUTH;
                break;
            }
            case CON_STATE_READ_AUTH:
            {
                /* CLIENT -------> PROXY */
                /* read auth from client */
                network_socket *recv_sock;

                recv_sock = con->client;

                g_assert(events == 0 || event_fd == recv_sock->fd);

                switch (network_mysqld_read(recv_sock, NULL)) {
                    case RET_SUCCESS:
                        break;
                    case RET_WAIT_FOR_EVENT:
                        WAIT_FOR_EVENT(con->client, EV_READ, NULL);
                        return;
                    case RET_ERROR:
                        log_error("%s.%d: network_mysqld_read(CON_STATE_READ_AUTH) returned an error", __FILE__, __LINE__);
                        return;
                }

                con->state = CON_STATE_CREATE_AUTH_RESPONSE;
                break;
            }
            case CON_STATE_CREATE_AUTH_RESPONSE:
            {
                /* generate a authentication response */

                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_info("%s.%d: plugin_call(CON_STATE_CREATE_AUTH_RESPONSE) != RET_SUCCESS", __FILE__, __LINE__);
                        break;
                }

                con->state = CON_STATE_SEND_AUTH_RESULT;
                break;
            }
            case CON_STATE_SEND_AUTH_RESULT:
            {
                /* PROXY -------> CLIENT */
                /* send the handshake result to the client and wait for a response*/

                switch (network_mysqld_write(srv, con->client)) {
                    case RET_SUCCESS:
                        break;
                    case RET_WAIT_FOR_EVENT:
                        WAIT_FOR_EVENT(con->client, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        log_error("%s.%d: network_mysqld_write(CON_STATE_SEND_AUTH_RESULT) returned an error", __FILE__, __LINE__);
                        return;
                }

                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_error("%s.%d: ...", __FILE__, __LINE__);
                        break;
                }

                // define a starting point for the connection
                END_PERF(con->client, PF_CONNECT | PF_PRINT);
                if (0)
                    g_mem_profile();

                break;
            }
            case CON_STATE_READ_AUTH_OLD_PASSWORD:
                /* read auth from client */

                switch (network_mysqld_read(con->client, NULL)) {
                    case RET_SUCCESS:
                        break;
                    case RET_WAIT_FOR_EVENT:
                        WAIT_FOR_EVENT(con->client, EV_READ, NULL);
                        return;
                    case RET_ERROR:
                        log_error("%s.%d: network_mysqld_read(CON_STATE_READ_AUTH_OLD_PASSWORD) returned an error", __FILE__, __LINE__);
                        return;
                }

                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_error("%s.%d: plugin_call(CON_STATE_READ_AUTH_OLD_PASSWORD) != RET_SUCCESS", __FILE__, __LINE__);
                        break;
                }

                break;
            case CON_STATE_SEND_AUTH_OLD_PASSWORD:
                // not supported
                g_assert(0);

                /* send the auth-response to the server */
                switch (network_mysqld_write(srv, con->server)) {
                    case RET_SUCCESS:
                        break;
                    case RET_WAIT_FOR_EVENT:
                        WAIT_FOR_EVENT(con->server, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        /* might be a connection close, we should just close the connection and be happy */
                        log_error("%s.%d: network_mysqld_write(CON_STATE_SEND_AUTH_OLD_PASSWORD) returned an error", __FILE__, __LINE__);
                        return;
                }

                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_error("%s.%d: plugin_call(CON_STATE_SEND_AUTH_OLD_PASSWORD) != RET_SUCCESS", __FILE__, __LINE__);
                        break;
                }

                break;

            case CON_STATE_READ_QUERY:
            {
                network_socket *recv_sock;

                recv_sock = con->client;

                g_assert(events == 0 || event_fd == recv_sock->fd);

                /* start performance analsys on QUERY and RECV */
                START_PERF(con->client, con->client->addr.str, PF_QUERY);
                START_PERF(con->client, con->client->addr.str, PF_RECV);

                switch (network_mysqld_read(recv_sock, NULL)) {
                    case RET_SUCCESS:
                        END_PERF(con->client, PF_PRINT | PF_RECV);
                        break;
                    case RET_WAIT_FOR_EVENT:
                    {
                        struct timeval tv;
                        tv.tv_sec = get_config_max_conn_idle_time();
                        tv.tv_usec = 0;
                        WAIT_FOR_EVENT(con->client, EV_READ | EV_TIMEOUT, &tv);
                        return;
                    }
                    case RET_ERROR:
                        con->state = CON_STATE_ERROR;
                        log_warning("%s.%d: network_mysqld_read(CON_STATE_READ_QUERY) returned an error", __FILE__, __LINE__);
                        break;
                }

                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_error("%s.%d: plugin_call(CON_STATE_READ_QUERY) != RET_SUCCESS", __FILE__, __LINE__);
                        break;
                }
                break;
            }

            case CON_STATE_PROCESS_READ_QUERY:
            {
                /*
                        process the read query
                 */
                con->parseMaster = 0;
                network_socket *recv_sock;
                GString *packet;
                GList *chunk;

                recv_sock = con->client;

                if ((NULL == recv_sock->recv_queue->chunks) ||
                        (NULL == recv_sock->recv_queue->chunks->head)) {
                    log_warning("%s.%d: CON_STATE_PROCESS_READ_QUERY) recv_queue empty",
                            __FILE__, __LINE__);
                    con->state = CON_STATE_ERROR;
                    break;
                }

                //////////////////////////////////////////////////
                // fetch a token list but only for QUERYs

                chunk = recv_sock->recv_queue->chunks->head;
                if (chunk != NULL) // still have RET_ERROR failre to check
                {
                    packet = (GString *) (chunk->data);

                    char *pos;
                    if (pos = strstr(packet->str + NET_HEADER_SIZE, "|m")) {
                        con->parseMaster = 1;
                        int len = packet->len - strlen(pos);
                        g_string_erase(packet, len, 2);
                        packet->str[0] -= 2;
                        recv_sock->packet_len -= 2;
                    }
                    if ((COM_QUERY == packet->str[NET_HEADER_SIZE + 0]) ||
                            (COM_FIELD_LIST == packet->str[NET_HEADER_SIZE + 0]) ||
                            (COM_INIT_DB == packet->str[NET_HEADER_SIZE + 0])) {
                        // for test scripts, convert trailing ';\n' etc to spaces.
                        char *p = packet->str + packet->len - 1;
                        while (strchr("\n;", *p) && (p > packet->str)) {
                            *p = ' ';
                            p--;
                        }

                        // free the token list if it already exists
                        if (NULL != con->sql_tokens) {
                            sql_tokens_free(con->sql_tokens);
                            con->sql_tokens = NULL;
                        }

                        // create a new token array
                        con->sql_tokens = g_ptr_array_new();

                        //parse sql to get token list
                        sql_tokenizer(con->sql_tokens,
                                packet->str + (NET_HEADER_SIZE + 1),
                                packet->len - (NET_HEADER_SIZE + 1));
                    } else if (COM_QUIT == packet->str[NET_HEADER_SIZE + 0]) { // close the client, but don't send this to the server

                        con->state = CON_STATE_CLOSE_CLIENT;
                        break;
                    }

                    /* Due to existing calls from the client, we decided to
                            disable ignore USE DATABASE request.  Support it is NOT
                            a good idea and you can not fake it due to the table
                            structured retured by MySql.   If you do use it, you risk
                            that the client may change databases on you in the middle
                            and the lookup code will not function properly
                     */
                    /*
                    else if ( COM_INIT_DB == packet->str[NET_HEADER_SIZE + 0] )
                    {	// 	at the moment, let's not allow changing the database, 
                            //	send a canned response

                            recv_sock->packet_len = PACKET_LEN_UNSET;
                            g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

                            // accept but don't send to the server
                            network_mysqld_con_send_ok(recv_sock);

                            network_mysqld_con_send_error_full(
                                            con->client, 
                                            "use database not supported",
                                            26, 
                                            ER_NO_DB_ERROR, 
                                            get_sql_state( ER_NO_DB_ERROR ) );

                            // will write really fail?
                            switch (network_mysqld_write(srv, con->client)) 
                            {
                                    case RET_SUCCESS:
                                    {
                                            break;
                                    }
                                    default:
                                            break;
                            }
	
                            // continue reading queries
                            con->state = CON_STATE_READ_QUERY;
                            break;
                    }
                     */
                }
                con->state = CON_STATE_GET_SERVER_LIST;
                break;
            }
            case CON_STATE_GET_SERVER_LIST:
            {
                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        con->state = CON_STATE_GET_SERVER_CONNECTION_LIST;
                        break;
                    case RET_ERROR:
                    {
                        GString *packet;

                        network_mysqld_write(srv, con->client);
                        con->state = CON_STATE_READ_QUERY;
                        END_PERF(con->client, PF_QUERY);

                        while ((packet = (GString *) g_queue_pop_head(con->client->recv_queue->chunks))) {
                            g_string_free(packet, TRUE);
                        }
                        con->client->packet_len = PACKET_LEN_UNSET;
                        return;
                    }
                    default:
                        log_error("%s.%d: plugin_call(CON_STATE_GET_SERVER_LIST) failed",
                                __FILE__, __LINE__);
                        con->state = CON_STATE_ERROR;
                        break;
                }
                break;
            }
            case CON_STATE_GET_SERVER_CONNECTION_LIST:
            {
                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        con->state = CON_STATE_SEND_QUERY;
                        break;
                    case RET_WAIT_FOR_EVENT:
                    {
                        con->retrynum += 1;
                        if(con->retrynum>2) 
                        {
                            log_error("%s.%d: plugin_call(CON_STATE_GET_SERVER_CONNECTION_LIST) failed",
                                __FILE__, __LINE__);
                            con->state = CON_STATE_ERROR;
                            break;//dqm重试次数大于2退出 
                        }
                        // more connection in the pool is needed
                        network_connection_pool_create_conns(srv);

                        // need to add code to try this operation again after
                        // a server connects
                        struct timeval tv;
                        tv.tv_sec = 0;
                        tv.tv_usec = EVENT_WAIT_TIME;
                        WAIT_FOR_EVENT(con->client, EV_TIMEOUT, &tv);
                        return;
                    }
                    default:
                        log_error("%s.%d: plugin_call(CON_STATE_GET_SERVER_CONNECTION_LIST) failed",
                                __FILE__, __LINE__);
                        con->state = CON_STATE_ERROR;
                        break;
                }
                break;
            }
            case CON_STATE_SEND_QUERY:
            {
                /* send the query to the server(s) */

                MULTIPART_DATA *pmd;
                int i;
                connection_state future_state;
                int async_server_write = 0;
                GString *s = NULL;

                if (NULL == con->server) { // no default server?  CON_STATE_GER_SERVER_LIST failed or 
                    // something else went wrong
                    log_info("%s.%d: CON_STATE_SEND_QUERY is missing default server",
                            __FILE__, __LINE__);
                    con->state = CON_STATE_ERROR;
                    break;
                }

                if (NULL == con->server->send_queue->chunks) {
                    log_info("%s.%d: CON_STATE_SEND_QUERY is default server send_queue is empty",
                            __FILE__, __LINE__);
                    con->state = CON_STATE_ERROR;
                    break;
                }

                if (NULL != con->server->send_queue->chunks->head) {
                    /* only parse the packets once */
                    GList *chunk;

                    chunk = con->server->send_queue->chunks->head;
                    s = (GString *) (chunk->data);

                    // reset this??? should it have already been set???	
                    con->parse.command = (enum_server_command) (s->str[NET_HEADER_SIZE + 0]);

                    /* only parse once and don't care about the blocking read */
                    if (con->parse.command == COM_QUERY &&
                            con->parse.state.query == PARSE_COM_QUERY_LOAD_DATA) {
                        /* is this a LOAD DATA INFILE ... extra round ? */
                        /* this isn't a command packet,but a LOAD DATA INFILE data-packet */
                        if (s->str[0] == 0 && s->str[1] == 0 && s->str[2] == 0) {
                            con->parse.state.query = PARSE_COM_QUERY_LOAD_DATA_END_DATA;
                        }
                    } else if (con->is_overlong_packet) {
                        /* the last packet was a over-long packet
                         * this is the same command, just more data */
                        if (con->parse.len != PACKET_LEN_MAX) {
                            con->is_overlong_packet = 0;
                        }
                    } else {
                        con->parse.command = (enum_server_command) (s->str[4]);

                        if (con->parse.len == PACKET_LEN_MAX) {
                            con->is_overlong_packet = 1;
                        }

                        /* init the parser for the commands */
                        switch (con->parse.command) {
                            case COM_QUERY:
                            case COM_STMT_EXECUTE:
                                con->parse.state.query = PARSE_COM_QUERY_INIT;
                                break;
                            case COM_STMT_PREPARE:
                                con->parse.state.prepare.first_packet = 1;
                                break;
                            case COM_INIT_DB:
                                if (s->str[NET_HEADER_SIZE] == COM_INIT_DB &&
                                        (s->len > NET_HEADER_SIZE + 1)) {
                                    con->parse.state.init_db.db_name = g_string_new(NULL);
                                    g_string_truncate(con->parse.state.init_db.db_name, 0);
                                    g_string_append_len(con->parse.state.init_db.db_name,
                                            s->str + NET_HEADER_SIZE + 1,
                                            s->len - NET_HEADER_SIZE - 1);
                                } else {
                                    con->parse.state.init_db.db_name = NULL;
                                }

                                break;
                            default:
                                break;
                        }
                    }
                } else {
                    log_error("%s.%d:unexpected missing data pointer",
                            __FILE__, __LINE__);
                    g_assert(FALSE);
                }

                // some statements don't have a server response 
                if (con->is_overlong_packet) { // more data to read...
                    future_state = CON_STATE_READ_QUERY;
                } else {
                    switch (con->parse.command) {
                        case COM_STMT_SEND_LONG_DATA: /* not acked */
                        case COM_STMT_CLOSE:
                            future_state = CON_STATE_READ_QUERY;
                            break;
                        case COM_QUERY:
                            if (con->parse.state.query == PARSE_COM_QUERY_LOAD_DATA) {
                                future_state = CON_STATE_READ_QUERY;
                            } else {
                                future_state = CON_STATE_READ_QUERY_RESULT;
                            }
                            break;
                        default:
                            future_state = CON_STATE_READ_QUERY_RESULT;
                            break;
                    }
                }

                // is this deprecated?
                if (future_state == CON_STATE_READ_QUERY) { // this case... the client is NOT finished, write the data and
                    // read more data from the client, but DO NOT reset the database
                    // list
                    con->keep_srv_con = 1; // keep it for one go around
                }

                con->num_pending_servers = pmd_cnt(con);

                // now send all of the server's the packet
                for (i = 0; i < pmd_cnt(con); i++) {
                    pmd = pmd_select(con, i);

                    // set the parse command for each server
                    pmd->server->parse.command = con->parse.command;
                    pmd->server->parse.state.query = con->parse.state.query;
                    pmd->server->parse.state.prepare.first_packet = con->parse.state.prepare.first_packet;
                    pmd->server->parse.state.auth_result.state = con->parse.state.auth_result.state;

                    //reset the state
                    pmd->server->rw.state = NET_RW_STATE_NONE;

                    if ((NULL != s) && (COM_INIT_DB == con->parse.command)) {
                        if (s->str[NET_HEADER_SIZE] == COM_INIT_DB &&
                                (s->len > NET_HEADER_SIZE + 1)) {
                            pmd->server->parse.state.init_db.db_name = g_string_new(NULL);
                            g_string_truncate(pmd->server->parse.state.init_db.db_name, 0);
                            g_string_append_len(pmd->server->parse.state.init_db.db_name,
                                    s->str + NET_HEADER_SIZE + 1,
                                    s->len - NET_HEADER_SIZE - 1);
                        } else {
                            pmd->server->parse.state.init_db.db_name = NULL;
                        }
                    }

                    START_PERF(pmd->server, pmd->sql->str, PF_SEND);

                    if (pmd->server->send_queue->chunks->head != NULL) {
                        switch (network_mysqld_write(srv, pmd->server)) {
                            case RET_SUCCESS:
                            {
                                // normal read state
                                pmd->server->rw.state = NET_STATE_READ;
                                END_PERF(pmd->server, PF_SEND | PF_PRINT);

                                break;
                            }
                            case RET_WAIT_FOR_EVENT:
                            { // server not ready, write later...

                                // write should occur later
                                pmd->server->rw.state = NET_RW_STATE_WRITE;

                                if (future_state == CON_STATE_READ_QUERY_RESULT) { // we need to write packet and then start immediately reading after
                                    pmd->server->rw.read_after_write++;
                                }

                                // just write 1 packet(what happens if the server can't keep up
                                // and the client has appended more data, should we just get
                                // the queue count and increase it??
                                pmd->server->rw.write_count++;

                                // create the asynchronous event
                                {
                                    create_async_writeread_event(srv, pmd->server, EV_WRITE, NULL, con);
                                }

                                // increment the number of servers that are 
                                // in asynchronous mode
                                async_server_write++;

                                if ((future_state == CON_STATE_READ_QUERY_RESULT) &&
                                        (pmd_cnt(con) == 1)) {
                                    con->state = CON_STATE_READ_SINGLE_QUERY_RESULT;
                                    return;
                                } else {
                                    // start with the next server
                                    continue;
                                }
                            }
                            case RET_ERROR:
                            {
                                // a request to one of the servers failed
                                char msg[256];
                                int j;

                                // log it
                                sprintf(msg,
                                        "server %s write failed: %s",
                                        pmd->server->addr.str,
                                        strerror(errno));

                                log_error("%s:%s: %s", __FILE__, __LINE__, msg);

                                // what state do we change the request?, some 
                                // servers may already receive a response, do we 
                                // just go ahead and try to read from them?  if 
                                // we don't there will be event failure later
                                for (j = 0; j < i; j++) {
                                    pmd = pmd_select(con, j);
                                    network_mysqld_con_send_command(
                                            pmd->server,
                                            COM_STMT_RESET,
                                            "\x00\x00");
                                }

                                // no matter what this is an error, send one back 
                                // to the client
                                con->state = CON_STATE_ERROR;

                                // send an error back to the client
                                network_mysqld_con_send_error_full(
                                        con->client,
                                        msg,
                                        strlen(msg),
                                        ER_NO_DB_ERROR,
                                        get_sql_state(ER_NO_DB_ERROR));

                                if (network_mysqld_write_len(con->client) != RET_SUCCESS) {
                                    log_error("%s.%d: error in sending error packet to SOCKET=%d.\n",
                                            __FILE__, __LINE__, con->client->fd);
                                }
                                break;
                            }
                        }
                    }
                }

                if ((future_state == CON_STATE_READ_QUERY_RESULT) &&
                        (pmd_cnt(con) == 1)) {
                    con->state = CON_STATE_READ_SINGLE_QUERY_RESULT;
                } else
                    con->state = future_state;

                break;
            }
                /*
                        SpockProxy handles single server requests 
                 */
            case CON_STATE_READ_SINGLE_QUERY_RESULT:
            {
                if (con->server->rw.state == NET_RW_STATE_FINISHED)
                    con->is_finished = 1;
                else if (con->server->rw.state != NET_RW_STATE_ERROR) {
                    // use the default server to read from (should only be one)
                    switch (network_mysqld_read(con->server, &(con->is_finished))) {
                        case RET_SUCCESS:
                        {
                            break;
                        }
                        case RET_WAIT_FOR_EVENT:
                            WAIT_FOR_EVENT(con->server, EV_READ, NULL);
                            return;
                        case RET_ERROR:
                        {
                            con->state = CON_STATE_ERROR;
                            log_error("%s.%d: SOCKET=%d network_mysqld_read returned an error",
                                    __FILE__, __LINE__, con->server->fd);
                            break;
                        }
                    }

                    END_PERF(con->server, PF_RECV | PF_PRINT);
                }

                if (con->state == CON_STATE_ERROR) {
                    GString *packet;
                    while ((packet = (GString *) g_queue_pop_head(con->server->recv_queue->chunks))) {
                        network_queue_append_chunk(con->client->send_queue, packet);
                    }
                    con->server->packet_len = PACKET_LEN_UNSET;

                    break; // force the state to be executed
                }

                /*
                                MULTIPART_DATA *pmd = (MULTIPART_DATA*) con->servers->pdata[0];
                
                                GPtrArray* recv_queues = g_ptr_array_sized_new(pmd_cnt(con));
                                int iter;
                                int total_bytes = 0;
                                for (iter = 0; iter < pmd_cnt(con); iter++) {
                                    pmd = pmd_select(con, iter);

                                    // this is dangerous, we are adding pointers
                                    // to the recv_queues, but it is NOT the owner
                                    // of the pointers...
                                    g_ptr_array_add(recv_queues,
                                            pmd->server->recv_queue);
                                    total_bytes += pmd->server->bytes_recved;
                                }

                                resultset_merge(con->client->send_queue->chunks,
                                        recv_queues,
                                        con->sql_tokens);
                 */
                con->state = CON_STATE_SEND_SINGLE_QUERY_RESULT;
                break;
            }

            case CON_STATE_SEND_SINGLE_QUERY_RESULT:
            {
                GString *packet;
                MULTIPART_DATA *pmd = (MULTIPART_DATA*) con->servers->pdata[0];
                
                sql_token *token_0 = get_token(con->sql_tokens, 0);
                //dqm 处理插入返回自增ID
                if (token_0->token_id != TK_SQL_INSERT || pmd->insertid<1) {
                    // move the server recv queue to client send queue
                    while ((packet = (GString *) g_queue_pop_head(con->server->recv_queue->chunks))) {
                        network_queue_append_chunk(con->client->send_queue, packet);
                    }
                } else {
                    packet = (GString *) g_queue_pop_head(con->server->recv_queue->chunks);
                    guint64 affected_rows = 0;
                    int warnings = 0;
                    GString s;
                    s.str = packet->str + NET_HEADER_SIZE;
                    s.len = packet->len - NET_HEADER_SIZE;
                    network_mysqld_proto_decode_ok_packet(&s, &affected_rows, NULL, NULL, &warnings, NULL);
                    GString *packet2 = g_string_sized_new(4);
                    packet2->len = 4;
                    packet2->str[3] = 1;
                    //not sure about wether those items are useful, so fill in some dummy value
                    int insert_id = 5;
                    int server_status = 0x0002;
                    network_mysqld_proto_append_int8(packet2, 0); /* no fields */
                    network_mysqld_proto_append_lenenc_int(packet2, affected_rows);
                    network_mysqld_proto_append_lenenc_int(packet2, pmd->insertid);
                    network_mysqld_proto_append_int16(packet2, server_status); /* autocommit */
                    network_mysqld_proto_append_int16(packet2, warnings); /* no warnings */
                    network_mysqld_proto_set_header_len((unsigned char*) packet2->str, packet2->len - NET_HEADER_SIZE);
                    network_queue_append_chunk(con->client->send_queue, packet2);
                }
                con->server->packet_len = PACKET_LEN_UNSET;
                START_PERF(con->client, con->client->addr.str, PF_SEND);
                switch (network_mysqld_write(srv, con->client)) {
                    case RET_SUCCESS:
                        END_PERF(con->client, PF_PRINT | PF_SEND);
                        break;
                    case RET_WAIT_FOR_EVENT:
                        END_PERF(con->client, PF_SEND);
                        WAIT_FOR_EVENT(con->client, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        log_error("%s.%d: network_mysqld_write(CON_STATE_SEND_QUERY_RESULT) returned an error", __FILE__, __LINE__);

                        while ((packet = (GString *) g_queue_pop_head(con->server->recv_queue->chunks)))
                            g_string_free(packet, TRUE);
                        con->server->packet_len = PACKET_LEN_UNSET;

                        con->state = CON_STATE_ERROR;
                        break;
                }

                if (con->state == CON_STATE_ERROR)
                    break; // force the state to be executed


                if (pmd->server->bytes_recved > BIGQUERY) {
                    log_warning("BIG QUERY, %d bytes recved, SQL=[%s]\n",
                            pmd->server->bytes_recved,
                            get_query_string(con).c_str());
                }
                pmd->server->bytes_recved = 0;

                if (con->is_finished == 1) {
                    proxy_cache_server_connections(con->srv, con);
                    END_PERF(con->client, PF_QUERY | PF_PRINT);
                    con->state = CON_STATE_READ_QUERY;
                } else {
                    END_PERF(con->client, PF_QUERY | PF_PRINT);
                    con->state = CON_STATE_READ_SINGLE_QUERY_RESULT;
                }
                break;
            }

                /*
                        CON_STATE_READ_QUERY_RESULT handles MULTIPLE server requests.
                        Due to merging, we must have all of the result sets first.
                 */
            case CON_STATE_READ_QUERY_RESULT:
            {
                MULTIPART_DATA *pmd;
                int i;
                int srv_response_count = 0;

                // enumerate the list of servers, reading from each if required
                for (i = 0; i < pmd_cnt(con); i++) {
                    int is_finished = 0;

                    pmd = pmd_select(con, i);

                    if ((pmd->server->rw.state == NET_RW_STATE_FINISHED) ||
                            (pmd->server->rw.state == NET_RW_STATE_READ))
                        continue; // this server has finished or is still reading

                    if (pmd->server->rw.state == NET_RW_STATE_WRITE)
                        continue;

                    if (pmd->server->rw.state == NET_RW_STATE_ERROR) {
                        int j;
                        // do we need to remove this connection from the pool?
                        for (j = 0; j < i; j++) {
                            pmd = pmd_select(con, j);
                            network_mysqld_con_send_command(
                                    pmd->server,
                                    COM_STMT_RESET,
                                    "\x00\x00");
                        }

                        // should we send an error? ok? what?
                        network_mysqld_con_send_error(con->client, C("server error"));

                        switch (network_mysqld_write_len(con->client)) {
                            case RET_SUCCESS:
                                break;
                            default:
                                log_error("%s.%d: error in sending error packet to SOCKET=%d.\n",
                                        __FILE__, __LINE__, con->client->fd);
                                break;
                        }

                        // start over and read query	
                        con->state = CON_STATE_READ_QUERY;
                        return; // communication failure
                    }
                    //else if ( pmd->server->rw.state == NET_RW_STATE_NONE)

                    START_PERF(pmd->server, pmd->sql->str, PF_RECV);

                    switch (network_mysqld_read(pmd->server, &is_finished)) {
                        case RET_SUCCESS:
                        {
                            // decrement or set to 0?
                            pmd->server->rw.read_after_write = 0;

                            if (is_finished == 1) {
                                con->num_pending_servers--;
                                log_debug("%s.%d: number of pending backend replies for client SOCKET=%d is %d\n",
                                        __FILE__, __LINE__, con->client ? con->client->fd : 0,
                                        con->num_pending_servers);

                                pmd->server->rw.state = NET_RW_STATE_FINISHED;
                                END_PERF(pmd->server, PF_RECV | PF_PRINT);
                            } else { //keep reading
                                pmd->server->rw.state = NET_RW_STATE_READ;
                                create_async_writeread_event(srv, pmd->server, EV_READ, NULL, con);
                            }

                            break;
                        }
                        case RET_WAIT_FOR_EVENT:
                            pmd->server->rw.state = NET_RW_STATE_READ;
                            create_async_writeread_event(srv, pmd->server, EV_READ, NULL, con);
                            break;
                        case RET_ERROR:
                        {
                            con->state = CON_STATE_ERROR;
                            log_error("%s.%d: SOCKET=%d network_mysqld_read(NET_RW_STATE_READ) returned an error",
                                    __FILE__, __LINE__, pmd->server->fd);
                            return;
                        }
                    }
                }

                // enumerate the list of servers, check to see which ones 
                // have received data
                for (i = 0; i < pmd_cnt(con); i++) {
                    pmd = pmd_select(con, i);

                    if (pmd->server->rw.state != NET_RW_STATE_FINISHED) { // found one that has not received a response

                        if (pmd->server->rw.state == NET_RW_STATE_ERROR) { // an error occurres, send back an error to the client,
                            // and disconnect related backend server connections.
                            //
                            while (con->servers && con->servers->len > 0) {
                                MULTIPART_DATA *pmd = (MULTIPART_DATA*) con->servers->pdata[0];
                                proxy_connection_pool_del_con(srv, pmd->server);
                                network_socket_free(pmd->server);

                                pmd->server = NULL;
                                g_ptr_array_remove(con->servers, pmd);
                                pmd_free(pmd);
                            }


                            network_mysqld_con_send_error(con->client, C("server error"));

                            switch (network_mysqld_write_len(con->client)) {
                                case RET_SUCCESS:
                                    break;
                                default:
                                    log_error("%s.%d: error in sending error packet to SOCKET=%d.\n",
                                            __FILE__, __LINE__, con->client->fd);
                                    break;
                            }

                            // start over and read query	
                            con->state = CON_STATE_READ_QUERY;
                            break;
                        }
                    } else {
                        // determine if there is a response from the server
                        //(g_queue_is_empty(pmd->server->recv_queue->chunks)== 0))
                        if ((pmd->server->recv_queue->chunks == NULL) ||
                                (pmd->server->recv_queue->chunks->tail == NULL))
                            log_debug("fd(%p) multi-server response, no data in queue", pmd->server->fd);

                        srv_response_count++;
                    }
                }

                if (con->state == CON_STATE_READ_QUERY) {
                    break;
                } else if (srv_response_count != pmd_cnt(con)) {
                    return;
                }

                /* perform the callback
                switch (plugin_call(srv, con, con->state)) 
                {
                        case RET_SUCCESS:
                                break;
                        default:
                                log_error("%s.%d: ...", __FILE__, __LINE__);
                                break;
                }
                 */

                if (con->parse.command == COM_INIT_DB) {
                    if (con->parse.state.init_db.db_name) {
                        g_string_free(con->parse.state.init_db.db_name, TRUE);
                        con->parse.state.init_db.db_name = NULL;
                    }
                }

                // is there data to send?
                if (srv_response_count != 0) {
                    guint8 single_response = 0;

                    if (srv_response_count > 1) {
                        // now we need to consolidate certain requests
                        switch (con->parse.command) {
                            case COM_STMT_EXECUTE:
                            case COM_QUERY:
                            {
                                START_PERF(con->client, (pmd_cnt(con) > 0) ? (pmd_select(con, 0)->sql->str) : con->client->addr.str, PF_MERGE);

                                GPtrArray* recv_queues = g_ptr_array_sized_new(pmd_cnt(con));
                                int iter;
                                int total_bytes = 0;
                                for (iter = 0; iter < pmd_cnt(con); iter++) {
                                    pmd = pmd_select(con, iter);

                                    // this is dangerous, we are adding pointers
                                    // to the recv_queues, but it is NOT the owner
                                    // of the pointers...
                                    g_ptr_array_add(recv_queues,
                                            pmd->server->recv_queue);
                                    total_bytes += pmd->server->bytes_recved;
                                }

                                if (total_bytes > BIGQUERY) {
                                    log_warning("BIG QUERY, %d bytes recved, SQL=[%s]\n",
                                            total_bytes, get_query_string(con).c_str());
                                }

                                resultset_merge(con->client->send_queue->chunks,
                                        recv_queues,
                                        con->sql_tokens);

                                // now clear the recieve queues
                                for (iter = 0; iter < pmd_cnt(con); iter++) {
                                    GString *packet;

                                    pmd = pmd_select(con, iter);

                                    while ((packet = (GString *) g_queue_pop_head(pmd->server->recv_queue->chunks)))
                                        g_string_free(packet, TRUE);
                                }

                                // no reasons to free the queues, they are only
                                // pointers to the pmd->server->recv_queue that were
                                // freed right before this call
                                g_ptr_array_free(recv_queues, TRUE);

                                END_PERF(con->client, PF_MERGE | PF_PRINT);

                                // now remove connections and add them back to the 
                                // cache to be used for the next call
                                proxy_cache_server_connections(con->srv, con);

                                break;
                            }
                            default:
                            { // all other requests, should we just send 1 response back?
                                single_response = 1;
                                break;
                            }
                        }
                    }

                    if ((srv_response_count == 1) || (single_response == 1)) { // single response, just copy it over to the client's send_queue
                        int iter;
                        GString *packet;
                        MULTIPART_DATA *pmd = pmd_select(con, 0);

                        while ((packet = (GString *) g_queue_pop_head(pmd->server->recv_queue->chunks))) {
                            network_queue_append_chunk(con->client->send_queue, packet);
                        }
                        pmd->server->packet_len = PACKET_LEN_UNSET;

                        // doesn't mean there isn't data in the other queues
                        for (iter = 1; iter < pmd_cnt(con); iter++) {
                            pmd = pmd_select(con, iter);

                            while ((packet = (GString *) g_queue_pop_head(pmd->server->recv_queue->chunks))) {
                                g_string_free(packet, TRUE);
                            }
                            pmd->server->packet_len = PACKET_LEN_UNSET;
                        }
                    } else { // delete everything in the recv_queue
                        int iter;
                        GString *packet;

                        for (iter = 0; iter < pmd_cnt(con); iter++) {
                            pmd = pmd_select(con, iter);

                            while ((packet = (GString *) g_queue_pop_head(pmd->server->recv_queue->chunks))) {
                                g_string_free(packet, TRUE);
                            }
                            pmd->server->packet_len = PACKET_LEN_UNSET;
                        }
                    }

                    START_PERF(con->client, (pmd_cnt(con) > 0) ? pmd_select(con, 0)->sql->str : con->client->addr.str, PF_SEND);
                    con->state = CON_STATE_SEND_QUERY_RESULT;
                } else {
                    con->state = CON_STATE_READ_QUERY;
                }

                break;
            }
            case CON_STATE_SEND_QUERY_RESULT:
            {
                /**
                 * send the query result-set to the client */

                // we have to write 10, since the loop won't come back around
                // because it checks if the state hasn't changed
                switch (network_mysqld_write_len(con->client)) {
                    case RET_SUCCESS:
                        END_PERF(con->client, PF_PRINT | PF_SEND);
                        break;
                    case RET_WAIT_FOR_EVENT:
                        END_PERF(con->client, PF_SEND);
                        WAIT_FOR_EVENT(con->client, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        log_error("%s.%d: network_mysqld_write(CON_STATE_SEND_QUERY_RESULT) returned an error", __FILE__, __LINE__);

                        con->state = CON_STATE_ERROR;
                        break;
                }

                if (con->client->send_queue->chunks != NULL &&
                        con->client->send_queue->chunks->tail != NULL) {
                    break; // not done... let this loop back around
                }

                /* if the write failed, don't call the plugin handlers */
                if (con->state != CON_STATE_SEND_QUERY_RESULT)
                    break;

                switch (plugin_call(srv, con, con->state)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_error("%s.%d: ...", __FILE__, __LINE__);
                        break;
                }

                break;
            }
            case CON_STATE_SEND_ERROR:
            {
                /**
                 * send error to the client
                 * and close the connections afterwards
                 *  */

                switch (network_mysqld_write(srv, con->client)) {
                    case RET_SUCCESS:
                        break;
                    case RET_WAIT_FOR_EVENT:
                        WAIT_FOR_EVENT(con->client, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        log_error("%s.%d: network_mysqld_write(CON_STATE_SEND_ERROR) returned an error", __FILE__, __LINE__);
                        con->state = CON_STATE_ERROR;
                        break;
                }

                //con->state = CON_STATE_ERROR;
                break;
            }

            default:
                log_warning("%s.%d: unsupported connection state %d.\n", con->state);
                break;
        }
        event_fd = -1;
        events = 0;
    } while (ostate != con->state);
}

/**
 * handle the different states of the MySQL asynchronous connection protocol
 * from the Proxy to the Databases
 */
void network_mysqld_async_con_handle(int event_fd, short events, void *user_data) {
    int ostate;
    server_connection_state * con = (server_connection_state *) user_data;
    network_mysqld * srv = con->srv;
    NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(func) = NULL;
    int ret;

#define ASYNC_WAIT_FOR_EVENT(ev_struct, ev_type, timeout) \
	log_debug("%s.%d SOCKET=%d: ASYNC_WAIT_FOR_EVENT %s.\n", __FILE__, __LINE__, ev_struct->fd, get_event_name(ev_type));\
	event_set(&(ev_struct->event), ev_struct->fd, ev_type, network_mysqld_async_con_handle, user_data); \
	event_base_set(srv->event_base, &(ev_struct->event));\
	event_add(&(ev_struct->event), timeout);

    if (events == EV_READ) {
        int b = -1;

        if (ioctl(con->server->fd, FIONREAD, &b)) {
            log_error("ioctl(%d, FIONREAD, ...) failed: %s",
                    event_fd, strerror(errno));
            con->state = CON_STATE_ASYNC_ERROR;
        } else if (b != 0) {
            con->server->to_read = b;
        } else {
            if (errno == 0 || errno == EWOULDBLOCK)
                return; //simply do nothing
            else {
                con->state = CON_STATE_ASYNC_ERROR;
                log_error("%s.%d: CON_STATE_ASYNC_ERROR EV_READ addr=%s errno=%d error:%s",
                        __FILE__, __LINE__, con->server->addr.str, errno, strerror(errno));
            }
            return;
        }
    }

    do {
        ostate = con->state;

        if (con->state != CON_STATE_ASYNC_INIT)
            log_debug("%s.%d SOCKET=%d: async_state=%s, events=%s.",
                __FILE__, __LINE__, con->server->fd, sz_async_state[con->state],
                get_event_name(events));

        switch (con->state) {
            case CON_STATE_ASYNC_NONE:
            { // this state indicates were done connecting to the database	

                // needed? con->server->packet_len = PACKET_LEN_UNSET;

                if (con->server->recv_queue->chunks != NULL) {
                    GList *chunk = con->server->recv_queue->chunks->head;
                    if (chunk != NULL) {
                        GString *packet = (GString *) (chunk->data);
                        g_queue_delete_link(con->server->recv_queue->chunks,
                                chunk);
                        g_string_free(packet, TRUE);
                    }
                }
                break;
            }
            case CON_STATE_ASYNC_ERROR:
            {
                log_error("%s.%d: CON_STATE_ASYNC_ERROR %s failed: %s",
                        __FILE__, __LINE__,
                        ((con->server != NULL) && (con->server->addr.str != NULL)) ? con->server->addr.str : "srv", strerror(errno));

                /* we can't go on, close the connection */
                network_mysqld_async_con_state_free(con);
                return;
            }
            case CON_STATE_ASYNC_INIT:
            { /* at this point we should determine if any work needs to be
					performed.  Most work is to manage the server connections
					for both the minimum and maximum number of pooled 
					connections */
                func = con->plugins.con_init;
                if ((ret = (*func)(srv, con)) != 0)
                    log_warning("%s.%d: CON_STATE_ASYNC_INIT returned an error = %d",
                        __FILE__, __LINE__, ret);
                return;
            }
            case CON_STATE_ASYNC_READ_HANDSHAKE:
            {
                g_assert(events == 0 || event_fd == con->server->fd);

                START_PERF(con->server, con->server->addr.str, PF_RECV);
                switch (network_mysqld_read(con->server, NULL)) {
                    case RET_SUCCESS:
                        END_PERF(con->server, PF_RECV);
                        break;
                    case RET_WAIT_FOR_EVENT:
                        /* call us again when you have a event */
                        ASYNC_WAIT_FOR_EVENT(con->server, EV_READ, NULL);
                        return;
                    case RET_ERROR:
                        log_warning("%s.%d: plugin_call(CON_STATE_ASYNC_READ_HANDSHAKE) returned an error", __FILE__, __LINE__);
                        con->state = CON_STATE_ASYNC_ERROR;
                        break;
                }

                if (con->state == CON_STATE_ASYNC_ERROR)
                    break;

                func = con->plugins.con_read_handshake;
                switch ((*func)(srv, con)) {
                    case RET_SUCCESS:
                        break;
                    case RET_ERROR:
                        /**
                         * we couldn't understand the pack from the server we have 
                                something in the queue and will send it to the client
                                and close the connection afterwards
                         */
                        con->state = CON_STATE_ASYNC_ERROR;
                        log_warning("%s.%d: CON_STATE_ASYNC_READ_HANDSHAKE con_read_handshake failed returned an error");
                        break;
                    default:
                        con->state = CON_STATE_ASYNC_ERROR;
                        log_warning("%s.%d: ...", __FILE__, __LINE__);
                        break;
                }

                con->state = CON_STATE_ASYNC_CREATE_AUTH;
                break;
            }
            case CON_STATE_ASYNC_CREATE_AUTH:
            {
                /* no need to send a handshake to the client, SpockProxy
                   logs into the database itself. */

                func = con->plugins.con_create_auth;
                switch ((*func)(srv, con)) {
                    case RET_SUCCESS:
                        break;
                    case RET_ERROR:
                    {
                        GList *chunk = con->server->send_queue->chunks->head;
                        if (chunk != NULL) {
                            con->server->packet_len = PACKET_LEN_UNSET;
                            g_string_free((GString *) (chunk->data), TRUE);
                            g_queue_delete_link(con->server->send_queue->chunks, chunk);
                        }

                        con->state = CON_STATE_ASYNC_ERROR;
                        log_warning("%s.%d: plugin_call(CON_STATE_ASYNC_SEND_AUTH) returned an error", __FILE__, __LINE__);
                        break;
                    }
                    default:
                        log_warning("%s.%d: unexpected return from plugins.con_create_auth.", __FILE__, __LINE__);
                        break;
                }

                if (con->server->recv_queue->chunks != NULL) {
                    GList *chunk = con->server->recv_queue->chunks->head;
                    if (chunk != NULL) {
                        GString *packet = (GString *) (chunk->data);
                        g_queue_delete_link(con->server->recv_queue->chunks,
                                chunk);
                        g_string_free(packet, TRUE);
                    }
                }
                con->state = CON_STATE_ASYNC_SEND_AUTH;
                break;
            }

            case CON_STATE_ASYNC_SEND_AUTH:
            { /* PROXY -------> SERVER */

                START_PERF(con->server, con->server->addr.str, PF_SEND);

                /* send the auth-response to the server */
                switch (network_mysqld_write(srv, con->server)) {
                    case RET_SUCCESS:
                        con->state = CON_STATE_ASYNC_READ_AUTH_RESULT;
                        END_PERF(con->server, PF_SEND);
                        break;
                    case RET_WAIT_FOR_EVENT:
                        con->state = CON_STATE_ASYNC_READ_AUTH_RESULT;
                        ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        con->state = CON_STATE_ASYNC_ERROR;
                        /* might be a connection close, we should just close 
                                the connection and be happy */
                        log_warning("%s.%d: network_mysqld_write(CON_STATE_ASYNC_SEND_AUTH) returned an error", __FILE__, __LINE__);
                        return;
                }

                break;
            }
            case CON_STATE_ASYNC_READ_AUTH_RESULT:
            { /* SERVER -------> PROXY read the auth result from the server */

                GList *chunk;
                GString *packet;

                g_assert(events == 0 || event_fd == con->server->fd);

                START_PERF(con->server, con->server->addr.str, PF_RECV);
                switch (network_mysqld_read(con->server, NULL)) {
                    case RET_SUCCESS:
                        END_PERF(con->server, PF_RECV);
                        break;
                    case RET_WAIT_FOR_EVENT:
                        ASYNC_WAIT_FOR_EVENT(con->server, EV_READ, NULL);
                        return;
                    case RET_ERROR:
                        con->state = CON_STATE_ASYNC_ERROR;
                        log_error("%s.%d: network_mysqld_read(CON_STATE_ASYNC_READ_AUTH_RESULT) returned an error", __FILE__, __LINE__);
                        break;
                }

                if (con->state == CON_STATE_ASYNC_ERROR)
                    break;

                /**
                 * depending on the result-set we have different exit-points
                 * - OK  -> READ_QUERY
                 * - EOF -> (read old password hash) 
                 * - ERR -> ERROR
                 */
                chunk = con->server->recv_queue->chunks->head;
                packet = (GString *) (chunk->data);
                g_assert(packet);
                g_assert(packet->len > NET_HEADER_SIZE);
                //con->parse.state.auth_result.state = packet->str[NET_HEADER_SIZE];

                func = con->plugins.con_read_auth_result;
                switch ((*func)(srv, con)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_warning("%s.%d: plugin_call(CON_STATE_ASYNC_READ_AUTH_RESULT) != RET_SUCCESS", __FILE__, __LINE__);

                        con->state = CON_STATE_ASYNC_ERROR;
                        break;
                }

                if (con->state == CON_STATE_ASYNC_ERROR)
                    break;

                switch (packet->str[NET_HEADER_SIZE]) {
                    case MYSQLD_PACKET_OK:
                    {
                        // now add to the backend pool associated to 
                        // this configuration
                        con->state = CON_STATE_ASYNC_NONE;
                        break;
                    }
                    case MYSQLD_PACKET_ERR:
                        log_warning("%s.%d: error in response for SEND_ASYNC_AUTH_RESULT: %02x",
                                __FILE__, __LINE__,
                                packet->str[NET_HEADER_SIZE]);
                        con->state = CON_STATE_ASYNC_ERROR;
                        break;
                    case MYSQLD_PACKET_EOF:
                        /* the MySQL 4.0 hash in a MySQL 4.1+ connection */
                        con->state = CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD;
                        break;
                    default:
                        log_error("%s.%d:unexpected state in ASYNC_READ_AUTH_RESULT:%02x",
                                __FILE__, __LINE__,
                                packet->str[NET_HEADER_SIZE]);
                        con->state = CON_STATE_ASYNC_ERROR;
                        break;
                }

                con->server->packet_len = PACKET_LEN_UNSET;
                g_queue_delete_link(con->server->recv_queue->chunks, chunk);
                g_string_free(packet, TRUE);

                if (con->state == CON_STATE_ASYNC_ERROR) {
                    break;
                }

                // if there is a default db send the request to select it
                if (NULL != con->server->default_db) {
                    network_mysqld_con_send_select_db(con->server,
                            con->server->default_db->str);

                    START_PERF(con->server, con->server->addr.str, PF_SEND);
                    switch (network_mysqld_write(srv, con->server)) {
                        case RET_SUCCESS:
                            END_PERF(con->server, PF_SEND);
                            con->state = CON_STATE_ASYNC_READ_SELECT_DB;
                            break;
                        case RET_WAIT_FOR_EVENT:
                            con->state = CON_STATE_ASYNC_READ_SELECT_DB;
                            ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL);
                            return;
                        case RET_ERROR:
                        {
                            con->state = CON_STATE_ASYNC_ERROR;
                            /* might be a connection close, we should just close the connection and be happy */
                            log_warning("%s.%d: network_mysqld_write(CON_STATE_ASYNC_READ_AUTH_RESULT) returned an error", __FILE__, __LINE__);
                            break;
                        }
                    }
                } else if (con->state == CON_STATE_ASYNC_NONE) {
                    // define an ending point for the connection
                    END_PERF(con->server, PF_CONNECT | PF_PRINT);
                    proxy_connection_pool_add(con);
                    return;
                }

                break;
            }
            case CON_STATE_ASYNC_READ_SELECT_DB:
            { // really just read the select db result and clear the
                // receive queue

                START_PERF(con->server, con->server->addr.str, PF_RECV);
                switch (network_mysqld_read(con->server, NULL)) {
                    case RET_SUCCESS:
                    {
                        GList *chunk;
                        con->state = CON_STATE_ASYNC_NONE;

                        // empty the read buffer
                        g_assert(con->server != NULL);
                        con->server->packet_len = PACKET_LEN_UNSET;
                        g_assert(con->server->recv_queue->chunks != NULL);

                        con->server->packet_len = PACKET_LEN_UNSET;
                        chunk = con->server->recv_queue->chunks->head;

                        GString *pkt = (GString *) (chunk->data);
                        if (pkt->str[NET_HEADER_SIZE] == MYSQLD_PACKET_ERR) {
                            log_warning("%s.%d: error in selecting default database: %s\n",
                                    __FILE__, __LINE__,
                                    con->server->mysqld_version > 40100 ? pkt->str + 13 : "");
                        }

                        g_string_free(pkt, TRUE);
                        g_queue_delete_link(con->server->recv_queue->chunks, chunk);

                        END_PERF(con->server, PF_RECV);
                        END_PERF(con->server, PF_CONNECT | PF_PRINT);
                        proxy_connection_pool_add(con);
                        //	con->state = CON_STATE_ASYNC_NONE;
                        return;
                    }
                    case RET_WAIT_FOR_EVENT:
                        ASYNC_WAIT_FOR_EVENT(con->server, EV_READ, NULL);
                        return;
                    case RET_ERROR:
                        // remove it? error???
                        con->state = CON_STATE_ASYNC_ERROR;

                        con->server->packet_len = PACKET_LEN_UNSET;
                        GList *chunk = con->server->recv_queue->chunks->head;
                        g_string_free((GString *) (chunk->data), TRUE);
                        g_queue_delete_link(con->server->recv_queue->chunks, chunk);
                        log_error("%s.%d: SOCKET=%d network_mysqld_read(CON_STATE_ASYNC_READ_AUTH_RESULT) returned an error",
                                __FILE__, __LINE__, con->server->fd);
                        break;
                }
                con->state = CON_STATE_ASYNC_NONE;
                break;
            }
            case CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD:
            {
                break;
            }
            case CON_STATE_ASYNC_SEND_AUTH_OLD_PASSWORDS:
            {
                /* send the auth-response to the server */
                switch (network_mysqld_write(srv, con->server)) {
                    case RET_SUCCESS:
                        break;
                    case RET_WAIT_FOR_EVENT:
                        ASYNC_WAIT_FOR_EVENT(con->server, EV_WRITE, NULL);
                        return;
                    case RET_ERROR:
                        con->state = CON_STATE_ASYNC_ERROR;
                        /* might be a connection close, we should just close the connection and be happy */
                        log_warning("%s.%d: network_mysqld_write(CON_STATE_SEND_AUTH_OLD_PASSWORD) returned an error", __FILE__, __LINE__);
                        return;
                }

                func = con->plugins.con_send_auth_old_password;
                switch ((*func)(srv, con)) {
                    case RET_SUCCESS:
                        break;
                    default:
                        log_error("%s.%d: plugin_call(CON_STATE_SEND_AUTH_OLD_PASSWORD) != RET_SUCCESS", __FILE__, __LINE__);
                        break;
                }

                break;
            }

        }
        event_fd = -1;
        events = 0;
    } while (ostate != con->state);

    return;
}

/**
 * we will be called by the event handler 
 *
 *
 */
void network_mysqld_con_accept(int event_fd, short events, void *user_data) {
    network_mysqld_con *con = (network_mysqld_con *) user_data;
    network_mysqld_con *client_con;
    socklen_t addr_len;
    struct sockaddr_in ipv4;
    int fd;

    g_assert(events == EV_READ);
    g_assert(con->server);

    addr_len = sizeof (struct sockaddr_in);

    if (-1 == (fd = accept(event_fd, (struct sockaddr *) &ipv4, &addr_len))) {
        return;
    }
#ifdef _WIN32
    ioctlvar = 1;
    ioctlsocket(fd, FIONBIO, &ioctlvar);
#else
    fcntl(fd, F_SETFL, O_NONBLOCK | O_RDWR);
#endif

    /* looks like we open a client connection */
    client_con = network_mysqld_con_init(con->srv);
    client_con->client = network_socket_init();
    client_con->client->addr.addr.ipv4 = ipv4;
    client_con->client->addr.len = addr_len;
    client_con->client->fd = fd;

    /* resolve the peer-addr if necessary */
    if (!client_con->client->addr.str) {
        switch (client_con->client->addr.addr.common.sa_family) {
            case AF_INET:
                client_con->client->addr.str = g_strdup_printf("%s:%d",
                        inet_ntoa(client_con->client->addr.addr.ipv4.sin_addr),
                        client_con->client->addr.addr.ipv4.sin_port);
                break;
            default:
                log_info("%s.%d: can't convert addr-type %d into a string",
                        __FILE__, __LINE__,
                        client_con->client->addr.addr.common.sa_family);
                break;
        }
    }
    /*dqm
        log_info("%s.%d: SOCKET=%d: new client, remote address=%s.\n",
                __FILE__, __LINE__, fd,
                client_con->client->addr.str ? client_con->client->addr.str : "");
     */
    /* copy the config */
    client_con->config = con->config;
    client_con->config.network_type = con->config.network_type;

    switch (con->config.network_type) {
        case NETWORK_TYPE_SERVER:
            network_mysqld_server_connection_init(client_con);
            break;
        case NETWORK_TYPE_PROXY:
            network_mysqld_proxy_connection_init(client_con);
            break;
        default:
            log_error("%s.%d", __FILE__, __LINE__);
            break;
    }

    network_mysqld_con_handle(-1, 0, client_con);
}

void handle_timeout() {
    if (!agent_shutdown) return;

    /* we have to shutdown, disable all events to leave the dispatch */
}

void *network_mysqld_thread(void *_srv) {
    network_mysqld *srv = (network_mysqld *) _srv;
    network_mysqld_con *proxy_con = NULL, *admin_con = NULL;

#ifdef _WIN32
    WORD wVersionRequested;
    WSADATA wsaData;
    int err;

    wVersionRequested = MAKEWORD(2, 2);

    err = WSAStartup(wVersionRequested, &wsaData);
    if (err != 0) {
        /* Tell the user that we could not find a usable */
        /* WinSock DLL.                                  */
        return NULL;
    }
#endif

    /* setup the different handlers */

    if (srv->config.admin.address) {
        network_mysqld_con *con = NULL;

        con = network_mysqld_con_init(srv);
        con->config = srv->config;
        con->config.network_type = NETWORK_TYPE_SERVER;

        con->server = network_socket_init();

        if (0 != network_mysqld_server_init(con)) {
            log_error("%s.%d: network_mysqld_server_init() failed", __FILE__, __LINE__);

            return NULL;
        }

        /* keep the listen socket alive */
        event_set(&(con->server->event), con->server->fd, EV_READ | EV_PERSIST, network_mysqld_con_accept, con);
        event_base_set(srv->event_base, &(con->server->event));
        log_debug("%s.%d: adding event EV_READ|EV_PERSIST for SOCKET=%d\n", __FILE__, __LINE__, con->server->fd);
        event_add(&(con->server->event), NULL);

        admin_con = con;
    }

    if (srv->config.proxy.address) {
        network_mysqld_con *con = NULL;

        con = network_mysqld_con_init(srv);
        con->config = srv->config;
        con->config.network_type = NETWORK_TYPE_PROXY;

        con->server = network_socket_init();

        if (0 != network_mysqld_proxy_init(con)) {
            log_error("%s.%d: network_mysqld_server_init() failed", __FILE__, __LINE__);
            return NULL;
        }

        /* keep the listen socket alive */
        event_set(&(con->server->event), con->server->fd, EV_READ | EV_PERSIST, network_mysqld_con_accept, con);
        event_base_set(srv->event_base, &(con->server->event));
        log_debug("%s.%d: adding event EV_READ|EV_PERSIST for SOCKET=%d\n", __FILE__, __LINE__, con->server->fd);
        event_add(&(con->server->event), NULL);

        proxy_con = con;
    }

    network_connection_pool_create_conns(srv);

    while (!agent_shutdown) {
        struct timeval timeout;
        int r;

        timeout.tv_sec = 0;
        timeout.tv_usec = 100000;

        g_assert(event_base_loopexit(srv->event_base, &timeout) == 0);

        r = event_base_dispatch(srv->event_base);

        if (r == -1) {
            if (errno != EINTR)
                break;
        }
    }

    /**
     * cleanup
     *
     */
    if (proxy_con) {
        /**
         * we still might have connections pointing to the close scope */
        event_del(&(proxy_con->server->event));
        network_mysqld_con_free(proxy_con);
    }

    if (admin_con) {
        event_del(&(admin_con->server->event));
        network_mysqld_con_free(admin_con);
    }

    return NULL;
}

int network_mysqld_con_send_resultset(network_socket *con, GPtrArray *fields, GPtrArray *rows) {
    GString *s;
    gsize i, j;

    g_assert(fields->len > 0 && fields->len < 251);

    s = g_string_new(NULL);

    /* - len = 99
     *  \1\0\0\1 
     *    \1 - one field
     *  \'\0\0\2 
     *    \3def 
     *    \0 
     *    \0 
     *    \0 
     *    \21@@version_comment 
     *    \0            - org-name
     *    \f            - filler
     *    \10\0         - charset
     *    \34\0\0\0     - length
     *    \375          - type 
     *    \1\0          - flags
     *    \37           - decimals
     *    \0\0          - filler 
     *  \5\0\0\3 
     *    \376\0\0\2\0
     *  \35\0\0\4
     *    \34MySQL Community Server (GPL)
     *  \5\0\0\5
     *    \376\0\0\2\0
     */

    g_string_append_c(s, fields->len); /* the field-count */
    network_queue_append(con->send_queue, s->str, s->len, con->packet_id++);

    for (i = 0; i < fields->len; i++) {
        MYSQL_FIELD *field = (MYSQL_FIELD *) (fields->pdata[i]);

        g_string_truncate(s, 0);

        network_mysqld_proto_append_lenenc_string(s, field->catalog ? field->catalog : "def"); /* catalog */
        network_mysqld_proto_append_lenenc_string(s, field->db ? field->db : ""); /* database */
        network_mysqld_proto_append_lenenc_string(s, field->table ? field->table : ""); /* table */
        network_mysqld_proto_append_lenenc_string(s, field->org_table ? field->org_table : ""); /* org_table */
        network_mysqld_proto_append_lenenc_string(s, field->name ? field->name : ""); /* name */
        network_mysqld_proto_append_lenenc_string(s, field->org_name ? field->org_name : ""); /* org_name */

        g_string_append_c(s, '\x0c'); /* length of the following block, 12 byte */
        g_string_append_c(s, DEFAULT_CHARSET); /* charset, use utf8 as default */
        g_string_append_c(s, '\0');
        g_string_append_c(s, (field->length >> 0) & 0xff); /* len */
        g_string_append_c(s, (field->length >> 8) & 0xff); /* len */
        g_string_append_c(s, (field->length >> 16) & 0xff); /* len */
        g_string_append_c(s, (field->length >> 24) & 0xff); /* len */
        g_string_append_c(s, field->type); /* type */
        g_string_append_c(s, field->flags & 0xff); /* flags */
        g_string_append_c(s, (field->flags >> 8) & 0xff); /* flags */
        g_string_append_c(s, 0); /* decimals */
        g_string_append_len(s, "\x00\x00", 2); /* filler */
#if 0
        /* this is in the docs, but not on the network */
        network_mysqld_proto_append_lenenc_string(s, field->def); /* default-value */
#endif
        network_queue_append(con->send_queue, s->str, s->len, con->packet_id++);
    }

    g_string_truncate(s, 0);

    /* EOF */
    g_string_append_len(s, "\xfe", 1); /* EOF */
    g_string_append_len(s, "\x00\x00", 2); /* warning count */
    g_string_append_len(s, "\x02\x00", 2); /* flags */

    network_queue_append(con->send_queue, s->str, s->len, con->packet_id++);

    for (i = 0; i < rows->len; i++) {
        GPtrArray *row = (GPtrArray *) (rows->pdata[i]);

        g_string_truncate(s, 0);

        for (j = 0; j < row->len; j++) {
            network_mysqld_proto_append_lenenc_string(s, (const char *) (row->pdata[j]));
        }
        network_queue_append(con->send_queue, s->str, s->len, con->packet_id++);
    }

    g_string_truncate(s, 0);

    /* EOF */
    g_string_append_len(s, "\xfe", 1); /* EOF */
    g_string_append_len(s, "\x00\x00", 2); /* warning count */
    g_string_append_len(s, "\x02\x00", 2); /* flags */

    network_queue_append(con->send_queue, s->str, s->len, con->packet_id++);

    g_string_free(s, TRUE);

    return 0;
}

