#ifndef _NETWORK_MYSQLD_H_
#define _NETWORK_MYSQLD_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TIME_H
/**
 * event.h needs struct timeval and doesn't include sys/time.h itself
 */
#include <sys/time.h>
#endif

#include <sys/types.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <windows.h>
#include <winsock2.h>
#endif

#include <mysql.h>

#include <glib.h>

#include <event.h>

#include "network-socket.h"
#include "network-conn-pool.h"
#include "sys-pedantic.h"

/**
 * stolen from sql/log_event.h
 *
 * (MySQL 5.1.12)
 */
enum Log_event_type {
    /*
      Every time you update this enum (when you add a type), you have to
      fix Format_description_log_event::Format_description_log_event().
     */
    UNKNOWN_EVENT = 0,
    START_EVENT_V3 = 1,
    QUERY_EVENT = 2,
    STOP_EVENT = 3,
    ROTATE_EVENT = 4,
    INTVAR_EVENT = 5,
    LOAD_EVENT = 6,
    SLAVE_EVENT = 7,
    CREATE_FILE_EVENT = 8,
    APPEND_BLOCK_EVENT = 9,
    EXEC_LOAD_EVENT = 10,
    DELETE_FILE_EVENT = 11,
    /*
      NEW_LOAD_EVENT is like LOAD_EVENT except that it has a longer
      sql_ex, allowing multibyte TERMINATED BY etc; both types share the
      same class (Load_log_event)
     */
    NEW_LOAD_EVENT = 12,
    RAND_EVENT = 13,
    USER_VAR_EVENT = 14,
    FORMAT_DESCRIPTION_EVENT = 15,
    XID_EVENT = 16,
    BEGIN_LOAD_QUERY_EVENT = 17,
    EXECUTE_LOAD_QUERY_EVENT = 18,
    TABLE_MAP_EVENT = 19,
    WRITE_ROWS_EVENT = 20,
    UPDATE_ROWS_EVENT = 21,
    DELETE_ROWS_EVENT = 22,

    /*
      Add new events here - right above this comment!
      Existing events (except ENUM_END_EVENT) should never change their numbers
     */

    ENUM_END_EVENT /* end marker */
};

typedef enum {
    RET_SUCCESS,
    RET_WAIT_FOR_EVENT,
    RET_ERROR
} retval_t;

/**
 * configuration of the sub-modules
 * 
 * TODO: move sub-structs into the plugins 
 */

#define DEFAULT_FLAGS	CLIENT_LONG_PASSWORD | CLIENT_CONNECT_WITH_DB | CLIENT_LONG_FLAG | CLIENT_LOCAL_FILES | CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_MULTI_STATEMENTS | CLIENT_MULTI_RESULTS
#define DEFAULT_CHARSET   '\x21'     //default charset is utf

typedef enum {
    READ_ONLY,
    READ_WRITE,
    DEF_CONN
} net_connection_type;

typedef struct tag_backend_config {
    net_connection_type connection_type;

    GString *address; /** IP/Hostname address */

    GString *default_username; /* default username */
    GString *default_password; /* default password */
    GString *default_db; /* default database */

    int max_conn_pool;

    guint32 client_flags;
    gchar charset;

    int status; /* either default or current */
} backend_config, *pbackend_config;

typedef enum {
    NETWORK_TYPE_SERVER, NETWORK_TYPE_PROXY
} nw_type;

typedef struct {

    struct {
        gchar *address; /**< listening address of the admin-server */
    } admin;

    struct {
        gchar *address; /**< listening address of the proxy */

        // convert to having an array of backend configurations
        GPtrArray *backend_configs; /** backend configurations */

        gchar **backend_addresses; /**<    read-write backends */
        gchar **read_only_backend_addresses; /**< read-only  backends */

        gint fix_bug_25371; /**< suppress the second ERR packet of bug #25371 */

        gint profiling; /**< used to skips the execution of the read_query() function, now used to keep rack of time of execution */

        gchar log_debug_messages; /* log debugging messages */

        const gchar *lua_script; /**< script to load at the start the connection */
    } proxy;

    nw_type network_type;

    const gchar *pid_file; /**< write the PID to this file at startup */
} network_mysqld_config;

typedef enum {
    BACKEND_STATE_UNKNOWN,
    BACKEND_STATE_UP,
    BACKEND_STATE_DOWN
} backend_state_t;

typedef enum {
    BACKEND_TYPE_UNKNOWN,
    BACKEND_TYPE_RW,
    BACKEND_TYPE_RO
} backend_type_t;

typedef struct {
    network_address addr;

    backend_state_t state; /**< UP or DOWN */
    backend_type_t type; /**< ReadWrite or ReadOnly */

    GTimeVal state_since; /**< timestamp of the last state-change */

    network_connection_pool *pool; /**< the pool of open connections */

    guint connected_clients; /**< number of open connections to this backend for SQF */

    backend_config *config; /* configuration used to initiate the connection */
    /* pending connections to fill this backend */
    GPtrArray *pending_dbconn; // pending connections hashed by IP address
} backend_t;

typedef struct {
    struct event_base *event_base;

    network_mysqld_config config;

    GPtrArray *cons;
    GHashTable *tables;

    // database specific configuration
    backend_config db_config;

    /**
     * our pool of backends
     *
     * GPtrArray<backend_t>
     */
    GPtrArray *backend_pool;

    GTimeVal backend_last_check;

} network_mysqld;

typedef struct network_mysqld_con network_mysqld_con; /* forward declaration */

#define NETWORK_MYSQLD_PLUGIN_FUNC(x) retval_t (*x)(network_mysqld *srv, network_mysqld_con *con)
#define NETWORK_MYSQLD_PLUGIN_PROTO(x) static retval_t x(network_mysqld *srv, network_mysqld_con *con)
#define NETWORK_MYSQLD_PLUGIN_PROTO_GLOBAL(x) retval_t x(network_mysqld *srv, network_mysqld_con *con)

struct network_mysqld_plugins {
    NETWORK_MYSQLD_PLUGIN_FUNC(con_init);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_create_handshake);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_create_auth_result);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_read_handshake);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_multiserver_read_handshake);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_send_handshake);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_read_auth);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_send_auth);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_read_auth_result);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_multiserver_read_auth_result);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_send_auth_result);

    NETWORK_MYSQLD_PLUGIN_FUNC(con_read_query);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_get_server_list);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_get_server_connection_list);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_read_query_result);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_send_query_result);
    NETWORK_MYSQLD_PLUGIN_FUNC(con_cleanup);
};

/* forward declaration */
typedef struct server_connection_state server_connection_state; /* forward declaration */

#define NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(x) retval_t (*x)(network_mysqld *srv, server_connection_state *con)
#define NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(x) static retval_t x(network_mysqld *srv, server_connection_state *con)

server_connection_state* network_mysqld_async_con_init(network_mysqld *srv);

typedef struct network_mysqld_async_plugins {
    NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_init);
    NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_read_handshake);
    NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_create_auth);
    NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_send_auth);
    NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_read_auth_result);
    NETWORK_MYSQLD_ASYNC_PLUGIN_FUNC(con_send_auth_old_password);
} network_mysqld_async_plugins;

extern char *sz_state[];

/**
 * SERVER:
 * - CON_STATE_INIT
 * - CON_STATE_SEND_HANDSHAKE
 * - CON_STATE_READ_AUTH
 * - CON_STATE_SEND_AUTH_RESULT
 * - CON_STATE_READ_QUERY
 * - CON_STATE_SEND_QUERY_RESULT
 *
 * Proxy does all states
 *
 * replication client needs some init to work
 * - SHOW MASTER STATUS 
 *   to get the binlog-file and the pos 
 */
typedef enum {
    CON_STATE_INIT, // 0
    CON_STATE_SEND_HANDSHAKE,
    CON_STATE_READ_AUTH,
    CON_STATE_CREATE_AUTH_RESPONSE,
    CON_STATE_SEND_AUTH_RESULT,
    CON_STATE_READ_AUTH_OLD_PASSWORD,
    CON_STATE_SEND_AUTH_OLD_PASSWORD,
    CON_STATE_READ_QUERY, // 10
    CON_STATE_SEND_QUERY,
    CON_STATE_SEND_SINGLE_QUERY_RESULT,
    CON_STATE_READ_SINGLE_QUERY_RESULT,
    CON_STATE_READ_QUERY_RESULT,
    CON_STATE_SEND_QUERY_RESULT,

    CON_STATE_CLOSE_CLIENT,
    CON_STATE_SEND_ERROR, // 15
    CON_STATE_ERROR,
    CON_STATE_MULTIPART_SEND_AUTH_OLD_PASSWORD,
    CON_STATE_MULTIPART_SEND_QUERY,
    CON_STATE_GET_SERVER_LIST,
    CON_STATE_GET_SERVER_CONNECTION_LIST,
    CON_STATE_PROCESS_READ_QUERY

} connection_state;

struct network_mysqld_con {
    connection_state state;

    /**
     * the client and server side of the connection
     * each connection has a internal state
     * - default_db
     */

    // this only holds the host names,
    // the next one 'servers' has the real socket connection
    GPtrArray * server_hostnames;

    GPtrArray * servers; // array of MULTIPART_DATA servers
    GPtrArray * cache_servers; // cash array of MULTIPART_DATA servers
    guint8 keep_srv_con; // keep server connections

    network_socket *server, *client;

    int is_overlong_packet;

    network_mysqld_plugins plugins;
    network_mysqld_config config;
    network_mysqld *srv; /* our srv object */

    int is_listen_socket;

    GPtrArray * sql_tokens; //by MW only parse sql query into tokens once
    bool parseMaster;
    int retrynum;//dqm 连接失败重试次数

    struct {
        guint32 len;
        enum enum_server_command command;

        /**
         * each state can add their local parsing information
         *
         * auth_result is used to track the state
         * - OK  is fine
         * - ERR will close the connection
         * - EOF asks for old-password
         */
        union {

            struct {
                int want_eofs;
                int first_packet;
            } prepare;

            query_type query;

            struct {
                char state; /** OK, EOF, ERR */
            } auth_result;

            /** track the db in the COM_INIT_DB */
            struct {
                GString *db_name;
            } init_db;
        } state;
    } parse;

    void *plugin_con_state;

    int tx_level; //number of nested transaction levels

    int num_pending_servers; // number of servers waiting for replies.

    int is_finished; // true if we have received all the results.

    int init_ndx;
    GPtrArray *pending_conn_server;
};

extern char *sz_async_state[];

typedef enum {
    CON_STATE_ASYNC_INIT, // 0
    CON_STATE_ASYNC_READ_HANDSHAKE,
    CON_STATE_ASYNC_CREATE_AUTH,
    CON_STATE_ASYNC_SEND_AUTH,
    CON_STATE_ASYNC_READ_AUTH_RESULT,
    CON_STATE_ASYNC_READ_SELECT_DB,
    CON_STATE_ASYNC_READ_AUTH_OLD_PASSWORD,
    CON_STATE_ASYNC_SEND_AUTH_OLD_PASSWORDS,
    CON_STATE_ASYNC_ERROR,
    CON_STATE_ASYNC_NONE
} async_con_state;

struct server_connection_state {
    /* asynchornous connection states
     */
    async_con_state state;

    network_mysqld_async_plugins plugins;
    network_socket *server; /* database connection */
    network_mysqld *srv; /* our srv object */
    GTimeVal lastused; /** last time this object was talked to*/
    backend_config *config; /* configuration used to initiate the connection */

    void *plugin_con_state; /*global connection states/backend*/

};

#define		DEF_MULTISERVER_DB		0

void network_mysqld_async_con_handle(int event_fd, short events, void *user_data);


#define 	EVENT_WAIT_TIME				100

typedef struct multipart_data {
    int backend_ndx; // index to the backend - used by LUA script
    guint32 read_wait_count;
    network_socket *server; // pointer to existing network_socket object

    GString *sql; // new sql if required, else use clients
    network_mysqld_con *con; // pointer to the connection_state object
    int tableidx; //分表
    gulong insertid;//业务自增ID 

} MULTIPART_DATA, *PMULTIPART_DATA;

typedef struct {
    guint max_used_key_len;
    double avg_used_key_len;

    guint64 used;
} network_mysqld_index_status;

typedef struct {
    int (*select)(GPtrArray *fields, GPtrArray *rows, gpointer user_data);
    gpointer user_data;
} network_mysqld_table;

network_mysqld_index_status *network_mysqld_index_status_init();
void network_mysqld_index_status_free(network_mysqld_index_status *);
backend_t *backend_init();

void g_list_string_free(gpointer data, gpointer UNUSED_PARAM(user_data));
gboolean g_hash_table_true(gpointer UNUSED_PARAM(key), gpointer UNUSED_PARAM(value), gpointer UNUSED_PARAM(u));

int network_mysqld_con_set_address(network_address *addr, gchar *address);
int network_mysqld_con_connect(network_mysqld *srv, network_socket *con);
int network_mysqld_con_bind(network_socket *con);

int network_queue_append(network_queue *queue, const char *data, size_t len, int packet_id);
int network_queue_append_chunk(network_queue *queue, GString *chunk);

int network_mysqld_con_send_ok(network_socket *con);
int network_mysqld_con_send_ok_full(network_socket *con, guint64 affected_rows, guint64 insert_id, guint16 server_status, guint16 warnings, gchar *msg);
int network_mysqld_con_send_error(network_socket *con, const gchar *errmsg, gsize errmsg_len);
int network_mysqld_con_send_error_full(network_socket *con, const char *errmsg, gsize errmsg_len, guint errorcode, const gchar *sqlstate);
int network_mysqld_con_send_resultset(network_socket *con, GPtrArray *fields, GPtrArray *rows);

retval_t network_mysqld_write(network_mysqld *srv, network_socket *con);
retval_t network_mysqld_write_len(network_socket *con);

int network_mysqld_server_init(network_mysqld_con *con);
int network_mysqld_proxy_init(network_mysqld_con *con);
void network_mysqld_proxy_free(network_mysqld_con *con);

int network_mysqld_server_connection_init(network_mysqld_con *con);
int network_mysqld_proxy_connection_init(network_mysqld_con *con);

network_mysqld *network_mysqld_init(void);
void network_mysqld_init_libevent(network_mysqld *m);
void *network_mysqld_thread(void *);
void network_mysqld_free(network_mysqld *);

network_socket *network_socket_init(void);

network_mysqld_table *network_mysqld_table_init(void);
void network_mysqld_table_free(network_mysqld_table *);

int proxy_connection_pool_add(server_connection_state *pscs);
int proxy_connection_pool_del(server_connection_state *pscs);
int proxy_connection_pool_del_con(network_mysqld *srv, network_socket *con);

void network_mysqld_con_handle(int event_fd, short events, void *user_data);

const char *get_sql_state(int mysql_errno);

int proxy_read_query_result_is_finished(network_socket *recv_sock, int *is_finished);
MULTIPART_DATA *pmd_select(network_mysqld_con *con, int index);
int pmd_cnt(network_mysqld_con *con);
void network_mysqld_async_con_state_free(struct server_connection_state * con);
int get_config_log_debug_msgs();


#endif
