
#ifndef _NETWORK_MYSQLD_PROXY_H_
#define _NETWORK_MYSQLD_PROXY_H_

#ifdef HAVE_LUA_H

extern "C" {
/**
 * embedded lua support
 */
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
}

#endif

typedef enum {
	PROXY_NO_DECISION,
	PROXY_SEND_QUERY,
	PROXY_SEND_RESULT,
	PROXY_SEND_INJECTION,
	PROXY_IGNORE_RESULT,       /** for read_query_result */
	PROXY_STMT_ERROR
} proxy_stmt_ret;

/**
 * the shared information across all connections 
 *
 */
typedef struct {
#ifdef HAVE_LUA_H
	lua_State *L;            /**< the global lua_State */
#endif

	int init;
} plugin_srv_state;

typedef struct {
	/**
	 * the content of the OK packet 
	 */
	int server_status;
	int warning_count;
	guint64 affected_rows;
	guint64 insert_id;

	int was_resultset; /** if set, affected_rows and insert_id are ignored */

	/**
	 * MYSQLD_PACKET_OK or MYSQLD_PACKET_ERR
	 */	
	int query_status;
} query_status;

typedef struct {
	struct {
		GQueue *queries;       /** queries we want to executed */
		query_status qstat;
#ifdef HAVE_LUA_H
		lua_State *L;
		int L_ref;
#endif
		int sent_resultset;    /** make sure we send only one result back to the client */
	} injected;

	plugin_srv_state *global_state;
	backend_t *backend;
	int backend_ndx;
} plugin_con_state;

typedef struct {
	GString *query;

	int id; /* a unique id set by the scripts to map the query to a handler */

	/* the userdata's need them */
	GQueue *result_queue; /* the data to parse */
	query_status qstat;

	GTimeVal ts_read_query;          /* timestamp when we added this query to the queues */
	GTimeVal ts_read_query_result_first;   /* when we first finished it */
	GTimeVal ts_read_query_result_last;     /* when we first finished it */
} injection;


void plugin_con_state_free(plugin_con_state *st);
void proxy_remove_server_connections(network_mysqld *srv, network_mysqld_con *con);
void msbackend_init(network_mysqld_con * con);
int msbackend_pool_count(network_mysqld_con *con);
int msbackend_backend_def_server(network_mysqld_con *con, int backend_ndx);
void msbackend_clear(network_mysqld_con *con);
void msbackend_free(network_mysqld_con *con);
void pmd_free( MULTIPART_DATA *pmd );
void proxy_cache_server_connections( network_mysqld *srv, network_mysqld_con *con);
void backend_free(backend_t *b);

int pmd_cnt(network_mysqld_con *con);
network_socket* pmd_select_server(network_mysqld_con *con, int index);
int pmd_clear(network_mysqld_con *con);
int pmd_init(network_mysqld_con *con);
int msbackend_switch_def_server(network_mysqld_con *con, int backend_ndx);
bool proxy_add_server_connection_array(
					network_mysqld *srv,
					network_mysqld_con *client,
					GPtrArray *server_hostnames,
					GString *sql);
network_mysqld *get_network_mysqld();
int pool_connections_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data);
int pool_config_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data);
gchar * g_timeval_string(GTimeVal *t1, GString *str);
NETWORK_MYSQLD_PLUGIN_PROTO_GLOBAL(proxy_init);
NETWORK_MYSQLD_PLUGIN_PROTO_GLOBAL(proxy_make_auth_resp);
void network_connection_pool_create_conns(network_mysqld *srv);
void free_gstring_ptr_array(GPtrArray *array);


#endif
