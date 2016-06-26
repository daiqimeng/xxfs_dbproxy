

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_FILIO_H
/**
 * required for FIONREAD on solaris
 */
#include <sys/filio.h>
#endif

#ifndef _WIN32
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define ioctlsocket ioctl
#endif

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <assert.h>

#include <errno.h>

#include <glib.h>


#include <mysqld_error.h> /** for ER_UNKNOWN_ERROR */

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-conn-pool.h"
#include "sys-pedantic.h"

#include "sql-tokenizer.h"
#include "partition.h"
#include "messages.h"
#include "network-mysqld-proxy.h"

#undef HAVE_LUA_H   //get rid of lua

#define 	DEBUG_CONN_POOL		1

//#define _OLD_CMD_LINE_CFG_	1



#define TIME_DIFF_US(t2, t1) \
	((t2.tv_sec - t1.tv_sec) * 1000000.0 + (t2.tv_usec - t1.tv_usec))

#define C(x) x, sizeof(x) - 1

#define HASH_INSERT(hash, key, expr) \
	do { \
		GString *hash_value; \
		if ((hash_value = g_hash_table_lookup(hash, key))) { \
			expr; \
		} else { \
			hash_value = g_string_new(NULL); \
			expr; \
			g_hash_table_insert(hash, g_strdup(key), hash_value); \
		} \
	} while(0);

#define CRASHME() do { char *_crashme = NULL; *_crashme = 0; } while(0);

#ifdef  HAVE_LUA_H

static injection *injection_init(int id, GString *query) {
	injection *i;

	i = g_new0(injection, 1);
	i->id = id;
	i->query = query;

	/**
	 * we have to assume that injection_init() is only used by the read_query call
	 * which should be fine
	 */
	g_get_current_time(&(i->ts_read_query));

	return i;
}
#endif
//dqm start 

const char *seek_after(const char *str, const char *after) {
	const char *t = strcasestr(str, after);
	if (!t)
		return NULL;

	int alen = strlen(after);
	do {
		if (((t == str) || isspace(t[-1])) && isspace(t[alen])) {
			t += alen + 1;
			while (isspace(*t))
				++t;
			return t;
		} else {
			t += alen;
			while (!isspace(*t))
				++t;
		}
		str = t;
		t = strcasestr(str, after);
	} while (t);

	return NULL;
}

int getTableIdx(const char *sql) {
	char *after;
	if (strncasecmp(sql, "select", 6) == 0) {
		after = "from";
	} else if (strncasecmp(sql, "insert", 6) == 0) {
		after = "into";
	} else if (strncasecmp(sql, "replace", 7) == 0) {
		after = "into";
	} else if (strncasecmp(sql, "update", 6) == 0) {
		after = "update";
	} else if (strncasecmp(sql, "delete", 6) == 0) {
		after = "from";
	}
	const char *t = seek_after(sql, after);
	std::string ret(sql);
	if (!t)
		return NULL;

	int alen = strlen(after);
	do {
		if (isspace(*t)) {
			break;
		}
		t++;
	} while (t);

	return strlen(sql) - strlen(t);
}
//dqm over

static void injection_free(injection *i) {
	if (!i) return;

	if (i->query) g_string_free(i->query, TRUE);

	g_free(i);
}

/**
 * reset the script context of the connection 
 */
static void proxy_lua_free_script(plugin_con_state *st) {
#ifdef HAVE_LUA_H
	lua_State *L = st->injected.L;
	plugin_srv_state *g = st->global_state;

	if (!st->injected.L) return;

	g_assert(lua_isfunction(L, -1));
	lua_pop(L, 1); /* function */

	g_assert(lua_gettop(L) == 0);

	luaL_unref(g->L, LUA_REGISTRYINDEX, st->injected.L_ref);

	/**
	 * clean up our object 
	 */
	lua_gc(g->L, LUA_GCCOLLECT, 0);

	st->injected.L = NULL;
#endif
}

static plugin_con_state *plugin_con_state_init() {
	plugin_con_state *st;

	st = g_new0(plugin_con_state, 1);

	st->injected.queries = g_queue_new();

	return st;
}

void plugin_con_state_free(plugin_con_state *st) {
	injection *inj;

	if (!st) return;

	proxy_lua_free_script(st);

	while ((inj = (injection *) g_queue_pop_head(st->injected.queries))) injection_free(inj);
	g_queue_free(st->injected.queries);

	g_free(st);
}

#ifdef HAVE_LUA_H

/**
 * init the global proxy object 
 */
static void proxy_lua_init_global_fenv(lua_State *L) {

	lua_newtable(L); /* my empty environment aka {}              (sp += 1) */
#define DEF(x) \
	lua_pushinteger(L, x); \
	lua_setfield(L, -2, #x);

	DEF(PROXY_SEND_QUERY);
	DEF(PROXY_SEND_RESULT);
	DEF(PROXY_IGNORE_RESULT);

	DEF(MYSQLD_PACKET_OK);
	DEF(MYSQLD_PACKET_ERR);
	DEF(MYSQLD_PACKET_RAW);

	DEF(BACKEND_STATE_UNKNOWN);
	DEF(BACKEND_STATE_UP);
	DEF(BACKEND_STATE_DOWN);

	DEF(BACKEND_TYPE_UNKNOWN);
	DEF(BACKEND_TYPE_RW);
	DEF(BACKEND_TYPE_RO);

	DEF(COM_SLEEP);
	DEF(COM_QUIT);
	DEF(COM_INIT_DB);
	DEF(COM_QUERY);
	DEF(COM_FIELD_LIST);
	DEF(COM_CREATE_DB);
	DEF(COM_DROP_DB);
	DEF(COM_REFRESH);
	DEF(COM_SHUTDOWN);
	DEF(COM_STATISTICS);
	DEF(COM_PROCESS_INFO);
	DEF(COM_CONNECT);
	DEF(COM_PROCESS_KILL);
	DEF(COM_DEBUG);
	DEF(COM_PING);
	DEF(COM_TIME);
	DEF(COM_DELAYED_INSERT);
	DEF(COM_CHANGE_USER);
	DEF(COM_BINLOG_DUMP);
	DEF(COM_TABLE_DUMP);
	DEF(COM_CONNECT_OUT);
	DEF(COM_REGISTER_SLAVE);
	DEF(COM_STMT_PREPARE);
	DEF(COM_STMT_EXECUTE);
	DEF(COM_STMT_SEND_LONG_DATA);
	DEF(COM_STMT_CLOSE);
	DEF(COM_STMT_RESET);
	DEF(COM_SET_OPTION);
#if MYSQL_VERSION_ID >= 50000
	DEF(COM_STMT_FETCH);
#if MYSQL_VERSION_ID >= 50100
	DEF(COM_DAEMON);
#endif
#endif
	DEF(MYSQL_TYPE_DECIMAL);
#if MYSQL_VERSION_ID >= 50000
	DEF(MYSQL_TYPE_NEWDECIMAL);
#endif
	DEF(MYSQL_TYPE_TINY);
	DEF(MYSQL_TYPE_SHORT);
	DEF(MYSQL_TYPE_LONG);
	DEF(MYSQL_TYPE_FLOAT);
	DEF(MYSQL_TYPE_DOUBLE);
	DEF(MYSQL_TYPE_NULL);
	DEF(MYSQL_TYPE_TIMESTAMP);
	DEF(MYSQL_TYPE_LONGLONG);
	DEF(MYSQL_TYPE_INT24);
	DEF(MYSQL_TYPE_DATE);
	DEF(MYSQL_TYPE_TIME);
	DEF(MYSQL_TYPE_DATETIME);
	DEF(MYSQL_TYPE_YEAR);
	DEF(MYSQL_TYPE_NEWDATE);
	DEF(MYSQL_TYPE_ENUM);
	DEF(MYSQL_TYPE_SET);
	DEF(MYSQL_TYPE_TINY_BLOB);
	DEF(MYSQL_TYPE_MEDIUM_BLOB);
	DEF(MYSQL_TYPE_LONG_BLOB);
	DEF(MYSQL_TYPE_BLOB);
	DEF(MYSQL_TYPE_VAR_STRING);
	DEF(MYSQL_TYPE_STRING);
	DEF(MYSQL_TYPE_GEOMETRY);
#if MYSQL_VERSION_ID >= 50000
	DEF(MYSQL_TYPE_BIT);
#endif

	/* cheat with DEF() a bit :) */
#define PROXY_VERSION PACKAGE_VERSION_ID
	DEF(PROXY_VERSION);
#undef DEF

	/**
	 * create 
	 * - proxy.global 
	 * - proxy.global.config
	 */
	lua_newtable(L);
	lua_newtable(L);
	lua_setfield(L, -2, "config");
	lua_setfield(L, -2, "global");

	lua_setglobal(L, "proxy");

}
#endif

backend_t *backend_init() {
	backend_t *b;

	b = g_new0(backend_t, 1);

	b->pool = network_connection_pool_init();

	return b;
}

void backend_free(backend_t *b) {
	if (!b) return;

	network_connection_pool_free(b->pool);

	if (b->addr.str) g_free(b->addr.str);

	if (NULL != b->config) {
		if (NULL != b->config->default_username)
			g_string_free(b->config->default_username, TRUE);

		if (NULL != b->config->default_password)
			g_string_free(b->config->default_password, TRUE);

		if (NULL != b->config->default_db)
			g_string_free(b->config->default_db, TRUE);

		g_free(b->config);
	}

	if (NULL != b->pending_dbconn) {
		size_t idx = 0;
		server_connection_state *pscs;
		for (idx = 0; idx < b->pending_dbconn->len; idx++) {
			if ((pscs = (server_connection_state *) (b->pending_dbconn->pdata[idx])) != NULL) {
				network_mysqld_async_con_state_free(pscs);
			}
		}

		g_ptr_array_free(b->pending_dbconn, TRUE);
	}

	g_free(b);
}

static plugin_srv_state *plugin_srv_state_init() {
	plugin_srv_state *g;

	g = g_new0(plugin_srv_state, 1);

#ifdef HAVE_LUA_H
	g->L = luaL_newstate();
	luaL_openlibs(g->L);

	proxy_lua_init_global_fenv(g->L);
#endif
	return g;
}

void plugin_srv_state_free(plugin_srv_state *g) {

	if (!g) return;

#ifdef HAVE_LUA_H
	if (g->L) lua_close(g->L);
#endif

	g_free(g);
}

static network_connection_pool *get_backend_conn_pool(network_mysqld *srv, network_socket *con) {
	backend_t *backend = NULL;
	size_t i;

	if (!con)
		return NULL;

	// find the pool the socket is associated to
	for (i = 0; i < srv->backend_pool->len; i++) {
		backend = (backend_t *) (srv->backend_pool->pdata[i]);

		if ((strcmp(backend->addr.str, con->addr.str) == 0) &&
				(strcmp(backend->config->default_db->str,
						con->default_db->str) == 0)) {
			break;
		}
		backend = NULL;
	}

	return backend ? backend->pool : NULL;
}

/**
 * handle the events of a idling server connection in the pool 
 *
 * make sure we know about connection close from the server side
 * - wait_timeout
 */
static void network_mysqld_con_idle_handle(int event_fd, short events, void *user_data) {
	network_socket *server = (network_socket *) user_data;

	network_connection_pool *pool = get_backend_conn_pool(get_network_mysqld(), server);

	if (events == EV_READ) {
		int b = -1;

		/**
		 * FIXME: we have to handle the case that the server really sent use something
		 * up to now we just ignore it
		 */
		if (ioctlsocket(event_fd, FIONREAD, &b)) {
			log_error("ioctl(%d, FIONREAD, ...) failed: %s", event_fd, strerror(errno));
		} else if (b != 0) {
			log_error("ioctl(%d, FIONREAD, ...) said there is something to read, oops: %d", event_fd, b);
		} else {
			/* the server decided the close the connection (wait_timeout, crash, ... )
			 *
			 * remove us from the connection pool and close the connection */

			network_connection_pool_del_byconn(pool, server);
		}
	} else if (events == EV_TIMEOUT) {
		if (time(NULL) - server->last_write_time >= get_config_max_conn_idle_time()) {
			log_warning("backend connection (socket=%d, addr=%s) has been idle for too long, closing ...",
					server->fd, server->addr.str ? server->addr.str : "");
			network_connection_pool_del_byconn(pool, server);
			network_socket_free(server);
			network_connection_pool_create_conns(get_network_mysqld());
		} else {
			struct timeval tv;
			event_set(&(server->event), server->fd, EV_READ | EV_TIMEOUT, network_mysqld_con_idle_handle, server);
			event_base_set(get_network_mysqld()->event_base, &(server->event));
			tv.tv_sec = get_config_max_conn_idle_time();
			tv.tv_usec = 0;
			log_debug("%s.%d: adding event EV_READ|EV_TIMEOUT for SOCKET=%d\n", __FILE__, __LINE__, server->fd);
			event_add(&(server->event), &tv);
		}
	}
}

/**
 * move the con->server into connection pool and disconnect the 
 * proxy from its backend 
 */
static int proxy_connection_pool_add_connection(network_mysqld_con *con) {
	network_mysqld *srv = con->srv;
	//plugin_con_state *st = (plugin_con_state *)(con->plugin_con_state);
	struct timeval tv;

	log_debug("%s.%d add_connection server = %p", __FILE__, __LINE__, con->server);

	/* con-server is already disconnected, get out */
	if (!con->server) return 0;

	if (!con->client) {
		log_debug("%s.%d add_connection server = %p", __FILE__, __LINE__, con->client);
		return 0;
	}

	/* the server connection is still authed */
	con->server->is_authed = 1;

	event_set(&(con->server->event), con->server->fd, EV_READ | EV_TIMEOUT, network_mysqld_con_idle_handle, con->server);
	event_base_set(srv->event_base, &(con->server->event));

	tv.tv_sec = get_config_max_conn_idle_time();
	tv.tv_usec = 0;
	log_debug("%s.%d: adding event EV_READ|EV_TIMEOUT for SOCKET=%d\n", __FILE__, __LINE__, con->server->fd);
	event_add(&(con->server->event), &tv);

	return 0;
}

#ifdef HAVE_LUA_H

/**
 * load the lua script
 *
 * wraps luaL_loadfile and prints warnings when needed
 *
 * @see luaL_loadfile
 */
lua_State *lua_load_script(lua_State *L, const gchar *name) {
	if (0 != luaL_loadfile(L, name)) {
		/* oops, an error, return it */
		log_warning("luaL_loadfile(%s) failed", name);

		return L;
	}

	/**
	 * pcall() needs the function on the stack
	 *
	 * as pcall() will pop the script from the stack when done, we have to
	 * duplicate it here
	 */
	g_assert(lua_isfunction(L, -1));

	return L;
}

/**
 * get the info connection pool 
 *
 * @return nil or requested information
 */
static int proxy_pool_queue_get(lua_State *L) {
	GQueue *queue = *(GQueue **) luaL_checkudata(L, 1, "proxy.backend.pool.queue");
	const char *key = luaL_checkstring(L, 2); /** ... cur_idle */

	if (0 == strcmp(key, "cur_idle_connections")) {
		lua_pushinteger(L, queue ? queue->length : 0);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

/**
 * get the info connection pool 
 *
 * @return nil or requested information
 */
static int proxy_pool_users_get(lua_State *L) {
	network_connection_pool *pool = *(network_connection_pool **) luaL_checkudata(L, 1, "proxy.backend.pool.users");
	const char *key = luaL_checkstring(L, 2); /** the username */
	GString *s = g_string_new(key);
	GQueue **q_p = NULL;

	log_debug("%s.%d proxy_pool_users_get", __FILE__, __LINE__);

	q_p = (GQueue **) (lua_newuserdata(L, sizeof (*q_p)));
	*q_p = network_connection_pool_get_conns(pool, s, NULL);
	g_string_free(s, TRUE);

	/* if the meta-table is new, add __index to it */
	if (1 == luaL_newmetatable(L, "proxy.backend.pool.queue")) {
		lua_pushcfunction(L, proxy_pool_queue_get); /* (sp += 1) */
		lua_setfield(L, -2, "__index"); /* (sp -= 1) */
	}

	lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */

	return 1;
}

static int proxy_pool_get(lua_State *L) {
	network_connection_pool *pool = *(network_connection_pool **) luaL_checkudata(L, 1, "proxy.backend.pool");
	const char *key = luaL_checkstring(L, 2);

	if (0 == strcmp(key, "max_idle_connections")) {
		lua_pushinteger(L, pool->max_idle_connections);
	} else if (0 == strcmp(key, "min_idle_connections")) {
		lua_pushinteger(L, pool->min_idle_connections);
	} else if (0 == strcmp(key, "users")) {
		network_connection_pool **pool_p;

		pool_p = (network_connection_pool **) (lua_newuserdata(L, sizeof (*pool_p)));
		*pool_p = pool;

		/* if the meta-table is new, add __index to it */
		if (1 == luaL_newmetatable(L, "proxy.backend.pool.users")) {
			lua_pushcfunction(L, proxy_pool_users_get); /* (sp += 1) */
			lua_setfield(L, -2, "__index"); /* (sp -= 1) */
		}

		lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */
	} else {
		lua_pushnil(L);
	}

	return 1;
}

static int proxy_pool_set(lua_State *L) {
	network_connection_pool *pool = *(network_connection_pool **) luaL_checkudata(L, 1, "proxy.backend.pool");
	const char *key = luaL_checkstring(L, 2);

	if (0 == strcmp(key, "max_idle_connections")) {
		pool->max_idle_connections = lua_tointeger(L, -1);
	} else if (0 == strcmp(key, "min_idle_connections")) {
		pool->min_idle_connections = lua_tointeger(L, -1);
	} else {
		return luaL_error(L, "proxy.backend[...].%s is not writable", key);
	}

	return 0;
}

/**
 * get the info about a backend
 *
 * proxy.backend[0].
 *   connected_clients => clients using this backend
 *   address           => ip:port or unix-path of to the backend
 *   state             => int(BACKEND_STATE_UP|BACKEND_STATE_DOWN) 
 *   type              => int(BACKEND_TYPE_RW|BACKEND_TYPE_RO) 
 *
 * @return nil or requested information
 * @see backend_state_t backend_type_t
 */
static int proxy_backend_get(lua_State *L) {
	backend_t *backend = *(backend_t **) luaL_checkudata(L, 1, "proxy.backend");
	const char *key = luaL_checkstring(L, 2);

	if (0 == strcmp(key, "connected_clients")) {
		lua_pushinteger(L, backend->connected_clients);
	} else if (0 == strcmp(key, "address")) {
		lua_pushstring(L, backend->addr.str);
	} else if (0 == strcmp(key, "state")) {
		lua_pushinteger(L, backend->state);
	} else if (0 == strcmp(key, "type")) {
		lua_pushinteger(L, backend->type);
	} else if (0 == strcmp(key, "pool")) {
		network_connection_pool *pool;
		network_connection_pool **pool_p;

		pool_p = (network_connection_pool **) (lua_newuserdata(L, sizeof (pool)));
		*pool_p = backend->pool;

		/* if the meta-table is new, add __index to it */
		if (1 == luaL_newmetatable(L, "proxy.backend.pool")) {
			lua_pushcfunction(L, proxy_pool_get); /* (sp += 1) */
			lua_setfield(L, -2, "__index"); /* (sp -= 1) */
			lua_pushcfunction(L, proxy_pool_set); /* (sp += 1) */
			lua_setfield(L, -2, "__newindex"); /* (sp -= 1) */
		}

		lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */
	} else {
		lua_pushnil(L);
	}

	return 1;
}

/**
 * get proxy.backends[ndx]
 *
 * get the backend from the array of mysql backends. 
 *
 * @return nil or the backend
 * @see proxy_backend_get
 */
static int proxy_backends_get(lua_State *L) {
	backend_t *backend;
	backend_t **backend_p;

	network_mysqld_con *con = *(network_mysqld_con **) luaL_checkudata(L, 1, "proxy.backends");
	int backend_ndx = luaL_checkinteger(L, 2) - 1; /** lua is indexes from 1, C from 0 */

	if (backend_ndx < 0 ||
			backend_ndx >= int(con->srv->backend_pool->len)) {
		lua_pushnil(L);

		return 1;
	}

	backend = (backend_t *) (con->srv->backend_pool->pdata[backend_ndx]);

	backend_p = (backend_t **) (lua_newuserdata(L, sizeof (backend))); /* the table underneat proxy.backends[ndx] */
	*backend_p = backend;

	/* if the meta-table is new, add __index to it */
	if (1 == luaL_newmetatable(L, "proxy.backend")) {
		lua_pushcfunction(L, proxy_backend_get); /* (sp += 1) */
		lua_setfield(L, -2, "__index"); /* (sp -= 1) */
	}

	lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */

	return 1;
}

static int proxy_backends_len(lua_State *L) {
	network_mysqld_con *con = *(network_mysqld_con **) luaL_checkudata(L, 1, "proxy.backends");

	lua_pushinteger(L, con->srv->backend_pool->len);

	return 1;
}

static int proxy_socket_get(lua_State *L) {
	network_socket *sock = *(network_socket **) luaL_checkudata(L, 1, "proxy.socket");
	const char *key = luaL_checkstring(L, 2);

	/**
	 * we to split it in .client and .server here
	 */

	if (0 == strcmp(key, "default_db")) {
		lua_pushlstring(L, sock->default_db->str, sock->default_db->len);
	} else if (0 == strcmp(key, "username")) {
		lua_pushlstring(L, sock->username->str, sock->username->len);
	} else if (0 == strcmp(key, "address")) {
		lua_pushstring(L, sock->addr.str);
	} else if (0 == strcmp(key, "scrambled_password")) {
		lua_pushlstring(L, sock->scrambled_password->str, sock->scrambled_password->len);
	} else if (sock->mysqld_version) { /* only the server-side has mysqld_version set */
		if (0 == strcmp(key, "mysqld_version")) {
			lua_pushinteger(L, sock->mysqld_version);
		} else if (0 == strcmp(key, "thread_id")) {
			lua_pushinteger(L, sock->thread_id);
		} else if (0 == strcmp(key, "scramble_buffer")) {
			lua_pushlstring(L, sock->scramble_buf->str, sock->scramble_buf->len);
		} else {
			lua_pushnil(L);
		}
	} else {
		lua_pushnil(L);
	}

	return 1;
}

/**
 * get the connection information
 *
 * note: might be called in connect_server() before con->server is set 
 */
static int proxy_connection_get(lua_State *L) {
	network_mysqld_con *con = *(network_mysqld_con **) luaL_checkudata(L, 1, "proxy.connection");
	plugin_con_state *st;
	const char *key = luaL_checkstring(L, 2);

	st = (plugin_con_state *) (con->plugin_con_state);

	/**
	 * we to split it in .client and .server here
	 */

	if (0 == strcmp(key, "default_db")) {
		return luaL_error(L, "proxy.connection.default_db is deprecated, use proxy.connection.client.default_db or proxy.connection.server.default_db instead");
	} else if (0 == strcmp(key, "thread_id")) {
		return luaL_error(L, "proxy.connection.thread_id is deprecated, use proxy.connection.server.thread_id instead");
	} else if (0 == strcmp(key, "mysqld_version")) {
		return luaL_error(L, "proxy.connection.mysqld_version is deprecated, use proxy.connection.server.mysqld_version instead");
	} else if (0 == strcmp(key, "backend_ndx")) {
		lua_pushinteger(L, st->backend_ndx + 1);
	} else if ((con->server && (0 == strcmp(key, "server"))) ||
			(con->client && (0 == strcmp(key, "client")))) {
		network_socket **socket_p;

		socket_p = (network_socket **) (lua_newuserdata(L, sizeof (network_socket))); /* the table underneat proxy.socket */

		if (key[0] == 's') {
			*socket_p = con->server;
		} else {
			*socket_p = con->client;
		}

		/* if the meta-table is new, add __index to it */
		if (1 == luaL_newmetatable(L, "proxy.socket")) {
			lua_pushcfunction(L, proxy_socket_get); /* (sp += 1) */
			lua_setfield(L, -2, "__index"); /* (sp -= 1) */
		}

		lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */
	} else {
		lua_pushnil(L);
	}

	return 1;
}

/**
 * set the connection information
 *
 * note: might be called in connect_server() before con->server is set 
 */
static int proxy_connection_set(lua_State *L) {
	network_mysqld_con *con = *(network_mysqld_con **) luaL_checkudata(L, 1, "proxy.connection");
	plugin_con_state *st;
	const char *key = luaL_checkstring(L, 2);

	st = (plugin_con_state *) (con->plugin_con_state);

	if (0 == strcmp(key, "backend_ndx")) {
		/**
		 * in lua-land the ndx is based on 1, in C-land on 0 */
		int backend_ndx = luaL_checkinteger(L, 3) - 1;
		network_socket *send_sock;

		log_debug("%s.%d: proxy_connection_set backend=%d\n", __FILE__, __LINE__, backend_ndx);

		if (backend_ndx == -1) {
			/** drop the backend for now
			*/
			proxy_connection_pool_add_connection(con);
		} else if (NULL != (send_sock = proxy_connection_pool_swap(con, backend_ndx))) {
			con->server = send_sock;
		} else {
			st->backend_ndx = backend_ndx;
		}
	} else {
		return luaL_error(L, "proxy.connection.%s is not writable", key);
	}

	return 0;
}

/**
 * get the info about a multipart
 *
 * proxy.multipart[0].
 *   connected_clients => clients using this backend
 *   address           => ip:port or unix-path of to the backend
 *   state             => int(BACKEND_STATE_UP|BACKEND_STATE_DOWN) 
 *   type              => int(BACKEND_TYPE_RW|BACKEND_TYPE_RO) 
 *
 * @return nil or requested information
 * @see backend_state_t backend_type_t
 */
static int proxy_multipart_get(lua_State *L) {
	MULTIPART_DATA *pmd = *(MULTIPART_DATA**) luaL_checkudata(L, 1, "proxy.multipart");
	const char *key = luaL_checkstring(L, 2);

	log_debug("%s.%d: multipart_get[] = %s", __FILE__, __LINE__, key);

	if (0 == strcmp(key, "backend")) {
		lua_pushinteger(L, pmd->backend_ndx + 1);
	} else if (0 == strcmp(key, "sql")) {
		if (pmd->sql == NULL)
			lua_pushnil(L);
		else
			lua_pushstring(L, pmd->sql->str);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

/**
 * set the info about a multipart
 *
 * proxy.multipart[0].
 *   connected_clients => clients using this backend
 *   address           => ip:port or unix-path of to the backend
 *   state             => int(BACKEND_STATE_UP|BACKEND_STATE_DOWN) 
 *   type              => int(BACKEND_TYPE_RW|BACKEND_TYPE_RO) 
 *
 * @return nil or requested information
 * @see backend_state_t backend_type_t
 */
static int proxy_multipart_set(lua_State *L) {
	network_socket *send_sock;
	MULTIPART_DATA *pmd = *(MULTIPART_DATA**) luaL_checkudata(L, 1, "proxy.multipart");
	const char *key = luaL_checkstring(L, 2);
	plugin_con_state *st;

	st = (plugin_con_state *) (pmd->con->plugin_con_state);

	log_debug("%s.%d: multipart_set[] = %s", __FILE__, __LINE__, key);

	if (0 == strcmp(key, "backend")) {
		// fetch the number and switch to 0 base
		pmd->backend_ndx = (int) (lua_tonumber(L, 3)) - 1;

		// prefetch the socket, this will also let us know if there is a problem
		// with the connection backend_ndx 	
		if (NULL != (send_sock = proxy_connection_fetch(
						pmd->con,
						pmd->backend_ndx))) {
			pmd->server = send_sock;
			log_debug("%s.%d: multipart_set[].backend found socket", __FILE__, __LINE__);

			st->backend_ndx = pmd->backend_ndx;
		} else {
			log_debug("%s.%d: multipart_set[].backend_ndx=%d has no pool object",
					__FILE__, __LINE__, pmd->backend_ndx);
			st->backend_ndx = pmd->backend_ndx;
			return 0;
		}

	} else if (0 == strcmp(key, "sql")) {
		//GString *s = g_string_new(key);
		pmd->sql->str = g_strdup(lua_tostring(L, 3));
		//pmd->sql = luaL_checkstring(L, 3);
		log_debug("%s.%d: multipart_set[].sql = %s", __FILE__, __LINE__, pmd->sql);
	} else {
		log_debug("%s.%d: multipart_set[] %s not supported", __FILE__, __LINE__);
	}

	return 1;
}

static int multiparts_len(lua_State *L) {
	network_mysqld_con *con = *(network_mysqld_con **) luaL_checkudata(L, 1, "proxy.multiparts");
	//plugin_con_state *st;

	log_debug("%s.%d: multipart_len = %d", __FILE__, __LINE__, (con->servers == NULL) ? 0 : con->servers->len);

	//st = con->plugin_con_state;

	lua_pushinteger(L, (con->servers == NULL) ? 0 : con->servers->len);

	return 1;
}

/**
 * get the connection information
 *
 * note: might be called in connect_server() before con->server is set 
 */
static int multiparts_get(lua_State *L) {
	network_mysqld_con *con = *(network_mysqld_con **) luaL_checkudata(L, 1, "proxy.multiparts");
	//backend_t *backend;
	//const char *key = luaL_checkstring(L, 2);
	//network_socket *send_sock;
	MULTIPART_DATA *pmd;
	MULTIPART_DATA **pmd_p;
	int backend_ndx = (int) (lua_tonumber(L, 2));

	if (0 == backend_ndx) // lua is 1 based, follow it...
	{
		log_debug("%s.%d: multiparts_get invalid index %d",
				__FILE__, __LINE__, backend_ndx);
		return 0;
	}

	if (backend_ndx > int(con->servers->len)) {
		pmd = g_new0(MULTIPART_DATA, 1);
		pmd->server = NULL;
		pmd->sql = NULL;
		pmd->con = con;
		g_ptr_array_add(con->servers, pmd);
	} else
		pmd = (MULTIPART_DATA*) con->servers->pdata[backend_ndx - 1];

	pmd_p = (MULTIPART_DATA **) (lua_newuserdata(L, sizeof (MULTIPART_DATA))); /* the table underneat proxy.backends[ndx] */
	*pmd_p = pmd;

	/* if the meta-table is new, add __index to it */
	if (1 == luaL_newmetatable(L, "proxy.multipart")) {
		lua_pushcfunction(L, proxy_multipart_get); /* (sp += 1) */
		lua_setfield(L, -2, "__index"); /* (sp -= 1) */
		lua_pushcfunction(L, proxy_multipart_set); /* (sp += 1) */
		lua_setfield(L, -2, "__newindex"); /* (sp -= 1) */
	}

	lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */

	return 1;
}

/**
 * set the connection information
 *
 * note: might be called in connect_server() before con->server is set 
 */
static int multiparts_set(lua_State *L) {
	network_mysqld_con *con = *(network_mysqld_con **) luaL_checkudata(L, 1, "proxy.multiparts");
	plugin_con_state *st;
	network_socket *send_sock;
	int ndx;
	MULTIPART_DATA *pmd;
	GString *sql = NULL;

	// the key is the index value [key]
	//const char *key = luaL_checkstring(L, 2);

	log_debug("%s.%d: multiparts_set", __FILE__, __LINE__);

	st = (plugin_con_state *) (con->plugin_con_state);

	ndx = (int) lua_tonumber(L, 2);

	//if (lua_istable(L, -1)) { 			/* proxy.multiparts[i] */
	//lua_getfield(L, -1, "backend"); 	/* proxy.multiparts[].value*/
	//if (lua_isnumber(L, -1)) {
	//ndx = lua_tonumber(L, -1);
	//}
	//lua_getfield(L, -1, "sql"); /* proxy.multiparts[].sql */
	//sql = lua_isstring(L, 0);
	//if (lua_isstring(L, -2)) {
	//	sql = lua_isstring(L, -2);
	//} }

	if (ndx == 0) {
		/* the first item becomes the default server */
		if (NULL != (send_sock = proxy_connection_pool_swap(con, ndx))) {
			pmd = g_new0(MULTIPART_DATA, 1);
			pmd->server = send_sock;
			pmd->sql = sql;
			pmd->con = con;
			g_ptr_array_add(con->servers, pmd);
		}
	} else if (NULL != (send_sock = proxy_connection_fetch(con, ndx))) {
		pmd = g_new0(MULTIPART_DATA, 1);
		pmd->server = send_sock;
		pmd->sql = sql;
		pmd->con = con;
		g_ptr_array_add(con->servers, pmd);
	} else
		log_debug("%s.%d: multiparts_set invalid server = %d", __FILE__, __LINE__, ndx);

	lua_pop(L, 1);

#if 0
	for (i = 1;; i++) {
		lua_rawgeti(L, -1, i);

		if (lua_istable(L, -1)) { /** proxy.multiparts[i] */

			//lua_getfield(L, -1, "value"); /* proxy.multiparts[].value*/
			if (lua_isnumber(L, -1)) {
				ndx = lua_tonumber(L, -1);

				if (ndx == 0) {
					/* the first item becomes the default server */
					if (NULL != (send_sock = proxy_connection_pool_swap(con, ndx))) {
						g_ptr_array_add(con->servers, send_sock);
					}
				} else if (NULL != (send_sock = proxy_connection_fetch(con, ndx))) {
					g_ptr_array_add(con->servers, send_sock);
				}
			}
			lua_pop(L, 1);
		}
	}
#endif

	return 0;
}

static int proxy_queue_append(lua_State *L) {
	/* we expect 2 parameters */
	GQueue *q = *(GQueue **) luaL_checkudata(L, 1, "proxy.queue");
	int resp_type = luaL_checkinteger(L, 2);
	size_t str_len;
	const char *str = luaL_checklstring(L, 3, &str_len);

	GString *query = g_string_sized_new(str_len);
	g_string_append_len(query, str, str_len);

	g_queue_push_tail(q, injection_init(resp_type, query));

	return 0;
}

static int proxy_queue_prepend(lua_State *L) {
	/* we expect 2 parameters */
	GQueue *q = *(GQueue **) luaL_checkudata(L, 1, "proxy.queue");
	int resp_type = luaL_checkinteger(L, 2);
	size_t str_len;
	const char *str = luaL_checklstring(L, 3, &str_len);

	GString *query = g_string_sized_new(str_len);
	g_string_append_len(query, str, str_len);

	g_queue_push_head(q, injection_init(resp_type, query));

	return 0;
}

static int proxy_queue_reset(lua_State *L) {
	/* we expect 2 parameters */
	GQueue *q = *(GQueue **) luaL_checkudata(L, 1, "proxy.queue");
	injection *inj;

	while ((inj = (injection *) (g_queue_pop_head(q)))) injection_free(inj);

	return 0;
}

static int proxy_queue_len(lua_State *L) {
	/* we expect 2 parameters */
	GQueue *q = *(GQueue **) luaL_checkudata(L, 1, "proxy.queue");

	lua_pushinteger(L, q->length);

	return 1;
}

/**
 * split the SQL query into a stream of tokens
 */
static int proxy_tokenize(lua_State *L) {
	size_t str_len;
	const char *str = luaL_checklstring(L, 1, &str_len);
	GPtrArray *tokens = g_ptr_array_new();
	gsize i;

	sql_tokenizer(tokens, str, str_len);

	/**
	 * export the data into a table 
	 */

	lua_newtable(L);

	for (i = 0; i < tokens->len; i++) {
		sql_token *token = (sql_token *) (tokens->pdata[i]);

		lua_newtable(L);

		lua_pushlstring(L, token->text->str, token->text->len);
		lua_setfield(L, -2, "text");

		lua_pushinteger(L, token->token_id);
		lua_setfield(L, -2, "token_id");

		lua_pushstring(L, sql_token_get_name(token->token_id));
		lua_setfield(L, -2, "token_name");

		lua_rawseti(L, -2, i + 1);

		sql_token_free(token);
	}

	g_ptr_array_free(tokens, TRUE);

	return 1;
}

/**
 * setup the script before we hook function is executed 
 *
 * has to be called before any lua_pcall() is called to start a hook function
 *
 * - we use a global lua_State which is split into child-states with lua_newthread()
 * - luaL_ref() moves the state into the registry and cleans up the global stack
 * - on connection close we call luaL_unref() to hand the thread to the GC
 *
 * @see proxy_lua_free_script
 */
static int lua_register_callback(network_mysqld_con *con) {
	lua_State *L = NULL;
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	plugin_srv_state *g = st->global_state;
	GQueue **q_p;
	network_mysqld_con **con_p;

	if (!con->config.proxy.lua_script) return 0;

	if (NULL == st->injected.L) {
		/**
		 * create a side thread for this connection
		 *
		 * (this is not pre-emptive, it is just a new stack in the global env)
		 */
		L = lua_newthread(g->L);

		/**
		 * move the thread into the registry to clean up the global stack 
		 */
		st->injected.L_ref = luaL_ref(g->L, LUA_REGISTRYINDEX);

		lua_load_script(L, con->config.proxy.lua_script);

		if (lua_isstring(L, -1)) {
			log_warning("lua_load_file(%s) failed: %s", con->config.proxy.lua_script, lua_tostring(L, -1));

			lua_pop(L, 1); /* remove the error-msg from the stack */

			proxy_lua_free_script(st);

			L = NULL;
		} else if (lua_isfunction(L, -1)) {
			/**
			 * set the function env */
			lua_newtable(L); /* my empty environment aka {}              (sp += 1) */
			lua_newtable(L); /* the meta-table for the new env           (sp += 1) */

			lua_pushvalue(L, LUA_GLOBALSINDEX); /* (sp += 1) */
			lua_setfield(L, -2, "__index"); /* { __index = _G }          (sp -= 1) */
			lua_setmetatable(L, -2); /* setmetatable({}, {__index = _G}) (sp -= 1) */
			lua_setfenv(L, -2); /* on the stack should be a modified env (sp -= 1) */

			/* cache the script */
			g_assert(lua_isfunction(L, -1));
			lua_pushvalue(L, -1);

			/* push the functions on the stack */
			if (lua_pcall(L, 0, 0, 0) != 0) {
				log_error("(lua-error) [%s]\n%s", con->config.proxy.lua_script, lua_tostring(L, -1));

				lua_pop(L, 1); /* errmsg */

				proxy_lua_free_script(st);

				L = NULL;
			}
			st->injected.L = L;

			/* on the stack should be the script now, keep it there */
		} else {
			log_error("lua_load_file(%s): returned a %s", con->config.proxy.lua_script, lua_typename(L, lua_type(L, -1)));
		}
	} else {
		L = st->injected.L;
	}

	if (!L) return 0;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "proxy");
	if (!lua_istable(L, -1)) {
		log_error("fenv.proxy should be a table, but is %s", lua_typename(L, lua_type(L, -1)));
	}
	g_assert(lua_istable(L, -1));

	q_p = (GQueue **) (lua_newuserdata(L, sizeof (GQueue *)));
	*q_p = st->injected.queries;

	/**
	 * proxy.queries
	 *
	 * implement a queue
	 *
	 * - append(type, query)
	 * - prepend(type, query)
	 * - reset()
	 * - len() and #proxy.queue
	 *
	 */
	if (1 == luaL_newmetatable(L, "proxy.queue")) {
		lua_pushcfunction(L, proxy_queue_append);
		lua_setfield(L, -2, "append");
		lua_pushcfunction(L, proxy_queue_prepend);
		lua_setfield(L, -2, "prepend");
		lua_pushcfunction(L, proxy_queue_reset);
		lua_setfield(L, -2, "reset");
		lua_pushcfunction(L, proxy_queue_len);
		lua_setfield(L, -2, "len"); /* DEPRECATED: */
		lua_pushcfunction(L, proxy_queue_len);
		lua_setfield(L, -2, "__len"); /* support #proxy.queue too */

		lua_pushvalue(L, -1); /* meta.__index = meta */
		lua_setfield(L, -2, "__index");
	}

	lua_setmetatable(L, -2);

	lua_setfield(L, -2, "queries");

	/**
	 * export internal functions 
	 *
	 * @note: might be moved into a lua-c-lib instead
	 */
	lua_pushcfunction(L, proxy_tokenize);
	lua_setfield(L, -2, "tokenize");

	/**
	 * proxy.connection is (mostly) read-only
	 *
	 * .thread_id  = ... thread-id against this server
	 * .backend_id = ... index into proxy.backends[ndx]
	 *
	 */

	con_p = (network_mysqld_con **) (lua_newuserdata(L, sizeof (con)));
	*con_p = con;

	/* if the meta-table is new, add __index to it */
	if (1 == luaL_newmetatable(L, "proxy.connection")) {
		lua_pushcfunction(L, proxy_connection_get); /* (sp += 1) */
		lua_setfield(L, -2, "__index"); /* (sp -= 1) */
		lua_pushcfunction(L, proxy_connection_set); /* (sp += 1) */
		lua_setfield(L, -2, "__newindex"); /* (sp -= 1) */
	}

	lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */
	lua_setfield(L, -2, "connection");

	/**
	 * register proxy.backends[]
	 *
	 * @see proxy_backends_get()
	 */

	con_p = (network_mysqld_con **) (lua_newuserdata(L, sizeof (con)));
	*con_p = con;
	/* if the meta-table is new, add __index to it */
	if (1 == luaL_newmetatable(L, "proxy.backends")) {
		lua_pushcfunction(L, proxy_backends_get); /* (sp += 1) */
		lua_setfield(L, -2, "__index"); /* (sp -= 1) */
		lua_pushcfunction(L, proxy_backends_len); /* (sp += 1) */
		lua_setfield(L, -2, "__len"); /* (sp -= 1) */
	}
	lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */
	lua_setfield(L, -2, "backends");

	/**
	 * proxy.multipart_backends is (mostly) read-only
	 */
	con_p = (network_mysqld_con **) (lua_newuserdata(L, sizeof (con)));
	*con_p = con;

	/* if the meta-table is new, add __index to it */
	if (1 == luaL_newmetatable(L, "proxy.multiparts")) {
		lua_pushcfunction(L, multiparts_get); /* (sp += 1) */
		lua_setfield(L, -2, "__index"); /* (sp -= 1) */
		lua_pushcfunction(L, multiparts_set); /* (sp += 1) */
		lua_setfield(L, -2, "__newindex"); /* (sp -= 1) */
		lua_pushcfunction(L, multiparts_len); /* (sp += 1) */
		lua_setfield(L, -2, "__len"); /* (sp -= 1) */
	}
	lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */
	lua_setfield(L, -2, "multiparts");


	/**
	 * proxy.response knows 3 fields with strict types:
	 *
	 * .type = <int>
	 * .errmsg = <string>
	 * .resultset = { 
	 *   fields = { 
	 *     { type = <int>, name = <string > }, 
	 *     { ... } }, 
	 *   rows = { 
	 *     { ..., ... }, 
	 *     { ..., ... } }
	 * }
	 */
	lua_newtable(L);
#if 0
	lua_newtable(L); /* the meta-table for the response-table    (sp += 1) */
	lua_pushcfunction(L, response_get); /* (sp += 1) */
	lua_setfield(L, -2, "__index"); /* (sp -= 1) */
	lua_pushcfunction(L, response_set); /* (sp += 1) */
	lua_setfield(L, -2, "__newindex"); /* (sp -= 1) */
	lua_setmetatable(L, -2); /* tie the metatable to response    (sp -= 1) */
#endif
	lua_setfield(L, -2, "response");


	lua_pop(L, 2); /* fenv + proxy */

	return 0;
}

/**
 * handle the proxy.response.* table from the lua script
 *
 * proxy.response
 *   .type can be either ERR, OK or RAW
 *   .resultset (in case of OK)
 *     .fields
 *     .rows
 *   .errmsg (in case of ERR)
 *   .packet (in case of nil)
 *
 */
static int proxy_lua_handle_proxy_response(network_mysqld_con *con) {
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	int resp_type = 1;
	const char *str;
	size_t str_len;
	gsize i;
	lua_State *L = st->injected.L;

	/**
	 * on the stack should be the fenv of our function */
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "proxy"); /* proxy.* from the env  */
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "response"); /* proxy.response */
	if (lua_isnil(L, -1)) {
		log_info("%s.%d: proxy.response isn't set in %s", __FILE__, __LINE__,
				con->config.proxy.lua_script);

		lua_pop(L, 2); /* proxy + nil */

		return -1;
	} else if (!lua_istable(L, -1)) {
		log_info("%s.%d: proxy.response has to be a table, is %s in %s", __FILE__, __LINE__,
				lua_typename(L, lua_type(L, -1)),
				con->config.proxy.lua_script);

		lua_pop(L, 2); /* proxy + response */
		return -1;
	}

	lua_getfield(L, -1, "type"); /* proxy.response.type */
	if (lua_isnil(L, -1)) {
		/**
		 * nil is fine, we expect to get a raw packet in that case
		 */
		log_info("%s.%d: proxy.response.type isn't set in %s", __FILE__, __LINE__,
				con->config.proxy.lua_script);

		lua_pop(L, 3); /* proxy + nil */

		return -1;

	} else if (!lua_isnumber(L, -1)) {
		log_info("%s.%d: proxy.response.type has to be a number, is %s in %s", __FILE__, __LINE__,
				lua_typename(L, lua_type(L, -1)),
				con->config.proxy.lua_script);

		lua_pop(L, 3); /* proxy + response + type */

		return -1;
	} else {
		resp_type = (int) (lua_tonumber(L, -1));
	}
	lua_pop(L, 1);

	switch (resp_type) {
		case MYSQLD_PACKET_OK:
			{
				GPtrArray *fields = NULL;
				GPtrArray *rows = NULL;
				gsize field_count = 0;

				lua_getfield(L, -1, "resultset"); /* proxy.response.resultset */
				if (lua_istable(L, -1)) {
					lua_getfield(L, -1, "fields"); /* proxy.response.resultset.fields */
					g_assert(lua_istable(L, -1));

					fields = g_ptr_array_new();

					for (i = 1, field_count = 0;; i++, field_count++) {
						lua_rawgeti(L, -1, i);

						if (lua_istable(L, -1)) { /** proxy.response.resultset.fields[i] */
							MYSQL_FIELD *field;

							field = network_mysqld_proto_field_init();

							lua_getfield(L, -1, "name"); /* proxy.response.resultset.fields[].name */

							if (!lua_isstring(L, -1)) {
								field->name = g_strdup("no-field-name");

								log_warning("%s.%d: proxy.response.type = OK, "
										"but proxy.response.resultset.fields[" F_SIZE_T "].name is not a string (is %s), "
										"using default",
										__FILE__, __LINE__,
										i,
										lua_typename(L, lua_type(L, -1)));
							} else {
								field->name = g_strdup(lua_tostring(L, -1));
							}
							lua_pop(L, 1);

							lua_getfield(L, -1, "type"); /* proxy.response.resultset.fields[].type */
							if (!lua_isnumber(L, -1)) {
								log_warning("%s.%d: proxy.response.type = OK, "
										"but proxy.response.resultset.fields[" F_SIZE_T "].type is not a integer (is %s), "
										"using MYSQL_TYPE_STRING",
										__FILE__, __LINE__,
										i,
										lua_typename(L, lua_type(L, -1)));

								field->type = MYSQL_TYPE_STRING;
							} else {
								field->type = (enum_field_types) (lua_tonumber(L, -1));
							}
							lua_pop(L, 1);
							field->flags = PRI_KEY_FLAG;
							field->length = 32;
							g_ptr_array_add(fields, field);

							lua_pop(L, 1); /* pop key + value */
						} else if (lua_isnil(L, -1)) {
							lua_pop(L, 1); /* pop the nil and leave the loop */
							break;
						} else {
							log_error("(boom)");
						}
					}
					lua_pop(L, 1);

					rows = g_ptr_array_new();
					lua_getfield(L, -1, "rows"); /* proxy.response.resultset.rows */
					g_assert(lua_istable(L, -1));
					for (i = 1;; i++) {
						lua_rawgeti(L, -1, i);

						if (lua_istable(L, -1)) { /** proxy.response.resultset.rows[i] */
							GPtrArray *row;
							gsize j;

							row = g_ptr_array_new();

							/* we should have as many columns as we had fields */

							for (j = 1; j < field_count + 1; j++) {
								lua_rawgeti(L, -1, j);

								if (lua_isnil(L, -1)) {
									g_ptr_array_add(row, NULL);
								} else {
									g_ptr_array_add(row, g_strdup(lua_tostring(L, -1)));
								}

								lua_pop(L, 1);
							}

							g_ptr_array_add(rows, row);

							lua_pop(L, 1); /* pop value */
						} else if (lua_isnil(L, -1)) {
							lua_pop(L, 1); /* pop the nil and leave the loop */
							break;
						} else {
							log_error("(boom)");
						}
					}
					lua_pop(L, 1);

					network_mysqld_con_send_resultset(con->client, fields, rows);
				} else {
					guint64 affected_rows = 0;
					guint64 insert_id = 0;

					lua_getfield(L, -2, "affected_rows"); /* proxy.response.affected_rows */
					if (lua_isnumber(L, -1)) {
						affected_rows = (guint64) (lua_tonumber(L, -1));
					}
					lua_pop(L, 1);

					lua_getfield(L, -2, "insert_id"); /* proxy.response.affected_rows */
					if (lua_isnumber(L, -1)) {
						insert_id = (guint64) (lua_tonumber(L, -1));
					}
					lua_pop(L, 1);

					network_mysqld_con_send_ok_full(con->client, affected_rows, insert_id, 0x0002, 0, NULL);
				}

				/**
				 * someone should cleanup 
				 */
				if (fields) {
					network_mysqld_proto_fields_free(fields);
					fields = NULL;
				}

				if (rows) {
					for (i = 0; i < rows->len; i++) {
						GPtrArray *row = (GPtrArray *) (rows->pdata[i]);
						gsize j;

						for (j = 0; j < row->len; j++) {
							if (row->pdata[j]) g_free(row->pdata[j]);
						}

						g_ptr_array_free(row, TRUE);
					}
					g_ptr_array_free(rows, TRUE);
					rows = NULL;
				}


				lua_pop(L, 1); /* .resultset */

				break;
			}
		case MYSQLD_PACKET_ERR:
			{
				gint errorcode = ER_UNKNOWN_ERROR;
				const gchar *sqlstate = "07000"; /** let's call ourself Dynamic SQL ... 07000 is "dynamic SQL error" */

				lua_getfield(L, -1, "errcode"); /* proxy.response.errcode */
				if (lua_isnumber(L, -1)) {
					errorcode = (gint) (lua_tonumber(L, -1));
				}
				lua_pop(L, 1);

				lua_getfield(L, -1, "sqlstate"); /* proxy.response.sqlstate */
				if (lua_isnumber(L, -1)) {
					sqlstate = lua_tostring(L, -1);
				}
				lua_pop(L, 1);

				lua_getfield(L, -1, "errmsg"); /* proxy.response.errmsg */
				if (lua_isstring(L, -1)) {
					str = lua_tolstring(L, -1, &str_len);

					network_mysqld_con_send_error_full(con->client, str, str_len, errorcode, sqlstate);
				} else {
					network_mysqld_con_send_error(con->client, C("(lua) proxy.response.errmsg is nil"));
				}
				lua_pop(L, 1);

				break;
			}
		case MYSQLD_PACKET_RAW:
			/**
			 * iterate over the packet table and add each packet to the send-queue
			 */
			lua_getfield(L, -1, "packets"); /* proxy.response.packets */
			if (lua_isnil(L, -1)) {
				log_info("%s.%d: proxy.response.packets isn't set in %s", __FILE__, __LINE__,
						con->config.proxy.lua_script);

				lua_pop(L, 3 + 1); /* fenv + proxy + response + nil */

				return -1;
			} else if (!lua_istable(L, -1)) {
				log_info("%s.%d: proxy.response.packets has to be a table, is %s in %s", __FILE__, __LINE__,
						lua_typename(L, lua_type(L, -1)),
						con->config.proxy.lua_script);

				lua_pop(L, 3 + 1); /* fenv + proxy + response + packets */
				return -1;
			}

			for (i = 1;; i++) {
				lua_rawgeti(L, -1, i);

				if (lua_isstring(L, -1)) { /** proxy.response.packets[i] */
					str = lua_tolstring(L, -1, &str_len);

					network_queue_append(con->client->send_queue, str, str_len, con->client->packet_id++);

					lua_pop(L, 1); /* pop value */
				} else if (lua_isnil(L, -1)) {
					lua_pop(L, 1); /* pop the nil and leave the loop */
					break;
				} else {
					log_error("%s.%d: proxy.response.packets should be array of strings, field "F_SIZE_T" was %s",
							__FILE__, __LINE__,
							i,
							lua_typename(L, lua_type(L, -1)));
				}
			}

			lua_pop(L, 1); /* .packets */

			break;
		default:
			log_info("proxy.response.type is unknown: %d", resp_type);

			lua_pop(L, 2); /* proxy + response */

			return -1;
	}

	lua_pop(L, 2);

	return 0;
}
#endif

/**
 * turn a GTimeVal into string
 *
 * @return string in ISO notation with micro-seconds
 */
gchar * g_timeval_string(GTimeVal *t1, GString *str) {
	size_t used_len;

	g_string_set_size(str, 63);

	used_len = strftime(str->str, str->allocated_len, "%Y-%m-%d %H:%M:%S", gmtime(&t1->tv_sec));

	g_assert(used_len < str->allocated_len);
	str->len = used_len;

	g_string_append_printf(str, ".%03ld", t1->tv_usec);
	//g_string_append_printf(str, ".%06ld", t1->tv_usec);

	return str->str;
}

#ifdef HAVE_LUA_H

/**
 * parsed result set
 *
 * 
 */
typedef struct {
	GQueue *result_queue; /**< where the packets are read from */

	GPtrArray *fields; /**< the parsed fields */

	GList *rows_chunk_head; /**< pointer to the EOF packet after the fields */
	GList *row; /**< the current row */

	query_status qstat; /**< state if this query */
} proxy_resultset_t;

proxy_resultset_t *proxy_resultset_init() {
	proxy_resultset_t *res;

	res = g_new0(proxy_resultset_t, 1);

	return res;
}

void proxy_resultset_free(proxy_resultset_t *res) {
	if (!res) return;

	if (res->fields) {
		network_mysqld_proto_fields_free(res->fields);
	}

	g_free(res);
}

static int proxy_resultset_gc(lua_State *L) {
	proxy_resultset_t *res = *(proxy_resultset_t **) lua_touserdata(L, 1);

	proxy_resultset_free(res);

	return 0;
}

static int proxy_resultset_gc_light(lua_State *L) {
	proxy_resultset_t *res = *(proxy_resultset_t **) lua_touserdata(L, 1);

	g_free(res);

	return 0;
}

static int proxy_resultset_fields_len(lua_State *L) {
	GPtrArray *fields = *(GPtrArray **) luaL_checkudata(L, 1, "proxy.resultset.fields");
	lua_pushinteger(L, fields->len);
	return 1;
}

static int proxy_resultset_field_get(lua_State *L) {
	MYSQL_FIELD *field = *(MYSQL_FIELD **) luaL_checkudata(L, 1, "proxy.resultset.fields.field");
	const char *key = luaL_checkstring(L, 2);


	if (0 == strcmp(key, "type")) {
		lua_pushinteger(L, field->type);
	} else if (0 == strcmp(key, "name")) {
		lua_pushstring(L, field->name);
	} else if (0 == strcmp(key, "org_name")) {
		lua_pushstring(L, field->org_name);
	} else if (0 == strcmp(key, "org_table")) {
		lua_pushstring(L, field->org_table);
	} else if (0 == strcmp(key, "table")) {
		lua_pushstring(L, field->table);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

static int proxy_resultset_fields_get(lua_State *L) {
	GPtrArray *fields = *(GPtrArray **) luaL_checkudata(L, 1, "proxy.resultset.fields");
	MYSQL_FIELD *field;
	MYSQL_FIELD **field_p;
	int ndx = luaL_checkinteger(L, 2);

	if (ndx < 0 || ndx >= int(fields->len)) {
		lua_pushnil(L);

		return 1;
	}

	field = (MYSQL_FIELD *) (fields->pdata[ndx]);

	field_p = (MYSQL_FIELD **) (lua_newuserdata(L, sizeof (field)));
	*field_p = field;

	/* if the meta-table is new, add __index to it */
	if (1 == luaL_newmetatable(L, "proxy.resultset.fields.field")) {
		lua_pushcfunction(L, proxy_resultset_field_get); /* (sp += 1) */
		lua_setfield(L, -2, "__index"); /* (sp -= 1) */
	}

	lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */

	return 1;
}

/**
 * get the next row from the resultset
 *
 * returns a lua-table with the fields (starting at 1)
 *
 * @return 0 on error, 1 on success
 *
 */
static int proxy_resultset_rows_iter(lua_State *L) {
	proxy_resultset_t *res = *(proxy_resultset_t **) lua_touserdata(L, lua_upvalueindex(1));
	guint32 off = NET_HEADER_SIZE; /* skip the packet-len and sequence-number */
	GString *packet;
	GPtrArray *fields = res->fields;
	gsize i;

	GList *chunk = res->row;

	if (chunk == NULL) return 0;

	packet = (GString *) (chunk->data);

	/* if we find the 2nd EOF packet we are done */
	if (packet->str[off] == MYSQLD_PACKET_EOF &&
			packet->len < 10) return 0;

	/* a ERR packet instead of real rows
	 *
	 * like "explain select fld3 from t2 ignore index (fld3,not_existing)"
	 *
	 * see mysql-test/t/select.test
	 *  */
	if (packet->str[off] == MYSQLD_PACKET_ERR) {
		return 0;
	}

	lua_newtable(L);

	for (i = 0; i < fields->len; i++) {
		guint64 field_len;

		g_assert(off <= packet->len + NET_HEADER_SIZE);

		field_len = network_mysqld_proto_decode_lenenc(packet, &off);

		if (field_len == 251) { /** FIXME: use constant */
			lua_pushnil(L);

			off += 0;
		} else {
			/**
			 * FIXME: we only support fields in the row-iterator < 16M (packet-len)
			 */
			g_assert(field_len <= packet->len + NET_HEADER_SIZE);
			g_assert(off + field_len <= packet->len + NET_HEADER_SIZE);

			lua_pushlstring(L, packet->str + off, field_len);

			off += field_len;
		}

		/* lua starts its tables at 1 */
		lua_rawseti(L, -2, i + 1);
	}

	res->row = res->row->next;

	return 1;
}

/**
 * parse the result-set of the query
 *
 * @return if this is not a result-set we return -1
 */
static int parse_resultset_fields(proxy_resultset_t *res) {
	GString *packet = (GString *) (res->result_queue->head->data);
	GList *chunk;

	if (res->fields) return 0;

	switch (packet->str[NET_HEADER_SIZE]) {
		case MYSQLD_PACKET_OK:
		case MYSQLD_PACKET_ERR:
			res->qstat.query_status = packet->str[NET_HEADER_SIZE];

			return 0;
		default:
			/* OK with a resultset */
			res->qstat.query_status = MYSQLD_PACKET_OK;
			break;
	}

	/* parse the fields */
	res->fields = network_mysqld_proto_fields_init();

	if (!res->fields) return -1;

	chunk = network_mysqld_result_parse_fields(res->result_queue->head, res->fields);

	/* no result-set found */
	if (!chunk) return -1;

	/* skip the end-of-fields chunk */
	res->rows_chunk_head = chunk->next;

	return 0;
}

static int proxy_resultset_get(lua_State *L) {
	proxy_resultset_t *res = *(proxy_resultset_t **) luaL_checkudata(L, 1, "proxy.resultset");
	const char *key = luaL_checkstring(L, 2);

	if (0 == strcmp(key, "fields")) {
		GPtrArray **fields_p;

		parse_resultset_fields(res);

		if (res->fields) {
			fields_p = (GPtrArray **) (lua_newuserdata(L, sizeof (res->fields)));
			*fields_p = res->fields;

			/* if the meta-table is new, add __index to it */
			if (1 == luaL_newmetatable(L, "proxy.resultset.fields")) {
				lua_pushcfunction(L, proxy_resultset_fields_get); /* (sp += 1) */
				lua_setfield(L, -2, "__index"); /* (sp -= 1) */
				lua_pushcfunction(L, proxy_resultset_fields_len); /* (sp += 1) */
				lua_setfield(L, -2, "__len"); /* (sp -= 1) */
			}

			lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */
		} else {
			lua_pushnil(L);
		}
	} else if (0 == strcmp(key, "rows")) {
		proxy_resultset_t *rows;
		proxy_resultset_t **rows_p;

		parse_resultset_fields(res);

		if (res->rows_chunk_head) {

			rows = proxy_resultset_init();
			rows->rows_chunk_head = res->rows_chunk_head;
			rows->row = rows->rows_chunk_head;
			rows->fields = res->fields;

			/* push the parameters on the stack */
			rows_p = (proxy_resultset_t **) lua_newuserdata(L, sizeof (rows));
			*rows_p = rows;

			/* if the meta-table is new, add __index to it */
			if (1 == luaL_newmetatable(L, "proxy.resultset.light")) {
				lua_pushcfunction(L, proxy_resultset_gc_light); /* (sp += 1) */
				lua_setfield(L, -2, "__gc"); /* (sp -= 1) */
			}
			lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */

			/* return a interator */
			lua_pushcclosure(L, proxy_resultset_rows_iter, 1);
		} else {
			lua_pushnil(L);
		}
	} else if (0 == strcmp(key, "raw")) {
		GString *s = (GString *) (res->result_queue->head->data);
		lua_pushlstring(L, s->str + 4, s->len - 4);
	} else if (0 == strcmp(key, "flags")) {
		lua_newtable(L);
		lua_pushboolean(L, (res->qstat.server_status & SERVER_STATUS_IN_TRANS) != 0);
		lua_setfield(L, -2, "in_trans");

		lua_pushboolean(L, (res->qstat.server_status & SERVER_STATUS_AUTOCOMMIT) != 0);
		lua_setfield(L, -2, "auto_commit");

		lua_pushboolean(L, (res->qstat.server_status & SERVER_QUERY_NO_GOOD_INDEX_USED) != 0);
		lua_setfield(L, -2, "no_good_index_used");

		lua_pushboolean(L, (res->qstat.server_status & SERVER_QUERY_NO_INDEX_USED) != 0);
		lua_setfield(L, -2, "no_index_used");
	} else if (0 == strcmp(key, "warning_count")) {
		lua_pushinteger(L, res->qstat.warning_count);
	} else if (0 == strcmp(key, "affected_rows")) {
		/**
		 * if the query had a result-set (SELECT, ...) 
		 * affected_rows and insert_id are not valid
		 */
		if (res->qstat.was_resultset) {
			lua_pushnil(L);
		} else {
			lua_pushnumber(L, res->qstat.affected_rows);
		}
	} else if (0 == strcmp(key, "insert_id")) {
		if (res->qstat.was_resultset) {
			lua_pushnil(L);
		} else {
			lua_pushnumber(L, res->qstat.insert_id);
		}
	} else if (0 == strcmp(key, "query_status")) {
		if (0 != parse_resultset_fields(res)) {
			/* not a result-set */
			lua_pushnil(L);
		} else {
			lua_pushinteger(L, res->qstat.query_status);
		}
	} else {
		lua_pushnil(L);
	}

	return 1;
}

#if HAVE_LUA_H

static int proxy_injection_get(lua_State *L) {
	injection *inj = *(injection **) luaL_checkudata(L, 1, "proxy.injection");
	const char *key = luaL_checkstring(L, 2);

	if (0 == strcmp(key, "type")) {
		lua_pushinteger(L, inj->id); /** DEPRECATED: use "inj.id" instead */
	} else if (0 == strcmp(key, "id")) {
		lua_pushinteger(L, inj->id);
	} else if (0 == strcmp(key, "query")) {
		lua_pushlstring(L, inj->query->str, inj->query->len);
	} else if (0 == strcmp(key, "query_time")) {
		lua_pushinteger(L, (lua_Integer) (TIME_DIFF_US(inj->ts_read_query_result_first, inj->ts_read_query)));
	} else if (0 == strcmp(key, "response_time")) {
		lua_pushinteger(L, (lua_Integer) (TIME_DIFF_US(inj->ts_read_query_result_last, inj->ts_read_query)));
	} else if (0 == strcmp(key, "resultset")) {
		/* fields, rows */
		proxy_resultset_t *res;
		proxy_resultset_t **res_p;

		res_p = (proxy_resultset_t **) (lua_newuserdata(L, sizeof (res)));
		*res_p = res = proxy_resultset_init();

		res->result_queue = inj->result_queue;
		res->qstat = inj->qstat;

		/* if the meta-table is new, add __index to it */
		if (1 == luaL_newmetatable(L, "proxy.resultset")) {
			lua_pushcfunction(L, proxy_resultset_get); /* (sp += 1) */
			lua_setfield(L, -2, "__index"); /* (sp -= 1) */
			lua_pushcfunction(L, proxy_resultset_gc); /* (sp += 1) */
			lua_setfield(L, -2, "__gc"); /* (sp -= 1) */
		}

		lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */

	} else {
		log_info("%s.%d: inj[%s] ... not found", __FILE__, __LINE__, key);

		lua_pushnil(L);
	}

	return 1;
}
#endif

static proxy_stmt_ret proxy_lua_read_query_result(network_mysqld_con *con) {
#ifdef HAVE_LUA_H
	network_socket *send_sock = con->client;
#endif
	injection *inj = NULL;
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	proxy_stmt_ret ret = PROXY_NO_DECISION;

	/**
	 * check if we want to forward the statement to the client 
	 *
	 * if not, clean the send-queue 
	 */

	if (0 == st->injected.queries->length) return PROXY_NO_DECISION;

	inj = (injection *) (g_queue_pop_head(st->injected.queries));

#ifdef HAVE_LUA_H
	/* call the lua script to pick a backend
	 * */
	lua_register_callback(con);

	if (st->injected.L) {
		lua_State *L = st->injected.L;

		g_assert(lua_isfunction(L, -1));
		lua_getfenv(L, -1);
		g_assert(lua_istable(L, -1));

		lua_getfield(L, -1, "read_query_result");
		if (lua_isfunction(L, -1)) {
			injection **inj_p;
			GString *packet;

			inj_p = (injection **) (lua_newuserdata(L, sizeof (inj)));
			*inj_p = inj;

			inj->result_queue = con->client->send_queue->chunks;
			inj->qstat = st->injected.qstat;

			/* if the meta-table is new, add __index to it */
			if (1 == luaL_newmetatable(L, "proxy.injection")) {
				lua_pushcfunction(L, proxy_injection_get); /* (sp += 1) */
				lua_setfield(L, -2, "__index"); /* (sp -= 1) */
			}

			lua_setmetatable(L, -2); /* tie the metatable to the table   (sp -= 1) */

			if (lua_pcall(L, 1, 1, 0) != 0) {
				log_error("(read_query_result) %s", lua_tostring(L, -1));

				lua_pop(L, 1); /* err-msg */

				ret = PROXY_NO_DECISION;
			} else {
				if (lua_isnumber(L, -1)) {
					ret = (proxy_stmt_ret) (lua_tonumber(L, -1));
				}
				lua_pop(L, 1);
			}

			switch (ret) {
				case PROXY_SEND_RESULT:
					/**
					 * replace the result-set the server sent us 
					 */
					while ((packet = (GString *) (g_queue_pop_head(send_sock->send_queue->chunks)))) g_string_free(packet, TRUE);

					/**
					 * we are a response to the client packet, hence one packet id more 
					 */
					send_sock->packet_id++;

					if (proxy_lua_handle_proxy_response(con)) {
						/**
						 * handling proxy.response failed
						 *
						 * send a ERR packet in case there was no result-set sent yet
						 */

						if (!st->injected.sent_resultset) {
							network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
						}
					}

					/* fall through */
				case PROXY_NO_DECISION:
					if (!st->injected.sent_resultset) {
						/**
						 * make sure we send only one result-set per client-query
						 */
						st->injected.sent_resultset++;
						break;
					}
					log_warning("%s.%d: got asked to send a resultset, but ignoring it as we already have sent %d resultset(s). injection-id: %d",
							__FILE__, __LINE__,
							st->injected.sent_resultset,
							inj->id);

					st->injected.sent_resultset++;

					/* fall through */
				case PROXY_IGNORE_RESULT:
					/* trash the packets for the injection query */
					while ((packet = (GString *) (g_queue_pop_head(send_sock->send_queue->chunks)))) g_string_free(packet, TRUE);

					break;
				default:
					/* invalid return code */
					log_info("%s.%d: return-code for read_query_result() was neither PROXY_SEND_RESULT or PROXY_IGNORE_RESULT, will ignore the result",
							__FILE__, __LINE__);

					while ((packet = (GString *) (g_queue_pop_head(send_sock->send_queue->chunks)))) g_string_free(packet, TRUE);

					break;
			}

		} else if (lua_isnil(L, -1)) {
			/* no function defined, let's send the result-set */
			lua_pop(L, 1); /* pop the nil */
		} else {
			log_info("%s.%d: (network_mysqld_con_handle_proxy_resultset) got wrong type: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
			lua_pop(L, 1); /* pop the nil */
		}
		lua_pop(L, 1); /* fenv */

		g_assert(lua_isfunction(L, -1));
	}
#endif

	injection_free(inj);

	return ret;
}

#endif

/**
 * call the lua function to intercept the handshake packet
 *
 * @return PROXY_SEND_QUERY  to send the packet from the client
 *         PROXY_NO_DECISION to pass the server packet unmodified
 */
static proxy_stmt_ret proxy_lua_read_handshake(network_mysqld_con *con) {
	proxy_stmt_ret ret = PROXY_NO_DECISION; /* send what the server gave us */
#ifdef HAVE_LUA_H
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	network_socket *recv_sock = con->server;
	network_socket *send_sock = con->client;

	lua_State *L;

	/* call the lua script to pick a backend
	 * */
	lua_register_callback(con);

	if (!st->injected.L) return ret;

	L = st->injected.L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "read_handshake");
	if (lua_isfunction(L, -1)) {
		/* export
		 *
		 * every thing we know about it
		 *  */

		lua_newtable(L);

		lua_pushlstring(L, recv_sock->scramble_buf->str, recv_sock->scramble_buf->len);
		lua_setfield(L, -2, "scramble");
		lua_pushinteger(L, recv_sock->mysqld_version);
		lua_setfield(L, -2, "mysqld_version");
		lua_pushinteger(L, recv_sock->thread_id);
		lua_setfield(L, -2, "thread_id");
		lua_pushstring(L, recv_sock->addr.str);
		lua_setfield(L, -2, "server_addr");
		lua_pushstring(L, send_sock->addr.str);
		lua_setfield(L, -2, "client_addr");

		if (lua_pcall(L, 1, 1, 0) != 0) {
			log_error("(read_handshake) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = (proxy_stmt_ret) (lua_tonumber(L, -1));
			}
			lua_pop(L, 1);
		}

		switch (ret) {
			case PROXY_NO_DECISION:
				break;
			case PROXY_SEND_QUERY:
				log_warning("%s.%d: (read_handshake) return proxy.PROXY_SEND_QUERY is deprecated, use PROXY_SEND_RESULT instead",
						__FILE__, __LINE__);

				ret = PROXY_SEND_RESULT;
			case PROXY_SEND_RESULT:
				/**
				 * proxy.response.type = ERR, RAW, ...
				 */

				if (proxy_lua_handle_proxy_response(con)) {
					/**
					 * handling proxy.response failed
					 *
					 * send a ERR packet
					 */

					network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
				}

				break;
			default:
				ret = PROXY_NO_DECISION;
				break;
		}
	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		log_info("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}

/**
 * parse the hand-shake packet from the server
 *
 *
 * @note the SSL and COMPRESS flags are disabled as we can't 
 *       intercept or parse them.
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_handshake) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;
	guint off = 0;
	int maj, min, patch;
	guint16 server_cap = 0;
	guint8 server_lang = 0;
	guint16 server_status = 0;
	gchar *scramble_1, *scramble_2;

	send_sock = con->client;
	recv_sock = con->server;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE) {
		/**
		 * packet is too short, looks nasty.
		 *
		 * report an error and let the core send a error to the 
		 * client
		 */

		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		g_string_free(packet, TRUE);
		return RET_ERROR;
	}

	if (packet->str[NET_HEADER_SIZE + 0] == '\xff') {
		/* the server doesn't like us and sends a ERR packet
		 *
		 * forward it to the client */

		network_queue_append_chunk(send_sock->send_queue, packet);

		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		return RET_ERROR;
	} else if (packet->str[NET_HEADER_SIZE + 0] != '\x0a') {
		/* the server isn't 4.1+ server, send a client a ERR packet
		*/
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		network_mysqld_con_send_error(send_sock, C("unknown protocol"));

		return RET_ERROR;
	}

	/* scan for a \0 */
	for (off = NET_HEADER_SIZE + 1; packet->str[off] && off < packet->len + NET_HEADER_SIZE; off++);

	if (packet->str[off] != '\0') {
		/* the server has sent us garbage */
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		network_mysqld_con_send_error(send_sock, C("protocol 10, but version number not terminated"));

		return RET_ERROR;
	}

	if (3 != sscanf(packet->str + NET_HEADER_SIZE + 1, "%d.%d.%d%*s", &maj, &min, &patch)) {
		/* can't parse the protocol */
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		network_mysqld_con_send_error(send_sock, C("protocol 10, but version number not parsable"));

		return RET_ERROR;
	}

	/**
	 * out of range 
	 */
	if (min < 0 || min > 100 ||
			patch < 0 || patch > 100 ||
			maj < 0 || maj > 10) {
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		network_mysqld_con_send_error(send_sock, C("protocol 10, but version number out of range"));

		return RET_ERROR;
	}

	recv_sock->mysqld_version =
		maj * 10000 +
		min * 100 +
		patch;

	/* skip the \0 */
	off++;

	recv_sock->thread_id = network_mysqld_proto_get_int32(packet, &off);
	send_sock->thread_id = recv_sock->thread_id;

	/**
	 * get the scramble buf
	 *
	 * 8 byte here and some the other 12 somewhen later
	 */
	scramble_1 = network_mysqld_proto_get_string_len(packet, &off, 8);

	network_mysqld_proto_skip(packet, &off, 1);

	/* we can't sniff compressed packets nor do we support SSL */
	packet->str[off] &= ~(CLIENT_COMPRESS);
	packet->str[off] &= ~(CLIENT_SSL);

	server_cap = network_mysqld_proto_get_int16(packet, &off);

	if (server_cap & CLIENT_COMPRESS) {
		packet->str[off - 2] &= ~(CLIENT_COMPRESS);
	}

	if (server_cap & CLIENT_SSL) {
		packet->str[off - 1] &= ~(CLIENT_SSL >> 8);
	}


	server_lang = network_mysqld_proto_get_int8(packet, &off);
	server_status = network_mysqld_proto_get_int16(packet, &off);

	network_mysqld_proto_skip(packet, &off, 13);

	scramble_2 = network_mysqld_proto_get_string_len(packet, &off, 13);

	/**
	 * scramble_1 + scramble_2 == scramble
	 *
	 * a len-encoded string
	 */

	g_string_truncate(recv_sock->scramble_buf, 0);
	g_string_append_len(recv_sock->scramble_buf, scramble_1, 8);
	g_string_append_len(recv_sock->scramble_buf, scramble_2, 13);

	g_free(scramble_1);
	g_free(scramble_2);

	g_string_truncate(recv_sock->auth_handshake_packet, 0);
	g_string_append_len(recv_sock->auth_handshake_packet, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);

	switch (proxy_lua_read_handshake(con)) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_QUERY:
			/* the client overwrote and wants to send its own packet
			 * it is already in the queue */

			recv_sock->packet_len = PACKET_LEN_UNSET;
			g_string_free(packet, TRUE);
			g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

			return RET_ERROR;
		default:
			log_error("%s.%d: ...", __FILE__, __LINE__);
			break;
	}

	/*
	 * move the packets to the server queue 
	 */
	network_queue_append_chunk(send_sock->send_queue, packet);

	recv_sock->packet_len = PACKET_LEN_UNSET;
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

	/* copy the pack to the client */
	con->state = CON_STATE_SEND_HANDSHAKE;

	return RET_SUCCESS;
}

/**
 * parse the hand-shake packet from the server
 *
 *
 * @note the SSL and COMPRESS flags are disabled as we can't 
 *       intercept or parse them.
 *
 *
 * @packet:
 *		3 bytes header length
 *		1 byte packet number
 *		1 byte '0a' because? part of header?
 *		1 byte MAJOR NUMBER
 *		1 byte "."
 *		1 byte MINOR NUMBER
 *		1 byte "."
 *		1 byte PATCH NUMBER
 *		2 byte NULL TERMINATED CLIENT STRING = -community-nt0
 *		4 bytes(INT) thread_id
 *		8 bytes SCRAMBLE_1 - PASSWORD?
 *		1 bytes UNKNOWN
 *		2 bytes SERVER_CAP - CLIENT_COMPRESS/CLIENT_SSL
 *		1 byte SERVER LANGUAGE
 *		2 bytes SERVER STATUS
 *		13 bytes FILLER
 *		13 bytes SCRAMBLE_2
 *
 *	41 00 00 00 0a 35 2e 30  A . . . . 5 . 0
 *	2e 34 35 2d 63 6f 6d 6d  . 4 5 - c o m m
 *	75 6e 69 74 79 2d 6e 74  u n i t y - n t
 *	00 aa 00 00 00 76 59 39  . . . . . v Y 9
 *	51 6b 46 59 70 00 0c a2  Q k F Y p . . .
 * 	08 02 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	48 56 55 2c 75 2f 28 77  H V U , u / ( w
 *	43 27 39 29 00 			 C ' 9 ) .
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_multiserver_read_handshake) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock = NULL;
	guint off = 0;
	int maj, min, patch;
	guint16 server_cap = 0;
	guint8 server_lang = 0;
	guint16 server_status = 0;
	gchar *scramble_1, *scramble_2;

	// the first valid server that was able to connect
	// logical below will work for now, need to change later
	if ((con->server != NULL) && (con->init_ndx == DEF_MULTISERVER_DB))
		send_sock = con->client;

	recv_sock = con->server;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE) {
		/**
		 * packet is too short, looks nasty.
		 *
		 * report an error and let the core send a error to the 
		 * client
		 */

		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		return RET_ERROR;
	}

	if (packet->str[NET_HEADER_SIZE + 0] == '\xff') {
		/* the server doesn't like us and sends a ERR packet
		 *
		 * forward it to the client */

		if (send_sock)
			network_queue_append_chunk(send_sock->send_queue, packet);

		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		return RET_ERROR;

	} else if (packet->str[NET_HEADER_SIZE + 0] != '\x0a') {
		/* the server isn't 4.1+ server, send a client a ERR packet
		*/
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		if (send_sock)
			network_mysqld_con_send_error(send_sock, C("unknown protocol"));

		return RET_ERROR;
	}


	/* scan for a \0 */
	for (off = NET_HEADER_SIZE + 1; packet->str[off] && off < packet->len + NET_HEADER_SIZE; off++);

	if (packet->str[off] != '\0') {
		/* the server has sent us garbage */
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		if (send_sock)
			network_mysqld_con_send_error(send_sock, C("protocol 10, but version number not terminated"));
		return RET_ERROR;

	}

	if (3 != sscanf(packet->str + NET_HEADER_SIZE + 1, "%d.%d.%d%*s", &maj, &min, &patch)) {
		/* can't parse the protocol */
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		if (send_sock)
			network_mysqld_con_send_error(send_sock, C("protocol 10, but version number not parsable"));

		return RET_ERROR;
	}

	/**
	 * out of range 
	 */
	if (min < 0 || min > 100 ||
			patch < 0 || patch > 100 ||
			maj < 0 || maj > 10) {
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		if (send_sock)
			network_mysqld_con_send_error(send_sock, C("protocol 10, but version number out of range"));

		return RET_ERROR;
	}

	recv_sock->mysqld_version =
		maj * 10000 +
		min * 100 +
		patch;

	/* skip the \0 */
	off++;

	recv_sock->thread_id = network_mysqld_proto_get_int32(packet, &off);
	if (send_sock)
		send_sock->thread_id = recv_sock->thread_id;

	/**
	 * get the scramble buf
	 *
	 * 8 byte here and some the other 12 somewhen later
	 */
	scramble_1 = network_mysqld_proto_get_string_len(packet, &off, 8);

	network_mysqld_proto_skip(packet, &off, 1);

	/* we can't sniff compressed packets nor do we support SSL */
	packet->str[off] &= ~(CLIENT_COMPRESS);
	packet->str[off] &= ~(CLIENT_SSL);

	server_cap = network_mysqld_proto_get_int16(packet, &off);

	if (server_cap & CLIENT_COMPRESS) {
		packet->str[off - 2] &= ~(CLIENT_COMPRESS);
	}

	if (server_cap & CLIENT_SSL) {
		packet->str[off - 1] &= ~(CLIENT_SSL >> 8);
	}


	server_lang = network_mysqld_proto_get_int8(packet, &off);
	server_status = network_mysqld_proto_get_int16(packet, &off);

	network_mysqld_proto_skip(packet, &off, 13);

	scramble_2 = network_mysqld_proto_get_string_len(packet, &off, 13);

	/**
	 * scramble_1 + scramble_2 == scramble
	 *
	 * a len-encoded string
	 */

	g_string_truncate(recv_sock->scramble_buf, 0);
	g_string_append_len(recv_sock->scramble_buf, scramble_1, 8);
	g_string_append_len(recv_sock->scramble_buf, scramble_2, 13);

	g_free(scramble_1);
	g_free(scramble_2);

	g_string_truncate(recv_sock->auth_handshake_packet, 0);
	g_string_append_len(recv_sock->auth_handshake_packet, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);

	switch (proxy_lua_read_handshake(con)) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_QUERY:
			/* the client overwrote and wants to send its own packet
			 * it is already in the queue */

			recv_sock->packet_len = PACKET_LEN_UNSET;
			g_string_free(packet, TRUE);
			g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

			return RET_ERROR;
		default:
			log_error("%s.%d: ...", __FILE__, __LINE__);
			break;
	}

	/*
	 * move the packets to the server queue 
	 */
	if (send_sock)
		network_queue_append_chunk(send_sock->send_queue, packet);

	recv_sock->packet_len = PACKET_LEN_UNSET;
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

	/* copy the pack to the client */

	// don't specify a state, let the end of the for loop in the AUTH
	// state change it after all the servers have been talked to
	//con->state = CON_STATE_SEND_HANDSHAKE;

	return RET_SUCCESS;
}

#ifdef HAVE_LUA_H

static proxy_stmt_ret proxy_lua_read_auth(network_mysqld_con *con) {
	proxy_stmt_ret ret = PROXY_NO_DECISION;

	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	lua_State *L;

	/* call the lua script to pick a backend
	 * */
	lua_register_callback(con);

	if (!st->injected.L) return (proxy_stmt_ret) 0;

	L = st->injected.L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "read_auth");
	if (lua_isfunction(L, -1)) {

		/* export
		 *
		 * every thing we know about it
		 *  */

		lua_newtable(L);

		lua_pushlstring(L, con->client->username->str, con->client->username->len);
		lua_setfield(L, -2, "username");
		lua_pushlstring(L, con->client->scrambled_password->str, con->client->scrambled_password->len);
		lua_setfield(L, -2, "password");
		lua_pushlstring(L, con->client->default_db->str, con->client->default_db->len);
		lua_setfield(L, -2, "default_db");

		if (lua_pcall(L, 1, 1, 0) != 0) {
			log_error("(read_auth) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = (proxy_stmt_ret) (lua_tonumber(L, -1));
			}
			lua_pop(L, 1);
		}

		switch (ret) {
			case PROXY_NO_DECISION:
				break;
			case PROXY_SEND_RESULT:
				/* answer directly */

				con->client->packet_id++;

				if (proxy_lua_handle_proxy_response(con)) {
					/**
					 * handling proxy.response failed
					 *
					 * send a ERR packet
					 */

					network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
				}

				break;
			default:
				ret = PROXY_NO_DECISION;
				break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		log_info("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
	return ret;
}
#endif

typedef struct {
	guint32 client_flags;
	guint32 max_packet_size;
	guint8 charset_number;
	gchar * user;
	gchar * scramble_buf;
	gchar * db_name;
} mysql_packet_auth;

void dump_str(const char *msg, const unsigned char *s, size_t len);
/*
 *
 *	Result Format:
 *		4 byte CLIENT_FLAGS
 *		4 byte PACKET LENGTH
 *		1 byte CHARSET
 *		23 byte UNKNOWN
 *		N bytes USERNAME
 *		N bytes SCRAMBLED PASSOWRD	
 *(opt) N bytes DEFAULT_DB
 *  
 *
 *  Example:
 *	38 00 00 01 85 a6 03 00  8 . . . . . . .
 *	00 00 00 01 08 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 73 61 00 14  . . . . s a . .
 *	4b 0c 15 84 3e b0 b0 d6  K . . . > . . .
 *	66 eb 04 47 0d 68 a1 df  f . . G . h . .
 * 	84 5f 09 98  . _ . .
 *
 */

/*
 * CON_STATE_SEND_AUTH
 *
 *	Result Format:
 *		4 byte CLIENT_FLAGS
 *		4 byte PACKET LENGTH
 *		1 byte CHARSET
 *		23 byte UNKNOWN
 *		N bytes USERNAME
 *		N bytes SCRAMBLED PASSOWRD	
 *(opt) N bytes DEFAULT_DB
 *  
 *
 *  Example:
 *	3d 00 00 01 8d a6 03 00  = . . . . . . .
 *	00 00 00 01 08 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 73 61 00 14  . . . . s a . .
 *	ff b1 af e8 4c a3 f9 13  . . . . L . . .
 *	33 28 2c 89 34 45 13 14  3 ( , . 4 E . .
 *	fb 2b 1f bd 74 65 73 74  . + ^_ . t e s t
 *	00  					 .
 *
 */




static proxy_stmt_ret proxy_lua_read_auth_result(network_mysqld_con *con) {
	proxy_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	network_socket *recv_sock = con->server;
	GList *chunk = recv_sock->recv_queue->chunks->tail;
	GString *packet = (GString *) (chunk->data);
	lua_State *L;

	/* call the lua script to pick a backend
	 * */
	lua_register_callback(con);

	if (!st->injected.L) return (proxy_stmt_ret) 0;

	L = st->injected.L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "read_auth_result");
	if (lua_isfunction(L, -1)) {

		/* export
		 *
		 * every thing we know about it
		 *  */

		lua_newtable(L);

		lua_pushlstring(L, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);
		lua_setfield(L, -2, "packet");

		if (lua_pcall(L, 1, 1, 0) != 0) {
			log_error("(read_auth_result) %s", lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = (proxy_stmt_ret) (lua_tonumber(L, -1));
			}
			lua_pop(L, 1);
		}

		switch (ret) {
			case PROXY_NO_DECISION:
				break;
			case PROXY_SEND_RESULT:
				/* answer directly */

				if (proxy_lua_handle_proxy_response(con)) {
					/**
					 * handling proxy.response failed
					 *
					 * send a ERR packet
					 */

					network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
				}

				break;
			default:
				ret = PROXY_NO_DECISION;
				break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		log_info("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_auth_result) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;

	recv_sock = con->server;
	send_sock = con->client;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	/* we aren't finished yet */
	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE) return RET_SUCCESS;

	/* send the auth result to the client */
	if (con->server->is_authed) {
		/**
		 * we injected a COM_CHANGE_USER above and have to correct to 
		 * packet-id now 
		 */
		packet->str[3] = 2;
	}

	/**
	 * copy the 
	 * - default-db, 
	 * - username, 
	 * - scrambed_password
	 *
	 * to the server-side 
	 */
	g_string_truncate(recv_sock->username, 0);
	g_string_append_len(recv_sock->username, send_sock->username->str, send_sock->username->len);
	g_string_truncate(recv_sock->default_db, 0);
	g_string_append_len(recv_sock->default_db, send_sock->default_db->str, send_sock->default_db->len);
	g_string_truncate(recv_sock->scrambled_password, 0);
	g_string_append_len(recv_sock->scrambled_password, send_sock->scrambled_password->str, send_sock->scrambled_password->len);

	/**
	 * recv_sock still points to the old backend that
	 * we received the packet from. 
	 *
	 * backend_ndx = 0 might have reset con->server
	 */

	switch (proxy_lua_read_auth_result(con)) {
		case PROXY_SEND_RESULT:
			/**
			 * we already have content in the send-sock 
			 *
			 * chunk->packet is not forwarded, free it
			 */

			g_string_free(packet, TRUE);

			break;
		case PROXY_NO_DECISION:
			network_queue_append_chunk(send_sock->send_queue, packet);

			break;
		default:
			g_string_free(packet, TRUE);
			log_error("%s.%d: ... ", __FILE__, __LINE__);
			break;
	}

	/**
	 * we handled the packet on the server side, free it
	 */
	recv_sock->packet_len = PACKET_LEN_UNSET;
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

	con->state = CON_STATE_SEND_AUTH_RESULT;

	return RET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_multiserver_read_auth_result) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;
	int ret;
	int i;

	recv_sock = con->server;
	send_sock = con->client;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	/* we aren't finished yet */
	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE) return RET_SUCCESS;

	/* send the auth result to the client */
	if (con->server->is_authed) {
		/**
		 * we injected a COM_CHANGE_USER above and have to correct to 
		 * packet-id now 
		 */
		packet->str[3] = 2;
	}

	/**
	 * copy the 
	 * - default-db, 
	 * - username, 
	 * - scrambed_password
	 *
	 * to the server-side 
	 */
	g_string_truncate(recv_sock->username, 0);
	g_string_append_len(recv_sock->username, send_sock->username->str, send_sock->username->len);
	g_string_truncate(recv_sock->default_db, 0);
	g_string_append_len(recv_sock->default_db, send_sock->default_db->str, send_sock->default_db->len);
	g_string_truncate(recv_sock->scrambled_password, 0);
	g_string_append_len(recv_sock->scrambled_password, send_sock->scrambled_password->str, send_sock->scrambled_password->len);

	/*
	   at this point we should make sure to determine if there are multiple
	   servers that need to be added to the connection pool
	   */
	for (i = 1; i < int(con->pending_conn_server->len); i++) {
		// set the default backend state
		msbackend_switch_def_server(con, i);

		// should probably determine if the server actually connected
		// succesfully before attempting to add it
		proxy_connection_pool_add_connection(con);
	}

	// set the default
	msbackend_switch_def_server(con, 0);

	/**
	 * recv_sock still points to the old backend that
	 * we received the packet from. 
	 *
	 * backend_ndx = 0 might have reset con->server
	 */

	switch ((ret = proxy_lua_read_auth_result(con))) {
		case PROXY_SEND_RESULT:
			/**
			 * we already have content in the send-sock 
			 *
			 * chunk->packet is not forwarded, free it
			 */

			g_string_free(packet, TRUE);
			break;
		case PROXY_NO_DECISION:
			network_queue_append_chunk(send_sock->send_queue, packet);
			break;
		default:
			g_string_free(packet, TRUE);
			log_error("%s.%d: read_auth_result error...%d", __FILE__, __LINE__, ret);
			break;
	}

	/**
	 * we handled the packet on the server side, free it
	 */
	recv_sock->packet_len = PACKET_LEN_UNSET;
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

	//	con->state = CON_STATE_SEND_AUTH_RESULT;

	return RET_SUCCESS;
}

#ifdef HAVE_LUA_H

static proxy_stmt_ret proxy_lua_read_query(network_mysqld_con *con) {
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	char command = -1;
	injection *inj;
	network_socket *recv_sock = con->client;
	GList *chunk = recv_sock->recv_queue->chunks->head;
	GString *packet = (GString *) (chunk->data);

	if (!con->config.proxy.profiling) return PROXY_SEND_QUERY;

	if (packet->len < NET_HEADER_SIZE) return PROXY_SEND_QUERY; /* packet too short */

	command = packet->str[NET_HEADER_SIZE + 0];

	if (COM_QUERY == command) {
		/* we need some more data after the COM_QUERY */
		if (packet->len < NET_HEADER_SIZE + 2) return PROXY_SEND_QUERY;

		/* LOAD DATA INFILE is nasty */
		if (packet->len - NET_HEADER_SIZE - 1 >= sizeof ("LOAD ") - 1 &&
				0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("LOAD "))) return PROXY_SEND_QUERY;

		/* don't cover them with injected queries as it trashes the result */
		if (packet->len - NET_HEADER_SIZE - 1 >= sizeof ("SHOW ERRORS") - 1 &&
				0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("SHOW ERRORS"))) return PROXY_SEND_QUERY;
		if (packet->len - NET_HEADER_SIZE - 1 >= sizeof ("select @@error_count") - 1 &&
				0 == g_ascii_strncasecmp(packet->str + NET_HEADER_SIZE + 1, C("select @@error_count"))) return PROXY_SEND_QUERY;

	}

	/* reset the query status */
	memset(&(st->injected.qstat), 0, sizeof (st->injected.qstat));

	while ((inj = (injection *) (g_queue_pop_head(st->injected.queries)))) injection_free(inj);

	/* ok, here we go */

#ifdef HAVE_LUA_H
	lua_register_callback(con);

	if (st->injected.L) {
		lua_State *L = st->injected.L;
		proxy_stmt_ret ret = PROXY_NO_DECISION;

		g_assert(lua_isfunction(L, -1));
		lua_getfenv(L, -1);
		g_assert(lua_istable(L, -1));

		/**
		 * reset proxy.response to a empty table 
		 */
		lua_getfield(L, -1, "proxy");
		g_assert(lua_istable(L, -1));

		lua_newtable(L);
		lua_setfield(L, -2, "response");

		lua_pop(L, 1);

		/**
		 * get the call back
		 */
		lua_getfield(L, -1, "read_query");
		if (lua_isfunction(L, -1)) {

			/* pass the packet as parameter */
			lua_pushlstring(L, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);

			if (lua_pcall(L, 1, 1, 0) != 0) {
				/* hmm, the query failed */
				log_error("(read_query) %s", lua_tostring(L, -1));

				lua_pop(L, 2); /* fenv + errmsg */

				/* perhaps we should clean up ?*/

				return PROXY_SEND_QUERY;
			} else {
				if (lua_isnumber(L, -1)) {
					ret = (proxy_stmt_ret) (lua_tonumber(L, -1));
				}
				lua_pop(L, 1);
			}

			switch (ret) {
				case PROXY_SEND_RESULT:
					/* check the proxy.response table for content,
					 *
					 */

					con->client->packet_id++;

					if (proxy_lua_handle_proxy_response(con)) {
						/**
						 * handling proxy.response failed
						 *
						 * send a ERR packet
						 */

						network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
					}

					break;
				case PROXY_NO_DECISION:
					/**
					 * PROXY_NO_DECISION and PROXY_SEND_QUERY may pick another backend
					 */
					break;
				case PROXY_SEND_QUERY:
					/* send the injected queries
					 *
					 * injection_init(..., query);
					 * 
					 *  */

					if (st->injected.queries->length) {
						ret = PROXY_SEND_INJECTION;
					}

					break;
				default:
					break;
			}
			lua_pop(L, 1); /* fenv */
		} else {
			lua_pop(L, 2); /* fenv + nil */
		}

		g_assert(lua_isfunction(L, -1));

		if (ret != PROXY_NO_DECISION) {
			return ret;
		}
	}
#endif
	return PROXY_NO_DECISION;
}

#endif

/**
 * gets called after a query has been read
 *
 * does nothing, process the get_server_list later so that it can be
 * called as a reentrant method
 *
 * @see 
 */

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query) {
	con->state = CON_STATE_PROCESS_READ_QUERY;
	return RET_SUCCESS;
}

void free_gstring_ptr_array(GPtrArray *array) {
	if (array == NULL)
		return;

	for (size_t idx = 0; idx < array->len; idx++) {
		g_string_free((GString *) (array->pdata[idx]), TRUE);
	}

	g_ptr_array_free(array, TRUE);
}

/**
 * gets called to process the SQL query to determine which database to
 * send the request to.  The connection pool may not be ready so the 
 * function will return a retry code for the caller to try again.
 *
 * @see 
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_get_server_list) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);

	send_sock = NULL;
	recv_sock = con->client;
	st->injected.sent_resultset = 0;

	chunk = recv_sock->recv_queue->chunks->head;

	if (recv_sock->recv_queue->chunks->length != 1) {
		log_warning("%s.%d: client-recv-queue-len = %d", __FILE__, __LINE__, recv_sock->recv_queue->chunks->length);
	}

	packet = (GString *) (chunk->data);

	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE)
		return RET_SUCCESS;

	con->parse.len = recv_sock->packet_len;

	// reset the default server object
	con->server = NULL;

	free_gstring_ptr_array(con->server_hostnames);
	con->server_hostnames = NULL;

	// fetch the command type
	con->parse.command = (enum_server_command) (packet->str[NET_HEADER_SIZE + 0]);

	//for debug info
	const char* command_names[] = {
		"COM_SLEEP",
		"COM_QUIT",
		"COM_INIT_DB",
		"COM_QUERY",
		"COM_FIELD_LIST",
		"COM_CREATE_DB",
		"COM_DROP_DB",
		"COM_REFRESH",
		"COM_SHUTDOWN",
		"COM_STATISTICS",
		"COM_PROCESS_INFO",
		"COM_CONNECT",
		"COM_PROCESS_KILL",
		"COM_DEBUG",
		"COM_PING",
		"COM_TIME",
		"COM_DELAYED_INSERT",
		"COM_CHANGE_USER",
		"COM_BINLOG_DUMP",
		"COM_TABLE_DUMP",
		"COM_CONNECT_OUT",
		"COM_REGISTER_SLAVE",
		"COM_STMT_PREPARE",
		"COM_STMT_EXECUTE",
		"COM_STMT_SEND_LONG_DATA",
		"COM_STMT_CLOSE",
		"COM_STMT_RESET",
		"COM_SET_OPTION",
		"COM_STMT_FETCH",
		"COM_DAEMON",
		/* don't forget to update const char *command_name[] in sql_parse.cc */
		/* Must be last */
		"COM_END"
	};

	if (get_config_log_all_queries() || get_config_log_debug_msgs()) {
		log_info("SOCKET=%d: query type=%s, len=%d, SQL=[%s].",
				con->client->fd,
				command_names[con->parse.command],
				packet->len - NET_HEADER_SIZE - 1,
				packet->str + NET_HEADER_SIZE + 1);
	}

	db_lookup_retval_t ret = database_lookup_from_sql(con->parse.command,con->sql_tokens, &(con->server_hostnames), packet, &(con->tx_level),con->parseMaster);

	if (ret == RET_ERROR_UNPARSABLE || ret == RET_DB_LOOKUP_ERROR) {
		network_mysqld_con_send_error_full(
				con->client,
				"invalid syntax, unable to parse sql statement",
				45,
				ER_NO_DB_ERROR,
				get_sql_state(ER_NO_DB_ERROR));

		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		return RET_ERROR;
	}

	return RET_SUCCESS;
}

/**
 * get server connection list from the backend server pool, if not all
 * the connections are available, RET_WAIT_FOR_EVENT is returned, we should
 * create more backend connections and try again.
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_get_server_connection_list) {
	network_socket *recv_sock = con->client;
	GList *chunk = recv_sock->recv_queue->chunks->head;
	GString *packet = (GString *) (chunk->data);
        GString *packet_old = g_string_new_len(packet->str,packet->len);

	/*
	   at this point we should have a list of server hostnames that we
	   need to lookup the databases to send the request to
	   */
	if (!proxy_add_server_connection_array(
				srv,
				con,
				con->server_hostnames,
				packet)) {
		log_warning("%s.%d: we ran out of connections, try again later",
				__FILE__, __LINE__);

		// if we can not get all the needed connections,
		// release all aquired back to the pool to avoid deadlock
		//
		proxy_cache_server_connections(srv, con);
		return RET_WAIT_FOR_EVENT; // try again after some time
                //return RET_ERROR;//dqm close
	}

	// now add the request to all the servers send_queue
	for (size_t i = 0; i < con->servers->len; i++) {
		MULTIPART_DATA *pmd = pmd_select(con, i);

		log_debug("SOCKET=%d: sending query to server SOCKET=%d(remote=%s:%s), "
				"%d servers in total.\n",
				recv_sock->fd, pmd->server->fd,
				pmd->server->addr.str, pmd->server->default_db->str,
				con->servers->len);
		if (pmd->tableidx >= 0) {
			int len = getTableIdx(packet->str + NET_HEADER_SIZE + 1);
			char *temp = new char[10];
			sprintf(temp, "_%d", pmd->tableidx);
			g_string_insert(packet, NET_HEADER_SIZE + 1 + len, temp);
			packet->str[0] += strlen(temp);
			delete temp;
		} else if (pmd->tableidx == -1) {
			int len = getTableIdx(packet->str + NET_HEADER_SIZE + 1);
			char *temp = new char[10];
			sprintf(temp, "_%d", i);
			g_string_insert(packet, NET_HEADER_SIZE + 1 + len, temp);
			packet->str[0] += strlen(temp);
			delete temp;
		}

		// create a copy of the packet
		GString *srv_packet = g_string_new(NULL);
		g_string_append_len(srv_packet, packet->str, packet->len);

		// add the copy to the send_queue
		network_queue_append_chunk(pmd->server->send_queue, srv_packet);

		// replicate the command
		pmd->server->parse.command = con->parse.command;

		/* keep track of the packet_id */
		//send_sock->packet_id = recv_sock->packet_id;
		//

		if (pmd->sql != NULL)
			g_string_free(pmd->sql, TRUE);

		if (packet != NULL)
			pmd->sql = g_string_new(packet->str + NET_HEADER_SIZE + 1);


		// reset the server object (probably make this a function)
		pmd->server->rw.state = NET_RW_STATE_NONE;
		pmd->server->rw.read_after_write = 0;
		pmd->server->rw.write_count = 0;
		pmd->server->bytes_recved = 0;
		g_string_truncate(packet, 0);
		g_string_append_len(packet, packet_old->str, packet_old->len);
	}
        g_string_free(packet_old,TRUE);
	// set the 'default' database con->server
	if (pmd_cnt(con) > 0)
		con->server = (pmd_select(con, 0))->server;
	else
		log_debug("%s.%d: unknown connection issue", __FILE__, __LINE__);

	// reset the recv_queue
	recv_sock->packet_len = PACKET_LEN_UNSET;
	//log_debug("%p: free recv queue %p", packet);
	g_string_free(packet, TRUE);
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);


	return RET_SUCCESS;
}

/**
 * decide about the next state after the result-set has been written 
 * to the client
 * 
 * if we still have data in the queue, back to proxy_send_query()
 * otherwise back to proxy_read_query() to pick up a new client query
 *
 * @note we should only send one result back to the client
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_send_query_result) {
	network_socket *recv_sock, *send_sock;
	injection *inj;
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);

	log_debug("%s.%d SOCKET=%d: in proxy_send_query_result plugin.\n",
			__FILE__, __LINE__, con->client ? con->client->fd : 0);

	send_sock = con->server;
	recv_sock = con->client;

	if (con->parse.command == COM_BINLOG_DUMP) {
		/**
		 * the binlog dump is different as it doesn't have END packet
		 *
		 * FIXME: in 5.0.x a NON_BLOCKING option as added which sends a EOF
		 */
		con->state = CON_STATE_READ_QUERY_RESULT;

		return RET_SUCCESS;
	}

	if (st->injected.queries->length == 0) {
		con->state = CON_STATE_READ_QUERY;

		return RET_SUCCESS;
	}

	con->parse.len = recv_sock->packet_len;

	inj = (injection *) (g_queue_peek_head(st->injected.queries));

	network_queue_append(send_sock->send_queue, inj->query->str, inj->query->len, 0);

	con->state = CON_STATE_SEND_QUERY;

	return RET_SUCCESS;
}

/**
 * handle the query-result we received from the server
 *
 * - decode the result-set to track if we are finished already
 * - handles BUG#25371 if requested
 * - if the packet is finished, calls the network_mysqld_con_handle_proxy_resultset
 *   to handle the resultset in the lua-scripts
 *
 * @see network_mysqld_con_handle_proxy_resultset
 */
int proxy_read_query_result_is_finished(network_socket *recv_sock, int *is_finished) {
	GString *packet;
	GList *chunk;

	*is_finished = 0;

	chunk = recv_sock->recv_queue->chunks->tail;

	if (chunk == NULL)
		return RET_SUCCESS;

	packet = (GString *) (chunk->data);

	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE)
		return RET_SUCCESS;

	switch (recv_sock->parse.command) {
		case COM_CHANGE_USER:
			{
				/**
				 * - OK
				 * - ERR (in 5.1.12+ + a duplicate ERR)
				 */
				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_ERR:
						if (recv_sock->mysqld_version > 50113 &&
								recv_sock->mysqld_version < 50118) {
							/**
							 * Bug #25371
							 *
							 * COM_CHANGE_USER returns 2 ERR packets instead of one we can 
							 * auto-correct the issue if needed and remove the second packet
							 * Some clients handle this issue and expect a double ERR packet.
							 */
							if (recv_sock->packet_id == 2) {
								*is_finished = 1;
							}
						} else {
							*is_finished = 1;
						}
						break;
					case MYSQLD_PACKET_OK:
						*is_finished = 1;
						break;
					default:
						log_error("%s.%d: COM_(0x%02x) should be (ERR|OK), got %02x",
								__FILE__, __LINE__,
								recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
						break;
				}
				break;
			}
		case COM_INIT_DB:
			{
				/**
				 * in case we have a init-db statement we track the db-change on 
				 * the server-side connection
				 */
				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_ERR:
						*is_finished = 1;
						break;
					case MYSQLD_PACKET_OK:
						/** track the change of the init_db */
						g_string_truncate(recv_sock->default_db, 0);
						//g_string_truncate(recv_sock->client->default_db, 0);
						if (recv_sock->parse.state.init_db.db_name->len) {
							g_string_append_len(
									recv_sock->default_db,
									recv_sock->parse.state.init_db.db_name->str,
									recv_sock->parse.state.init_db.db_name->len);

						}

						*is_finished = 1;
						break;
					default:
						log_error("%s.%d: COM_(0x%02x) should be (ERR|OK), got %02x",
								__FILE__, __LINE__,
								recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
						break;
				}
				break;
			}
		case COM_STMT_RESET:
		case COM_PING:
		case COM_PROCESS_KILL:
			{
				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_ERR:
					case MYSQLD_PACKET_OK:
						*is_finished = 1;
						break;
					default:
						log_error("%s.%d: COM_(0x%02x) should be (ERR|OK), got %02x",
								__FILE__, __LINE__,
								recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
						break;
				}
				break;
			}
		case COM_DEBUG:
		case COM_SET_OPTION:
		case COM_SHUTDOWN:
			{
				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_EOF:
						*is_finished = 1;
						break;
					default:
						log_error("%s.%d: COM_(0x%02x) should be EOF, got %02x",
								__FILE__, __LINE__,
								recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
						break;
				}
				break;
			}
		case COM_FIELD_LIST:
			{
				/* we transfer some data and wait for the EOF */
				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_ERR:
					case MYSQLD_PACKET_EOF:
						*is_finished = 1;
						break;
					case MYSQLD_PACKET_NULL:
					case MYSQLD_PACKET_OK:
						log_error("%s.%d: COM_(0x%02x), packet %d should not be (OK|ERR|NULL), got: %02x",
								__FILE__, __LINE__,
								recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);

						break;
					default:
						break;
				}
				break;
			}
#if MYSQL_VERSION_ID >= 50000
		case COM_STMT_FETCH:
			{
				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_EOF:
						if (packet->str[NET_HEADER_SIZE + 3] & SERVER_STATUS_LAST_ROW_SENT) {
							*is_finished = 1;
						}
						if (packet->str[NET_HEADER_SIZE + 3] & SERVER_STATUS_CURSOR_EXISTS) {
							*is_finished = 1;
						}
						break;
					default:
						break;
				}
				break;
#endif
			}
		case COM_QUIT: /* sometimes we get a packet before the connection closes */
		case COM_STATISTICS:
			{
				/* just one packet, no EOF */
				*is_finished = 1;
				break;
			}
		case COM_STMT_PREPARE:
			{
				if (recv_sock->parse.state.prepare.first_packet == 1) {
					recv_sock->parse.state.prepare.first_packet = 0;

					switch (packet->str[NET_HEADER_SIZE + 0]) {
						case MYSQLD_PACKET_OK:
							g_assert(packet->len == 12 + NET_HEADER_SIZE);

							/* the header contains the number of EOFs we expect to see
							 * - no params -> 0
							 * - params | fields -> 1
							 * - params + fields -> 2 
							 */
							recv_sock->parse.state.prepare.want_eofs = 0;

							if (packet->str[NET_HEADER_SIZE + 5] != 0 ||
									packet->str[NET_HEADER_SIZE + 6] != 0) {
								recv_sock->parse.state.prepare.want_eofs++;
							}

							if (packet->str[NET_HEADER_SIZE + 7] != 0 ||
									packet->str[NET_HEADER_SIZE + 8] != 0) {
								recv_sock->parse.state.prepare.want_eofs++;
							}

							if (recv_sock->parse.state.prepare.want_eofs == 0) {
								*is_finished = 1;
							}

							break;

						case MYSQLD_PACKET_ERR:
							*is_finished = 1;
							break;
						default:
							log_error("%s.%d: COM_(0x%02x) should either get a (OK|ERR), got %02x",
									__FILE__, __LINE__,
									recv_sock->parse.command, packet->str[NET_HEADER_SIZE + 0]);
							break;
					}
				} else {
					switch (packet->str[NET_HEADER_SIZE + 0]) {
						case MYSQLD_PACKET_OK:
						case MYSQLD_PACKET_NULL:
						case MYSQLD_PACKET_ERR:
							log_error("%s.%d: COM_(0x%02x), packet %d should not be (OK|ERR|NULL), got: %02x",
									__FILE__, __LINE__,
									recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);
							break;
						case MYSQLD_PACKET_EOF:
							if (--recv_sock->parse.state.prepare.want_eofs == 0) {
								*is_finished = 1;
							}
							break;
						default:
							break;
					}
				}

				break;
			}
		case COM_STMT_EXECUTE:
		case COM_QUERY:
			{
				/**
				 * if we get a OK in the first packet there will be no result-set
				 */
				switch (recv_sock->parse.state.query) {
					case PARSE_COM_QUERY_INIT:
						{
							switch (packet->str[NET_HEADER_SIZE + 0]) {
								case MYSQLD_PACKET_ERR: /* e.g. SELECT * FROM dual -> ERROR 1096 (HY000): No tables used */
									g_assert(recv_sock->parse.state.query == PARSE_COM_QUERY_INIT);

									*is_finished = 1;
									break;
								case MYSQLD_PACKET_OK:
									{ /* e.g. DELETE FROM tbl */
										int server_status;
										int warning_count;
										guint64 affected_rows;
										guint64 insert_id;
										GString s;

										s.str = packet->str + NET_HEADER_SIZE;
										s.len = packet->len - NET_HEADER_SIZE;

										network_mysqld_proto_decode_ok_packet(
												&s, &affected_rows, &insert_id,
												&server_status, &warning_count, NULL);

										if (server_status & SERVER_MORE_RESULTS_EXISTS) {

										} else {
											*is_finished = 1;
										}

										recv_sock->qstat.server_status = server_status;
										recv_sock->qstat.warning_count = warning_count;
										recv_sock->qstat.affected_rows = affected_rows;
										recv_sock->qstat.insert_id = insert_id;
										recv_sock->qstat.was_resultset = 0;

										break;
									}
								case MYSQLD_PACKET_NULL:
									/* OH NO, LOAD DATA INFILE :) */
									recv_sock->parse.state.query = PARSE_COM_QUERY_LOAD_DATA;
									*is_finished = 1;
									break;

								case MYSQLD_PACKET_EOF:
									log_error("%s.%d: COM_(0x%02x), packet %d should not be (NULL|EOF), got: %02x",
											__FILE__, __LINE__,
											recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);

									break;
								default:
									/* looks like a result */
									recv_sock->parse.state.query = PARSE_COM_QUERY_FIELD;
									break;
							}
							break;
						}
					case PARSE_COM_QUERY_FIELD:
						{
							switch (packet->str[NET_HEADER_SIZE + 0]) {
								case MYSQLD_PACKET_ERR:
								case MYSQLD_PACKET_OK:
								case MYSQLD_PACKET_NULL:
									log_error("%s.%d: COM_(0x%02x), packet %d should not be (OK|NULL|ERR), got: %02x",
											__FILE__, __LINE__,
											recv_sock->parse.command, recv_sock->packet_id,
											packet->str[NET_HEADER_SIZE + 0]);

									break;
								case MYSQLD_PACKET_EOF:
#if MYSQL_VERSION_ID >= 50000
									/**
									 * in 5.0 we have CURSORs which have no rows, 
									 * just a field definition
									 */
									if (packet->str[NET_HEADER_SIZE + 3] & SERVER_STATUS_CURSOR_EXISTS) {
										*is_finished = 1;
									} else {
										recv_sock->parse.state.query = PARSE_COM_QUERY_RESULT;
									}
#else
									recv_sock->parse.state.query = PARSE_COM_QUERY_RESULT;
#endif
									break;
								default:
									break;
							}
							break;
						}
					case PARSE_COM_QUERY_RESULT:
						{
							switch (packet->str[NET_HEADER_SIZE + 0]) {
								case MYSQLD_PACKET_EOF:
									if (recv_sock->packet_len < 9) {
										/* so much on the binary-length-encoding sometimes 
										 * the len-encoding is ...*/
										if (packet->str[NET_HEADER_SIZE + 3] & SERVER_MORE_RESULTS_EXISTS) {
											recv_sock->parse.state.query = PARSE_COM_QUERY_INIT;
										} else {
											*is_finished = 1;
										}

										recv_sock->qstat.server_status = packet->str[NET_HEADER_SIZE + 3] | (packet->str[NET_HEADER_SIZE + 4] >> 8);
										recv_sock->qstat.warning_count = packet->str[NET_HEADER_SIZE + 1] | (packet->str[NET_HEADER_SIZE + 2] >> 8);

										recv_sock->qstat.was_resultset = 1;
									}
									break;
								case MYSQLD_PACKET_ERR:
									/* like EXPLAIN SELECT * FROM dual; returns an error
									 * EXPLAIN SELECT 1 FROM dual; returns a result-set */
									*is_finished = 1;
									break;
								case MYSQLD_PACKET_OK:
								case MYSQLD_PACKET_NULL: /* the first field might be a NULL */
									break;
								default:
									break;
							}
							break;
						}
					case PARSE_COM_QUERY_LOAD_DATA_END_DATA:
						{
							switch (packet->str[NET_HEADER_SIZE + 0]) {
								case MYSQLD_PACKET_OK:
									*is_finished = 1;
									break;
								case MYSQLD_PACKET_NULL:
								case MYSQLD_PACKET_ERR:
								case MYSQLD_PACKET_EOF:
								default:
									log_error("%s.%d: COM_(0x%02x), packet %d should be (OK), got: %02x",
											__FILE__, __LINE__,
											recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);
									break;
							}
							break;
						}
					default:
						{
							log_error("%s.%d: unknown state in COM_(0x%02x): %d",
									__FILE__, __LINE__,
									recv_sock->parse.command,
									recv_sock->parse.state.query);
						}
				}
				break;
			}
		case COM_BINLOG_DUMP:
			{
				/**
				 * the binlog-dump event stops, forward all packets as we see them
				 * and keep the command active */
				*is_finished = 1;
				break;
			}
		default:
			log_error("%s.%d: COM_(0x%02x) is not handled",
					__FILE__, __LINE__,
					recv_sock->parse.command);
			break;
	}

	return RET_SUCCESS;
}

/**
 * handle the query-result we received from the server
 *
 * - decode the result-set to track if we are finished already
 * - handles BUG#25371 if requested
 * - if the packet is finished, calls the network_mysqld_con_handle_proxy_resultset
 *   to handle the resultset in the lua-scripts
 *
 * @see network_mysqld_con_handle_proxy_resultset
 */
NETWORK_MYSQLD_PLUGIN_PROTO(proxy_read_query_result) {
	int send_packet = 1; /* shall we forward this packet ? */
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	injection *inj = NULL;

	recv_sock = con->server;
	send_sock = con->client;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	/**
	 * check if we want to forward the statement to the client 
	 *
	 * if not, clean the send-queue 
	 */

	if (0 != st->injected.queries->length) {
		inj = (injection *) (g_queue_peek_head(st->injected.queries));
	}

	if (inj && inj->ts_read_query_result_first.tv_sec == 0) {
		/**
		 * log the time of the first received packet
		 */
		g_get_current_time(&(inj->ts_read_query_result_first));
	}

	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE)
		return RET_SUCCESS;

#if 0
	log_info("%s.%d: packet-len: %08x, packet-id: %d, command: COM_(%02x)",
			__FILE__, __LINE__,
			recv_sock->packet_len,
			recv_sock->packet_id,
			con->parse.command
			);
#endif						

#if 0
	/* forward the response to the client */
	switch (con->parse.command) {
		case COM_CHANGE_USER:
			/**
			 * - OK
			 * - ERR (in 5.1.12+ + a duplicate ERR)
			 */
			switch (packet->str[NET_HEADER_SIZE + 0]) {
				case MYSQLD_PACKET_ERR:
					if (recv_sock->mysqld_version > 50113 &&
							recv_sock->mysqld_version < 50118) {
						/**
						 * Bug #25371
						 *
						 * COM_CHANGE_USER returns 2 ERR packets instead of one we can 
						 * auto-correct the issue if needed and remove the second packet
						 * Some clients handle this issue and expect a double ERR packet.
						 */
						if (recv_sock->packet_id == 2) {
							if (con->config.proxy.fix_bug_25371) {
								send_packet = 0;
							}
							is_finished = 1;
						}
					} else {
						is_finished = 1;
					}
					break;
				case MYSQLD_PACKET_OK:
					is_finished = 1;
					break;
				default:
					log_error("%s.%d: COM_(0x%02x) should be (ERR|OK), got %02x",
							__FILE__, __LINE__,
							recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
					break;
			}
			break;

		case COM_INIT_DB:
			/**
			 * in case we have a init-db statement we track the db-change on 
			 * the server-side connection
			 */
			switch (packet->str[NET_HEADER_SIZE + 0]) {
				case MYSQLD_PACKET_ERR:
					is_finished = 1;
					break;
				case MYSQLD_PACKET_OK:
					/** track the change of the init_db */
					g_string_truncate(recv_sock->default_db, 0);
					if (con->parse.state.init_db.db_name->len) {
						g_string_append_len(
								recv_sock->server->default_db,
								recv_sock->parse.state.init_db.db_name->str,
								recv_sock->parse.state.init_db.db_name->len);
					}

					is_finished = 1;
					break;
				default:
					log_error("%s.%d: COM_(0x%02x) should be (ERR|OK), got %02x",
							__FILE__, __LINE__,
							recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
					break;
			}
			break;

		case COM_STMT_RESET:
		case COM_PING:
		case COM_PROCESS_KILL:
			switch (packet->str[NET_HEADER_SIZE + 0]) {
				case MYSQLD_PACKET_ERR:
				case MYSQLD_PACKET_OK:
					is_finished = 1;
					break;
				default:
					log_error("%s.%d: COM_(0x%02x) should be (ERR|OK), got %02x",
							__FILE__, __LINE__,
							recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
					break;
			}
			break;

		case COM_DEBUG:
		case COM_SET_OPTION:
		case COM_SHUTDOWN:
			switch (packet->str[NET_HEADER_SIZE + 0]) {
				case MYSQLD_PACKET_EOF:
					is_finished = 1;
					break;
				default:
					log_error("%s.%d: COM_(0x%02x) should be EOF, got %02x",
							__FILE__, __LINE__,
							recv_sock->parse.command, packet->str[0 + NET_HEADER_SIZE]);
					break;
			}
			break;

		case COM_FIELD_LIST:
			/* we transfer some data and wait for the EOF */
			switch (packet->str[NET_HEADER_SIZE + 0]) {
				case MYSQLD_PACKET_ERR:
				case MYSQLD_PACKET_EOF:
					is_finished = 1;
					break;
				case MYSQLD_PACKET_NULL:
				case MYSQLD_PACKET_OK:
					log_error("%s.%d: COM_(0x%02x), packet %d should not be (OK|ERR|NULL), got: %02x",
							__FILE__, __LINE__,
							recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);

					break;
				default:
					break;
			}
			break;

#if MYSQL_VERSION_ID >= 50000
		case COM_STMT_FETCH:
			switch (packet->str[NET_HEADER_SIZE + 0]) {
				case MYSQLD_PACKET_EOF:
					if (packet->str[NET_HEADER_SIZE + 3] & SERVER_STATUS_LAST_ROW_SENT) {
						is_finished = 1;
					}
					if (packet->str[NET_HEADER_SIZE + 3] & SERVER_STATUS_CURSOR_EXISTS) {
						is_finished = 1;
					}
					break;
				default:
					break;
			}
			break;
#endif
		case COM_QUIT: /* sometimes we get a packet before the connection closes */
		case COM_STATISTICS:
			/* just one packet, no EOF */
			is_finished = 1;
			break;

		case COM_STMT_PREPARE:
			if (recv_sock->parse.state.prepare.first_packet == 1) {
				recv_sock->parse.state.prepare.first_packet = 0;

				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_OK:
						g_assert(packet->len == 12 + NET_HEADER_SIZE);

						/* the header contains the number of EOFs we expect to see
						 * - no params -> 0
						 * - params | fields -> 1
						 * - params + fields -> 2 
						 */
						recv_sock->parse.state.prepare.want_eofs = 0;

						if (packet->str[NET_HEADER_SIZE + 5] != 0 ||
								packet->str[NET_HEADER_SIZE + 6] != 0) {
							recv_sock->parse.state.prepare.want_eofs++;
						}

						if (packet->str[NET_HEADER_SIZE + 7] != 0 ||
								packet->str[NET_HEADER_SIZE + 8] != 0) {
							recv_sock->parse.state.prepare.want_eofs++;
						}

						if (recv_sock->parse.state.prepare.want_eofs == 0) {
							is_finished = 1;
						}

						break;

					case MYSQLD_PACKET_ERR:
						is_finished = 1;
						break;
					default:
						log_error("%s.%d: COM_(0x%02x) should either get a (OK|ERR), got %02x",
								__FILE__, __LINE__,
								recv_sock->parse.command, packet->str[NET_HEADER_SIZE + 0]);
						break;
				}
			} else {
				switch (packet->str[NET_HEADER_SIZE + 0]) {
					case MYSQLD_PACKET_OK:
					case MYSQLD_PACKET_NULL:
					case MYSQLD_PACKET_ERR:
						log_error("%s.%d: COM_(0x%02x), packet %d should not be (OK|ERR|NULL), got: %02x",
								__FILE__, __LINE__,
								recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);
						break;
					case MYSQLD_PACKET_EOF:
						if (--recv_sock->parse.state.prepare.want_eofs == 0) {
							is_finished = 1;
						}
						break;
					default:
						break;
				}
			}

			break;
		case COM_STMT_EXECUTE:
		case COM_QUERY:
			/**
			 * if we get a OK in the first packet there will be no result-set
			 */
			switch (recv_sock->parse.state.query) {
				case PARSE_COM_QUERY_INIT:
					switch (packet->str[NET_HEADER_SIZE + 0]) {
						case MYSQLD_PACKET_ERR: /* e.g. SELECT * FROM dual -> ERROR 1096 (HY000): No tables used */
							g_assert(recv_sock->parse.state.query == PARSE_COM_QUERY_INIT);

							is_finished = 1;
							break;
						case MYSQLD_PACKET_OK:
							{ /* e.g. DELETE FROM tbl */
								int server_status;
								int warning_count;
								guint64 affected_rows;
								guint64 insert_id;
								GString s;

								s.str = packet->str + NET_HEADER_SIZE;
								s.len = packet->len - NET_HEADER_SIZE;

								network_mysqld_proto_decode_ok_packet(
										&s, &affected_rows, &insert_id,
										&server_status, &warning_count, NULL);

								if (server_status & SERVER_MORE_RESULTS_EXISTS) {

								} else {
									is_finished = 1;
								}

								recv_sock->qstat.server_status = server_status;
								recv_sock->qstat.warning_count = warning_count;
								recv_sock->qstat.affected_rows = affected_rows;
								recv_sock->qstat.insert_id = insert_id;
								recv_sock->qstat.was_resultset = 0;
								break;
							}
						case MYSQLD_PACKET_NULL:
							/* OH NO, LOAD DATA INFILE :) */
							recv_sock->parse.state.query = PARSE_COM_QUERY_LOAD_DATA;
							is_finished = 1;
							break;

						case MYSQLD_PACKET_EOF:
							log_error("%s.%d: COM_(0x%02x), packet %d should not be (NULL|EOF), got: %02x",
									__FILE__, __LINE__,
									recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);

							break;
						default:
							/* looks like a result */
							recv_sock->parse.state.query = PARSE_COM_QUERY_FIELD;
							break;
					}
					break;
				case PARSE_COM_QUERY_FIELD:
					switch (packet->str[NET_HEADER_SIZE + 0]) {
						case MYSQLD_PACKET_ERR:
						case MYSQLD_PACKET_OK:
						case MYSQLD_PACKET_NULL:
							log_error("%s.%d: COM_(0x%02x), packet %d should not be (OK|NULL|ERR), got: %02x",
									__FILE__, __LINE__,
									recv_sock->parse.command, recv_sock->packet_id,
									packet->str[NET_HEADER_SIZE + 0]);

							break;
						case MYSQLD_PACKET_EOF:
#if MYSQL_VERSION_ID >= 50000
							/**
							 * in 5.0 we have CURSORs which have no rows, 
							 * just a field definition
							 */
							if (packet->str[NET_HEADER_SIZE + 3] & SERVER_STATUS_CURSOR_EXISTS) {
								is_finished = 1;
							} else {
								recv_sock->parse.state.query = PARSE_COM_QUERY_RESULT;
							}
#else
							recv_sock->parse.state.query = PARSE_COM_QUERY_RESULT;
#endif
							break;
						default:
							break;
					}
					break;

				case PARSE_COM_QUERY_RESULT:
					switch (packet->str[NET_HEADER_SIZE + 0]) {
						case MYSQLD_PACKET_EOF:
							if (recv_sock->packet_len < 9) {
								/* so much on the binary-length-encoding sometimes 
								 * the len-encoding is ...*/
								if (packet->str[NET_HEADER_SIZE + 3] & SERVER_MORE_RESULTS_EXISTS) {
									recv_sock->parse.state.query = PARSE_COM_QUERY_INIT;
								} else {
									is_finished = 1;
								}

								recv - sock->qstat.server_status = packet->str[NET_HEADER_SIZE + 3] | (packet->str[NET_HEADER_SIZE + 4] >> 8);
								recv_sock->qstat.warning_count = packet->str[NET_HEADER_SIZE + 1] | (packet->str[NET_HEADER_SIZE + 2] >> 8);

								recv_sock->qstat.was_resultset = 1;
							}
							break;
						case MYSQLD_PACKET_ERR:
							/* like EXPLAIN SELECT * FROM dual; returns an error
							 * EXPLAIN SELECT 1 FROM dual; returns a result-set */
							is_finished = 1;
							break;
						case MYSQLD_PACKET_OK:
						case MYSQLD_PACKET_NULL: /* the first field might be a NULL */
							break;
						default:
							break;
					}
					break;
				case PARSE_COM_QUERY_LOAD_DATA_END_DATA:
					switch (packet->str[NET_HEADER_SIZE + 0]) {
						case MYSQLD_PACKET_OK:
							is_finished = 1;
							break;
						case MYSQLD_PACKET_NULL:
						case MYSQLD_PACKET_ERR:
						case MYSQLD_PACKET_EOF:
						default:
							log_error("%s.%d: COM_(0x%02x), packet %d should be (OK), got: %02x",
									__FILE__, __LINE__,
									recv_sock->parse.command, recv_sock->packet_id, packet->str[NET_HEADER_SIZE + 0]);
							break;
					}
					break;
				default:
					log_error("%s.%d: unknown state in COM_(0x%02x): %d",
							__FILE__, __LINE__,
							recv_sock->parse.command,
							recv_sock->parse.state.query);
			}
			break;

		case COM_BINLOG_DUMP:
			/**
			 * the binlog-dump event stops, forward all packets as we see them
			 * and keep the command active */
			is_finished = 1;
			break;
		default:
			log_error("%s.%d: COM_(0x%02x) is not handled",
					__FILE__, __LINE__,
					recv_sock->parse.command);
			break;
	}
#endif

	// determine if this packet should be passed on
	if (send_packet) {
		network_queue_append_chunk(send_sock->send_queue, packet);
	} else {
		if (chunk->data)
			g_string_free((GString *) (chunk->data), TRUE);
	}

	// remove the packet from the recv_queue	
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
	recv_sock->packet_len = PACKET_LEN_UNSET;

	//proxy_lua_read_query_result(con);

	/*
	 * if the send-queue is empty, we have nothing to send
	 * and can read the next query */
	if (con->client->send_queue->chunks) {
		con->state = CON_STATE_SEND_QUERY_RESULT;
	} else
		con->state = CON_STATE_READ_QUERY;

	// read more data???	
	return RET_SUCCESS;
}

#ifdef HAVE_LUA_H

/**
 * dump the content of a lua table
 */
static void proxy_lua_dumptable(lua_State *L) {
	g_assert(lua_istable(L, -1));

	lua_pushnil(L);
	while (lua_next(L, -2) != 0) {
		int t = lua_type(L, -2);

		switch (t) {
			case LUA_TSTRING:
				log_info("[%d] (string) %s", 0, lua_tostring(L, -2));
				break;
			case LUA_TBOOLEAN:
				log_info("[%d] (bool) %s", 0, lua_toboolean(L, -2) ? "true" : "false");
				break;
			case LUA_TNUMBER:
				log_info("[%d] (number) %g", 0, lua_tonumber(L, -2));
				break;
			default:
				log_info("[%d] (%s)", 0, lua_typename(L, lua_type(L, -2)));
				break;
		}
		log_info("[%d] (%s)", 0, lua_typename(L, lua_type(L, -1)));

		lua_pop(L, 1);
	}
}
#endif

#if HAVE_LUA_H

static proxy_stmt_ret proxy_lua_connect_server(network_mysqld_con *con) {
	proxy_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	lua_State *L;

	/* call the lua script to pick a backend
	 * */
	lua_register_callback(con);

	if (!st->injected.L) return (proxy_stmt_ret) 0;

	L = st->injected.L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "connect_server");
	if (lua_isfunction(L, -1)) {
		if (lua_pcall(L, 0, 1, 0) != 0) {
			log_error("%s.%d: (connect_server) %s",
					__FILE__, __LINE__,
					lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = (proxy_stmt_ret) (lua_tonumber(L, -1));
			}
			lua_pop(L, 1);
		}

		switch (ret) {
			case PROXY_NO_DECISION:
			case PROXY_IGNORE_RESULT:
				break;
			case PROXY_SEND_RESULT:
				/* answer directly */

				if (proxy_lua_handle_proxy_response(con)) {
					/**
					 * handling proxy.response failed
					 *
					 * send a ERR packet
					 */

					network_mysqld_con_send_error(con->client, C("(lua) handling proxy.response failed, check error-log"));
				}

				break;
			default:
				ret = PROXY_NO_DECISION;
				break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		log_info("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}
#endif

/**
 * initizalize the number of backend pool connection array
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
void msbackend_init(network_mysqld_con *con) {
	con->init_ndx = -1;
	con->pending_conn_server = g_ptr_array_new();
}

/**
 * clear backend pool connection array
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
void msbackend_clear(network_mysqld_con *con) {
	msbackend_free(con);
	con->init_ndx = -1;
	con->pending_conn_server = g_ptr_array_new();
}

/**
 * clear backend pool connection array
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
void msbackend_free(network_mysqld_con *con) {
	if (NULL != con->pending_conn_server) {
		size_t idx = 0;
		for (idx = 0; idx < con->pending_conn_server->len; idx++) {
			network_socket_free((network_socket *) (con->pending_conn_server->pdata[idx]));
		}
		g_ptr_array_free(con->pending_conn_server, TRUE);
	}
	con->pending_conn_server = NULL;
}

/**
 * return the number of backend pool connections
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */

int msbackend_pool_count(network_mysqld_con *con) {

	if ((NULL != con) && (NULL != con->srv->backend_pool)) {
		return con->srv->backend_pool->len;
	}
	return 0;
}

/**
 * switch the connection's state on which backend pool is being pointed to
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */

int msbackend_switch_def_server(network_mysqld_con *con, int backend_ndx) {

	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);

	if (backend_ndx > int(con->srv->backend_pool->len))
		return -1;

	st->backend_ndx = backend_ndx;
	st->backend = (backend_t *) (con->srv->backend_pool->pdata[backend_ndx]);

	con->server = (network_socket *) (con->pending_conn_server->pdata[backend_ndx]);

	if (NULL == con->server) {
		log_debug("%s.%d:switch_backend default %d missing %d",
				__FILE__, __LINE__, backend_ndx, g_hash_table_size(st->backend->pool->users));
	}

	return 0;
}

/**
 * return the number of MULTIPART data objects
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
int pmd_cnt(network_mysqld_con *con) {
	if (NULL == con->servers)
		return 0;

	return con->servers->len;
}

/**
 * select a specific MULTIPART data object and return it
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
MULTIPART_DATA *pmd_select(network_mysqld_con *con, int index) {
	int cnt = pmd_cnt(con);

	if (index >= cnt)
		return NULL;

	g_assert(con->servers->pdata != NULL);

	return (MULTIPART_DATA*) con->servers->pdata[index];
}

/**
 * select a specific MULTIPART server network object and return it's value
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
network_socket* pmd_select_server(network_mysqld_con *con, int index) {
	int cnt = pmd_cnt(con);

	if (index > cnt)
		return NULL;

	if (NULL == con->servers->pdata[index])
		return NULL;

	return ((MULTIPART_DATA*) con->servers->pdata[index])->server;
}

/**
 * initialize the MULTIPART data array with server network objects
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
int pmd_init(network_mysqld_con *con) {
	con->servers = g_ptr_array_new();
	con->cache_servers = g_ptr_array_new();
	return 0;
}

void pmd_free(MULTIPART_DATA *pmd) {
	if (pmd) {
		if (pmd->server != NULL)
			network_socket_free(pmd->server);

		if (pmd->sql != NULL)
			g_string_free(pmd->sql, TRUE);

		g_free(pmd);
	}
}

/**
 * pmd_clear clears the MULTIPART array
 *
 * @return
 *   RET_SUCCESS        - 
 *   RET_ERROR          - 
 */
int pmd_clear(network_mysqld_con *con) {
	//plugin_con_state *st = (plugin_con_state *)(con->plugin_con_state);
	int cnt = pmd_cnt(con);
	int i;
	MULTIPART_DATA *pmd = NULL;

	for (i = 0; i < cnt; i++) {
		pmd = (MULTIPART_DATA *) (con->servers->pdata[i]);
		g_assert(pmd != NULL);

		pmd_free(pmd);
	}

	g_ptr_array_free(con->servers, TRUE);
	con->servers = g_ptr_array_new();
	con->cache_servers = g_ptr_array_new();
	return 0;
}

static plugin_srv_state *plugin_srv_state_get(network_mysqld *srv) {
	static plugin_srv_state *global_state = NULL;

	/**
	 * the global pool is started once 
	 */

	if (global_state) return global_state;
	/* if srv is not set, return the old global-state (used at shutdown) */
	if (!srv) return global_state;

	global_state = plugin_srv_state_init();
	global_state->init = 1;

#ifdef _OLD_CMD_LINE_CFG_
	/* init the pool */
	for (i = 0; srv->config.proxy.backend_addresses[i]; i++) {
		backend_t *backend;
		gchar *address = srv->config.proxy.backend_addresses[i];

		backend = backend_init();
		backend->type = BACKEND_TYPE_RW;

		backend->config = g_new0(backend_config, 1);
		backend->config->address = g_string_new(address);
		backend->config->default_username = g_string_new(NULL);
		g_string_append(backend->config->default_username, "sa");
		backend->config->default_password = g_string_new(NULL);
		g_string_append_len(backend->config->default_password, "1234", 5);
		backend->config->default_db = g_string_new(NULL);
		g_string_append(backend->config->default_db, "test");
		backend->config->client_flags = DEFAULT_FLAGS;
		backend->config->charset = DEFAULT_CHARSET;
		backend->config->max_conn_pool = get_config_max_conn_pool_size();

		backend->pending_dbconn = g_ptr_array_new();

		if (0 != network_mysqld_con_set_address(&backend->addr, address)) {
			return NULL;
		}

		g_ptr_array_add(srv->backend_pool, backend);
	}

#endif

	return global_state;
}


retval_t proxy_create_handshake(network_mysqld *srv, network_mysqld_con *con);

NETWORK_MYSQLD_PLUGIN_PROTO_GLOBAL(proxy_init) {
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	int ret;

	g_assert(con->plugin_con_state == NULL);

	st = plugin_con_state_init();

	if (NULL == (st->global_state = plugin_srv_state_get(srv))) {
		return RET_ERROR;
	}

	con->plugin_con_state = st;

	if (RET_SUCCESS != (ret = proxy_create_handshake(srv, con))) {
		con->state = CON_STATE_ERROR;
		return (retval_t) ret;
	}

	con->state = CON_STATE_SEND_HANDSHAKE;

	return RET_SUCCESS;
}

static proxy_stmt_ret proxy_lua_disconnect_client(network_mysqld_con *con) {
	proxy_stmt_ret ret = PROXY_NO_DECISION;

#ifdef HAVE_LUA_H
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	lua_State *L;

	/* call the lua script to pick a backend
	 * */
	lua_register_callback(con);

	if (!st->injected.L) return proxy_stmt_ret(0);

	L = st->injected.L;

	g_assert(lua_isfunction(L, -1));
	lua_getfenv(L, -1);
	g_assert(lua_istable(L, -1));

	lua_getfield(L, -1, "disconnect_client");
	if (lua_isfunction(L, -1)) {
		if (lua_pcall(L, 0, 1, 0) != 0) {
			log_error("%s.%d: (disconnect_client) %s",
					__FILE__, __LINE__,
					lua_tostring(L, -1));

			lua_pop(L, 1); /* errmsg */

			/* the script failed, but we have a useful default */
		} else {
			if (lua_isnumber(L, -1)) {
				ret = (proxy_stmt_ret) (lua_tonumber(L, -1));
			}
			lua_pop(L, 1);
		}

		switch (ret) {
			case PROXY_NO_DECISION:
			case PROXY_IGNORE_RESULT:
				break;
			default:
				ret = PROXY_NO_DECISION;
				break;
		}

		/* ret should be a index into */

	} else if (lua_isnil(L, -1)) {
		lua_pop(L, 1); /* pop the nil */
	} else {
		log_info("%s.%d: %s", __FILE__, __LINE__, lua_typename(L, lua_type(L, -1)));
		lua_pop(L, 1); /* pop the ... */
	}
	lua_pop(L, 1); /* fenv */

	g_assert(lua_isfunction(L, -1));
#endif
	return ret;
}

int proxy_connection_pool_del_con(network_mysqld *srv, network_socket *con) {
	backend_t *backend = NULL;

	/* con-server is already disconnected, get out */
	if (!con)
		return 0;

	log_debug("%s.%d remove_pool_con server = %s",
			__FILE__, __LINE__, con->addr.str);

	// find the pool the socket is associated to
	for (size_t i = 0; i < srv->backend_pool->len; i++) {
		backend = (backend_t *) (srv->backend_pool->pdata[i]);

		if ((strcmp(backend->addr.str, con->addr.str) == 0) &&
				(strcmp(backend->config->default_db->str, con->default_db->str) == 0)) {
			break;
		}
		backend = NULL;
	}

	if (backend == NULL) {
		log_debug("%s.%d can't find pool for server = %s",
				__FILE__, __LINE__, con->addr.str);
		return 0;
	}


	g_assert(backend->pool->num_conns_being_used > 0);
	backend->pool->num_conns_being_used--;

	network_connection_pool_del_byconn(backend->pool, con);

	// add the event to handle the pool if it times out
	log_debug("%s.%d remove event %s/%d", __FILE__, __LINE__, con->addr.str, con->fd);
	event_del(&(con->event));

	return 0;
}

/**
 * cleanup the proxy specific data on the current connection 
 *
 * move the server connection into the connection pool in case it is a 
 * good client-side close
 *
 * @return RET_SUCCESS
 * @see plugin_call_cleanup
 */
void show() {
	return;
}

NETWORK_MYSQLD_PLUGIN_PROTO(proxy_disconnect_client) {
	plugin_con_state *st = (plugin_con_state *) (con->plugin_con_state);
	gboolean use_pooled_connection = FALSE;

	show();
	log_debug("%s.%d SOCKET=%d: in proxy_disconnect_client plugin.",
			__FILE__, __LINE__, con->client ? con->client->fd : 0);

	if (st == NULL) return RET_SUCCESS;

	while (con->servers && con->servers->len > 0) {
		MULTIPART_DATA *pmd = (MULTIPART_DATA*) con->servers->pdata[0];

		//we need to close the backend connections since they have outstanding queries
		proxy_connection_pool_del_con(srv, pmd->server);
		network_socket_free(pmd->server);

		pmd->server = NULL;
		g_ptr_array_remove(con->servers, pmd);
		pmd_free(pmd);
	}

	if (con->tx_level > 0) {
		//we have incomplete transactions, need to close all the
		//related backend server connections, so the servers can roll them back.

		while (con->cache_servers && con->cache_servers->len > 0) {
			MULTIPART_DATA *pmd = (MULTIPART_DATA*) con->cache_servers->pdata[0];

			proxy_connection_pool_del_con(srv, pmd->server);
			network_socket_free(pmd->server);

			pmd->server = NULL;
			g_ptr_array_remove(con->cache_servers, pmd);
			pmd_free(pmd);
		}
	}

	/**
	 * let the lua-level decide if we want to keep the connection in the pool
	 */

	switch (proxy_lua_disconnect_client(con)) {
		case PROXY_NO_DECISION:
			/* just go on */

			break;
		case PROXY_IGNORE_RESULT:
			break;
		default:
			log_error("%s.%d: ... ", __FILE__, __LINE__);
			break;
	}

	/**
	 * check if one of the backends has to many open connections
	 */

	if (use_pooled_connection &&
			con->state == CON_STATE_CLOSE_CLIENT) {
		/* move the connection to the connection pool
		 *
		 * this disconnects con->server and safes it from getting free()ed later
		 */

		proxy_connection_pool_add_connection(con);
	} else if (st->backend) {
		/* we have backend assigned and want to close the connection to it */
		st->backend->connected_clients--;
	}

	plugin_con_state_free(st);

	con->plugin_con_state = NULL;

	/**
	 * walk all pools and clean them up
	 */

	return RET_SUCCESS;
}

int network_mysqld_proxy_connection_init(network_mysqld_con *con) {
	con->plugins.con_init = proxy_init;
	con->plugins.con_create_auth_result = proxy_make_auth_resp;
	con->plugins.con_read_handshake = proxy_read_handshake;
	con->plugins.con_read_auth_result = proxy_read_auth_result;
	con->plugins.con_multiserver_read_handshake = proxy_multiserver_read_handshake;
	con->plugins.con_multiserver_read_auth_result = proxy_multiserver_read_auth_result;
	con->plugins.con_read_query = proxy_read_query;
	con->plugins.con_get_server_list = proxy_get_server_list;
	con->plugins.con_get_server_connection_list = proxy_get_server_connection_list;
	con->plugins.con_read_query_result = proxy_read_query_result;
	con->plugins.con_send_query_result = proxy_send_query_result;
	con->plugins.con_cleanup = proxy_disconnect_client;
	return 0;
}

/**
 * bind to the proxy-address to listen for client connections we want
 * to forward to one of the backends
 */
int network_mysqld_proxy_init(network_mysqld_con *con) {
	gchar *address = con->config.proxy.address;

	log_debug("%s.%d proxy_init(%s)", __FILE__, __LINE__, address);

	if (0 != network_mysqld_con_set_address(&con->server->addr, address)) {
		return -1;
	}

	if (0 != network_mysqld_con_bind(con->server)) {
		return -1;
	}

	return 0;
}

/**
 * free the global scope which is shared between all connections
 *
 * make sure that is called after all connections are closed
 */
void network_mysqld_proxy_free(network_mysqld_con *con) {
	plugin_srv_state *g = plugin_srv_state_get(NULL);

	plugin_srv_state_free(g);
}

NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_init) {
	return (retval_t) 0;
}

void network_connection_pool_create_conns(network_mysqld *srv) {
	backend_t *backend = NULL;
	int count;
	network_socket *server;
	server_connection_state *pscs;

	for (size_t i = 0; i < srv->backend_pool->len; i++) {
		if (NULL != (backend = (backend_t *) (srv->backend_pool->pdata[i]))) {

			count = network_connection_pool_get_conns_count(
					backend->pool,
					backend->config->default_username,
					backend->config->default_db);

			int pendingConns = backend->pending_dbconn->len;
			for (int j = 0;
					j < backend->config->max_conn_pool - count -
					backend->pool->num_conns_being_used - pendingConns;
					j++) {
				pscs = network_mysqld_async_con_init(srv);
				pscs->config = backend->config;
				pscs->server->addr = backend->addr;
				pscs->server->addr.str = g_strdup(backend->addr.str);

				// need to set the name used for pool lookup
				//pscs->server->username = g_string_new(NULL);
				pscs->server->username = g_string_sized_new(backend->config->default_username->len);
				g_string_append(pscs->server->username, backend->config->default_username->str);

				pscs->server->default_db = g_string_sized_new(backend->config->default_db->len);
				g_string_append(pscs->server->default_db, backend->config->default_db->str);

				if (0 != network_mysqld_con_connect(srv, pscs->server)) {
					backend->state = BACKEND_STATE_DOWN;
					g_get_current_time(&(backend->state_since));
					server = NULL;
					network_mysqld_async_con_state_free(pscs);
					break;
				}

				log_info("%s.%d SOCKET=%d: new backend connection, remote=%s:%s.\n",
						__FILE__, __LINE__, pscs->server->fd,
						pscs->server->addr.str, pscs->server->default_db->str);


				if (backend->state != BACKEND_STATE_UP) {
					backend->state = BACKEND_STATE_UP;
					g_get_current_time(&(backend->state_since));
				}

#ifdef _WIN32
				ioctlvar = 1;
				ioctlsocket(pscs->server->fd, FIONBIO, &ioctlvar);
#else
				fcntl(pscs->server->fd, F_SETFL, O_NONBLOCK | O_RDWR);
#endif

				// add a EV_READ event, because we just connected to the serve
				log_debug("%s.%d SOCKET=%d: wait for event EV_READ.", __FILE__, __LINE__, pscs->server->fd);

				// we we expect to read data from the server	
				event_set(&(pscs->server->event), pscs->server->fd, EV_READ, network_mysqld_async_con_handle, pscs);
				event_base_set(srv->event_base, &(pscs->server->event));
				event_add(&(pscs->server->event), NULL);

				// add the pending connection to the array(in case
				// of failure or network connection we can clean this up
				g_ptr_array_add(backend->pending_dbconn, pscs);

				// we already performed the connecte_server, look for 
				// handshake	
				pscs->state = CON_STATE_ASYNC_READ_HANDSHAKE;

				// update the time we last used this object
				g_get_current_time(&(pscs->lastused));
			}
		}
	}

}

/**
 * parse the hand-shake packet from the server
 *
 *
 * @note the SSL and COMPRESS flags are disabled as we can't 
 *       intercept or parse them.
 */
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_read_handshake) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock;
	guint off = 0;
	int maj, min, patch;
	guint16 server_cap = 0;
	guint8 server_lang = 0;
	guint16 server_status = 0;
	gchar *scramble_1, *scramble_2;

	recv_sock = con->server;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE) {
		/**
		 * packet is too short, looks nasty.
		 *
		 * report an error and let the core send a error to the 
		 * client
		 */

		log_warning("%s.%d: handshake packet too small", __FILE__, __LINE__);
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		return RET_ERROR;
	}

	if (packet->str[NET_HEADER_SIZE + 0] == '\xff') {
		/* the server doesn't like us and sends a ERR packet */

		log_warning("%s.%d: handshake packet error", __FILE__, __LINE__);
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		return RET_ERROR;

	} else if (packet->str[NET_HEADER_SIZE + 0] != '\x0a') {
		/* the server isn't 4.1+ server, send a client a ERR packet
		*/
		log_warning("%s.%d: handshake packet err < version 4.1 server", __FILE__, __LINE__);
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		return RET_ERROR;
	}

	/* scan for a \0 */
	for (off = NET_HEADER_SIZE + 1; packet->str[off] && off < packet->len + NET_HEADER_SIZE; off++);

	if (packet->str[off] != '\0') {
		/* the server has sent us garbage */
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		log_warning("%s.%d: handshake is garbage", __FILE__, __LINE__);
		return RET_ERROR;
	}

	if (3 != sscanf(packet->str + NET_HEADER_SIZE + 1, "%d.%d.%d%*s", &maj, &min, &patch)) {
		/* can't parse the protocol */
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		g_string_free(packet, TRUE);

		log_warning("%s.%d: handshake packet has invalid version", __FILE__, __LINE__);

		return RET_ERROR;
	}

	/**
	 * out of range 
	 */
	if (min < 0 || min > 100 ||
			patch < 0 || patch > 100 ||
			maj < 0 || maj > 10) {
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		log_warning("%s.%d: handshake packet unsupported version", __FILE__, __LINE__);
		return RET_ERROR;
	}

	recv_sock->mysqld_version =
		maj * 10000 +
		min * 100 +
		patch;

	/* skip the \0 */
	off++;

	recv_sock->thread_id = network_mysqld_proto_get_int32(packet, &off);

	/**
	 * get the scramble buf
	 *
	 * 8 byte here and some the other 12 somewhen later
	 */
	scramble_1 = network_mysqld_proto_get_string_len(packet, &off, 8);

	network_mysqld_proto_skip(packet, &off, 1);

	/* we can't sniff compressed packets nor do we support SSL */
	packet->str[off] &= ~(CLIENT_COMPRESS);
	packet->str[off] &= ~(CLIENT_SSL);

	server_cap = network_mysqld_proto_get_int16(packet, &off);

	if (server_cap & CLIENT_COMPRESS) {
		packet->str[off - 2] &= ~(CLIENT_COMPRESS);
	}

	if (server_cap & CLIENT_SSL) {
		packet->str[off - 1] &= ~(CLIENT_SSL >> 8);
	}

	server_lang = network_mysqld_proto_get_int8(packet, &off);
	server_status = network_mysqld_proto_get_int16(packet, &off);

	network_mysqld_proto_skip(packet, &off, 13);

	scramble_2 = network_mysqld_proto_get_string_len(packet, &off, 13);

	/**
	 * scramble_1 + scramble_2 == scramble
	 *
	 * a len-encoded string
	 */

	g_string_truncate(recv_sock->scramble_buf, 0);
	g_string_append_len(recv_sock->scramble_buf, scramble_1, 8);
	g_string_append_len(recv_sock->scramble_buf, scramble_2, 13);

	g_free(scramble_1);
	g_free(scramble_2);

	g_string_truncate(recv_sock->auth_handshake_packet, 0);
	g_string_append_len(recv_sock->auth_handshake_packet, packet->str + NET_HEADER_SIZE, packet->len - NET_HEADER_SIZE);

#if 0
	switch (proxy_lua_read_handshake(con)) {
		case PROXY_NO_DECISION:
			break;
		case PROXY_SEND_QUERY:
			/* the client overwrote and wants to send its own packet
			 * it is already in the queue */

			recv_sock->packet_len = PACKET_LEN_UNSET;
			g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

			return RET_ERROR;
		default:
			log_error("%s.%d: ...", __FILE__, __LINE__);
			break;
	}
#endif

	/*
	 * move the packets from the server queue 
	 */
	recv_sock->packet_len = PACKET_LEN_UNSET;
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
	g_string_free(packet, TRUE);

	return RET_SUCCESS;
}

/*
 *
 *	Result Format:
 *		4 byte Mysql-Packet Header
 *		4 byte CLIENT_FLAGS
 *		4 byte PACKET LENGTH
 *		1 byte CHARSET
 *		23 byte UNKNOWN
 *		N bytes USERNAME
 *		N bytes SCRAMBLED PASSOWRD	
 *(opt) N bytes DEFAULT_DB
 *  
 *
 *  Example:
 *	38 00 00 01 85 a6 03 00  8 . . . . . . .
 *	00 00 00 01 08 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 73 61 00 14  . . . . s a . .
 *	4b 0c 15 84 3e b0 b0 d6  K . . . > . . .
 *	66 eb 04 47 0d 68 a1 df  f . . G . h . .
 * 	84 5f 09 98  . _ . .
 *
 */
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_create_auth) {
	/* read auth from client */
	GString *packet;
	network_socket *send_sock;
	char scrambled[256];
	GString *new_packet;

	send_sock = con->server;

	/**
	 * @\0\0\1
	 *  \215\246\3\0 - client-flags
	 *  \0\0\0\1     - max-packet-len
	 *  \10          - charset-num
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0       - fillers
	 *  root\0       - username
	 *  \24          - len of the scrambled buf
	 *    ~    \272 \361 \346
	 *    \211 \353 D    \351
	 *    \24  \243 \223 \257
	 *    \0   ^    \n   \254
	 *    t    \347 \365 \244
	 *  
	 *  world\0
	 */

	// 4 byte packet header
	// 4 byte CLIENT_FLAGS
	// 4 byte PACKET LENGTH
	// 1 byte CHARSET
	// 23 byte UNKNOWN
	// N bytes USERNAME
	// N bytes SCRAMBLED PASSOWRD	
	// N bytes DEFAULT_DB

	new_packet = g_string_new(NULL);

	// skip puting the header
	//network_mysqld_proto_append_int32( new_packet, (guint32)0 );

	// 4 byte CLIENT_FLAGS
	network_mysqld_proto_append_int32(new_packet, (guint32) con->config->client_flags);

	// 4 byte packet length 
	network_mysqld_proto_append_int32(new_packet, (guint32) 0x01000000);

	// 1 byte CHARSET
	network_mysqld_proto_append_int8(new_packet, (guint8) con->config->charset);

	// 23 byte zero buffer
	network_mysqld_proto_append_int8(new_packet, (guint8) 0);
	network_mysqld_proto_append_int16(new_packet, (guint16) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);

	// N bytes USERNAME
	g_string_append_len(new_packet, con->config->default_username->str, con->config->default_username->len);
	g_string_append_c(new_packet, '\0');

	// N bytes scrambled password
	memset((void*) scrambled, 0, sizeof (scrambled));
	g_string_truncate(send_sock->scramble_buf, SCRAMBLE_LENGTH);
	g_string_append_c(send_sock->scramble_buf, '\0');

	g_string_append_c(con->config->default_password, '\0');
	mysql_scramble(scrambled, send_sock->scramble_buf->str, con->config->default_password->str);
	g_string_truncate(con->config->default_password, con->config->default_password->len - 1);

	g_string_truncate(send_sock->scrambled_password, 0);
	g_string_append_len(send_sock->scrambled_password, scrambled, SCRAMBLE_LENGTH);

	g_string_append_c(new_packet, SCRAMBLE_LENGTH);
	g_string_append_len(new_packet, scrambled, SCRAMBLE_LENGTH);

	// 1 byte filler, we do not need this ?
	// g_string_append_c(new_packet, '\0');

	// N bytes default_db (optional) - zero terminated??
	if ((NULL != con->config->default_db->str) && (strlen(con->config->default_db->str) != 0)) {
		//g_string_append_len(new_packet, con->config->default_db->str, con->config->default_db->len);

		// null terminated?
		g_string_append_len(new_packet, con->config->default_db->str, con->config->default_db->len);
		g_string_append_c(new_packet, '\0');
	}

	packet = g_string_new(NULL);
	network_mysqld_proto_append_int16(packet, (guint16) new_packet->len);
	network_mysqld_proto_append_int8(packet, 0);
	network_mysqld_proto_append_int8(packet, 0x1);
	g_string_append_len(packet, new_packet->str, new_packet->len);
	g_string_free(new_packet, TRUE);

	network_queue_append_chunk(send_sock->send_queue, packet);

	return RET_SUCCESS;
}

/*
   read the authentication result from the database server


*/
NETWORK_MYSQLD_ASYNC_PLUGIN_PROTO(proxy_async_read_auth_result) {
	GString *packet;
	GList *chunk;
	network_socket *recv_sock;

	recv_sock = con->server;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	/* we aren't finished yet */
	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE) {
		return RET_SUCCESS;
	}


	/**
	 * we handled the packet on the server side, free it
	 */
	recv_sock->packet_len = PACKET_LEN_UNSET;

	// caller already has a pointer and will free
	//g_string_free(packet, TRUE);
	//g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

	return RET_SUCCESS;
}

server_connection_state* network_mysqld_async_con_init(network_mysqld *srv) {
	server_connection_state *con;
	plugin_con_state *st;

	con = g_new0(server_connection_state, 1);

	con->srv = srv;
	con->server = network_socket_init();
	con->state = CON_STATE_ASYNC_INIT;

	con->plugin_con_state = st = plugin_con_state_init();

	if (NULL == (st->global_state = plugin_srv_state_get(srv))) {
		return NULL;
	}

	con->plugins.con_init = proxy_async_init;
	con->plugins.con_read_handshake = proxy_async_read_handshake;
	con->plugins.con_create_auth = proxy_async_create_auth;
	con->plugins.con_send_auth = NULL;
	con->plugins.con_read_auth_result = proxy_async_read_auth_result;

	return con;
}

/**
 * create the hand-shake packet as a database server
 *
 * @packet:
 *		3 bytes header length
 *		1 byte packet number
 *		1 byte PROTOCOL VERSION
 *		N byte NULL TERMINATED SERVER STRING = major.minor.patch-string
 *		4 bytes(INT) thread_id
 *		8 bytes SCRAMBLE_1
 *		1 bytes filler always 0
 *		2 bytes SERVER_CAP - CLIENT_COMPRESS/CLIENT_SSL
 *		1 byte SERVER LANGUAGE
 *		2 bytes SERVER STATUS - eg. SERVER_STATUS_AUTOCOMMIT
 *		13 bytes FILLER
 *		13 bytes SCRAMBLE_2
 *
 *	41 00 00 00 0a 35 2e 30  A . . . . 5 . 0
 *	2e 34 35 2d 63 6f 6d 6d  . 4 5 - c o m m
 *	75 6e 69 74 79 2d 6e 74  u n i t y - n t
 *	00 aa 00 00 00 76 59 39  . . . . . v Y 9
 *	51 6b 46 59 70 00 0c a2  Q k F Y p . . .
 * 	08 02 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	48 56 55 2c 75 2f 28 77  H V U , u / ( w
 *	43 27 39 29 00 			 C ' 9 ) .
 */

// the server version should be the lowest version of every server connected
// need to change to find the correct version from all connected servers and 
// then generate the proper version_string. For now it will be hardcoded.
#define SERVER_MAJ		5
#define SERVER_MIN		1
#define SERVER_PATCH	0
const char szSERVER_VERSION[] = "5.1.0-SpockProxy";
static int thread_id = 0;

retval_t proxy_create_handshake(network_mysqld *srv, network_mysqld_con *con)
	//NETWORK_MYSQLD_PLUGIN_PROTO(proxy_create_handshake) 
{
	GString *packet, *new_packet;
	network_socket *send_sock;
	char scramble_buf[SCRAMBLE_LENGTH + 1];

	send_sock = con->client;

	// create the server packet
	new_packet = g_string_new(NULL);

	// skip puting the header, do it later...
	//network_mysqld_proto_append_int32( new_packet, (guint32)0 );

	// protocol version is currently 10?
	network_mysqld_proto_append_int8(new_packet, (guint8) PROTOCOL_VERSION);

	// SERVER VERSION STRING
	g_string_append_len(new_packet, szSERVER_VERSION, strlen(szSERVER_VERSION) + 1);
	send_sock->mysqld_version = SERVER_MAJ * 10000 + SERVER_MIN * 100 + SERVER_PATCH;

	// THREAD_ID - need to know how to keep this in sequence (associated with the client?)
	send_sock->thread_id = ++thread_id;
	network_mysqld_proto_append_int32(new_packet, (guint32) thread_id);

	// now generate the random hash to the client
	mysql_create_random_string(scramble_buf, sizeof (scramble_buf) - 1);

	g_string_truncate(send_sock->scrambled_hash, 0);
	g_string_append_len(send_sock->scrambled_hash, scramble_buf, sizeof (scramble_buf));

	// write first part of the scrambled password	
	g_string_append_len(new_packet, scramble_buf, 8);

	// 1 byte filler
	network_mysqld_proto_append_int8(new_packet, (guint8) 0);

	// 2 byte server cap
	network_mysqld_proto_append_int16(new_packet, (guint16) srv->db_config.client_flags);

	// 1 byte language
	network_mysqld_proto_append_int8(new_packet, (guint8) srv->db_config.charset);

	// 2 byte server status - eg. SERVER_STATUS_AUTOCOMMIT 
	network_mysqld_proto_append_int16(new_packet, (guint16) SERVER_STATUS_AUTOCOMMIT);

	// 13 bytes of filler
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	network_mysqld_proto_append_int32(new_packet, (guint32) 0);
	g_string_append_c(new_packet, '\0');

	// 13 bytes of 2nd part of the scrambled buffer
	g_string_append_len(new_packet, scramble_buf + 8, 13);

	packet = g_string_new(NULL);
	network_mysqld_proto_append_int16(packet, (guint16) new_packet->len);
	network_mysqld_proto_append_int8(packet, 0);
	network_mysqld_proto_append_int8(packet, 0x0);
	g_string_append_len(packet, new_packet->str, new_packet->len);

	network_queue_append_chunk(send_sock->send_queue, packet);
	g_string_free(new_packet, TRUE);

	/* copy the pack to the client */
	con->state = CON_STATE_SEND_HANDSHAKE;

	return RET_SUCCESS;
}

/*
 *
 *	SERVER AUTHENTICATION RESPONSE
 *
 *		4 byte header
 *		1 field count - always 0
 *		1 affected rows = 0
 *		1 insert_id = 0
 *		2 server_status = SERVER_STATUS_AUTOCOMMIT
 *		2 warning_count = 0
 *
 *	Success Example:
 *		07 00 00 02 00 00 00 02  . . . . . . . .
 *		00 00 00  . . .
 *
 */

void create_ok_packet(network_socket *con, int packet_num, const char *errmsg) {
	GString *packet, *new_packet;

	new_packet = g_string_new(NULL);

	// field count
	network_mysqld_proto_append_int8(new_packet, (guint8) 0);

	// affected_rows
	network_mysqld_proto_append_int8(new_packet, (guint8) 0);

	// insert_id
	network_mysqld_proto_append_int8(new_packet, (guint8) 0);

	// server_status
	network_mysqld_proto_append_int16(new_packet, (guint16) SERVER_STATUS_AUTOCOMMIT);

	// warning count
	network_mysqld_proto_append_int16(new_packet, (guint16) 1);

	// write string
	if (NULL != errmsg)
		g_string_append_len(new_packet, errmsg, strlen(errmsg));

	packet = g_string_new(NULL);
	network_mysqld_proto_append_int16(packet, (guint16) new_packet->len);
	network_mysqld_proto_append_int8(packet, 0);
	network_mysqld_proto_append_int8(packet, packet_num);
	g_string_append_len(packet, new_packet->str, new_packet->len);

	network_queue_append_chunk(con->send_queue, packet);
	g_string_free(new_packet, TRUE);
}

typedef struct mysql_error_state {
	int mysql_errno;
	char *sql_state;
} mysql_error_state;

mysql_error_state mysql_states[] = {
	{ ER_PASSWORD_NO_MATCH, "42000"},
	{ ER_USERNAME, "42000"},
	{ ER_NO_DB_ERROR, "3D000"},
	{ 0, NULL}
};

const char *get_sql_state(int mysql_errno) {
	int i = 0;
	mysql_error_state *p;

	do {
		p = &mysql_states[i++];
		if (p->sql_state != NULL) {
			if (p->mysql_errno == mysql_errno)
				return p->sql_state;
		} else
			break;

	} while (1);

	return "";
}

/*
 *
 *	SERVER AUTHENTICATION ERR RESPONSE
 *
 *		4 byte header
 *		1 field count - always 0xff
 *		2 errno (see include/mysqld_error.h)
 *		1 sqlstate marker, always '#'
 *		5 sqlstate (5 characeters) - use mysql_errno_to_sqlstate or sql_state.h
 *		n message -
 *
 *	Err Example:
 *
 */
void create_err_packet(network_socket *con, int packet_num, int mysql_errno, const char *errmsg) {
	GString *packet, *new_packet;
	const char *sqlstate;

	new_packet = g_string_new(NULL);

	// field count
	network_mysqld_proto_append_int8(new_packet, (guint8) 0xff);

	// errno
	network_mysqld_proto_append_int16(new_packet, (guint16) mysql_errno);

	// marker
	network_mysqld_proto_append_int8(new_packet, (guint8) '#');

	// sqlstate marker
	sqlstate = get_sql_state(mysql_errno);
	g_string_append_len(new_packet, sqlstate, 5);

	// write string
	if (NULL != errmsg)
		g_string_append_len(new_packet, errmsg, strlen(errmsg));

	packet = g_string_new(NULL);
	network_mysqld_proto_append_int16(packet, (guint16) new_packet->len);
	network_mysqld_proto_append_int8(packet, 0);
	network_mysqld_proto_append_int8(packet, packet_num);
	g_string_append_len(packet, new_packet->str, new_packet->len);

	network_queue_append_chunk(con->send_queue, packet);
	g_string_free(new_packet, TRUE);
}

/*
 *  Read the client authentication response and create a an authentication
 *	response to be sent back to the client
 *
 *	Result Format:
 *		4 byte CLIENT_FLAGS
 *		4 byte PACKET LENGTH
 *		1 byte CHARSET
 *		23 byte Filler
 *		N bytes USERNAME
 *		N bytes SCRAMBLED PASSWORD	
 *(opt) N bytes DEFAULT_DB
 *  
 *
 *  Example:
 *	38 00 00 01 85 a6 03 00  8 . . . . . . .
 *	00 00 00 01 08 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 00 00 00 00  . . . . . . . .
 *	00 00 00 00 73 61 00 14  . . . . s a . .
 *	4b 0c 15 84 3e b0 b0 d6  K . . . > . . .
 *	66 eb 04 47 0d 68 a1 df  f . . G . h . .
 * 	84 5f 09 98  . _ . .
 *
 *
 *	SERVER AUTHENTICATION RESPONSE
 *
 *		4 byte header
 *		1 field count - always 0
 *		1 affected rows = 0
 *		1 insert_id = 0
 *		2 server_status = SERVER_STATUS_AUTOCOMMIT
 *		2 warning_count = 0
 *
 *	Success Example:
 *		07 00 00 02 00 00 00 02  . . . . . . . .
 *		00 00 00  . . .
 *
 */
NETWORK_MYSQLD_PLUGIN_PROTO_GLOBAL(proxy_make_auth_resp) {
	/* read auth from client */
	GString *packet;
	GList *chunk;
	network_socket *recv_sock, *send_sock;
	mysql_packet_auth auth;
	guint off = 0;
	guint8 password_hash[256];
	gchar password[256];
	my_bool myb;

	memset((void*) password_hash, 0, sizeof (password_hash));

	recv_sock = con->client;
	send_sock = con->client;

	chunk = recv_sock->recv_queue->chunks->tail;
	packet = (GString *) (chunk->data);

	if (packet->len != recv_sock->packet_len + NET_HEADER_SIZE)
		return RET_SUCCESS; /* we are not finished yet */

	/* extract the default db from it */
	network_mysqld_proto_skip(packet, &off, NET_HEADER_SIZE); /* packet-header */

	/**
	 * @\0\0\1
	 *  \215\246\3\0 - client-flags
	 *  \0\0\0\1     - max-packet-len
	 *  \10          - charset-num
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0\0
	 *  \0\0\0       - fillers
	 *  root\0       - username
	 *  \24          - len of the scrambled buf
	 *    ~    \272 \361 \346
	 *    \211 \353 D    \351
	 *    \24  \243 \223 \257
	 *    \0   ^    \n   \254
	 *    t    \347 \365 \244
	 *  
	 *  world\0
	 */

	auth.client_flags = network_mysqld_proto_get_int32(packet, &off);
	auth.max_packet_size = network_mysqld_proto_get_int32(packet, &off);
	auth.charset_number = network_mysqld_proto_get_int8(packet, &off);

	// skip the filler
	network_mysqld_proto_skip(packet, &off, 23);

	// get the username	
	network_mysqld_proto_get_gstring(packet, &off, con->client->username);

	// get the scrambled pass
	network_mysqld_proto_get_lenenc_gstring(packet, &off, con->client->scrambled_password);

	if (off != packet->len) {
		network_mysqld_proto_get_gstring(packet, &off, con->client->default_db);
	}

	//
	// at this point we should make a response...
	//

	// check the username (is that valid?)
	if (strcmp(con->client->username->str, srv->db_config.default_username->str) != 0) { // send an error response

		// clean up the receiving socket
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

		network_mysqld_con_send_error_full(con->client, "invalid username", 16, ER_USERNAME, get_sql_state(ER_USERNAME));
		//create_err_packet( con->client, 2, ER_USERNAME, "invalid username" );
		return RET_ERROR;
	}

	// create a password hash(salt) aka hash_stage2
	password[0] = 0;
	//strcpy( password, "*");
	strcpy(password, srv->db_config.default_password->str);
	mysql_make_scramble((char *) password_hash, password);

	// check the password (is password valid?)
	if ((myb = mysql_is_valid(con->client->scrambled_password->str,
					con->client->scrambled_hash->str,
					password_hash)) != 0) { // send an error
		// clean up the receiving socket

		// at the moment ignore the password failing
#if 1
		recv_sock->packet_len = PACKET_LEN_UNSET;
		g_string_free(packet, TRUE);
		g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);
		network_mysqld_con_send_error_full(con->client, "invalid password", 16, ER_PASSWORD_NO_MATCH, get_sql_state(ER_PASSWORD_NO_MATCH));
		//create_err_packet( con->client, 2, ER_PASSWORD_NO_MATCH, "invalid password" );
		return RET_ERROR;
#endif
	}

	con->client->packet_id = 2;
	network_mysqld_con_send_ok(con->client);

	// clean up the receiving socket
	recv_sock->packet_len = PACKET_LEN_UNSET;
	g_string_free(packet, TRUE);
	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

	return RET_SUCCESS;
}

/**
 * move the con->server into connection pool and remove from the connection
 * pending list
 */
int proxy_connection_pool_add(server_connection_state *pscs) {
	network_mysqld *srv = pscs->srv;
	network_socket *server = pscs->server;
	backend_t *backend = NULL;
	struct timeval tv;

	/* con-server is already disconnected, get out */
	if (!server)
		return 0;

	log_debug("%s.%d add_pool server = %s",
			__FILE__, __LINE__, server->addr.str);

	/* the server connection is authed */
	server->is_authed = 1;

	// find the pool the socket is associated to
	for (size_t i = 0; i < srv->backend_pool->len; i++) {
		backend = (backend_t *) (srv->backend_pool->pdata[i]);

		if ((strcmp(backend->addr.str, server->addr.str) == 0) &&
				(strcmp(backend->config->default_db->str, server->default_db->str) == 0)) {
			break;
		}
		backend = NULL;
	}

	if (backend == NULL) {
		log_debug("%s.%d can't find pool for server = %s",
				__FILE__, __LINE__, server->addr.str);
		return 0;
	}

	/* insert the server socket into the connection pool */
	network_connection_pool_add(backend->pool, server);

	// add the event to handle the pool if it times out
	event_set(&(server->event), server->fd, EV_READ | EV_TIMEOUT, network_mysqld_con_idle_handle, server);
	event_base_set(srv->event_base, &(server->event));
	tv.tv_sec = get_config_max_conn_idle_time();
	tv.tv_usec = 0;
	log_debug("%s.%d: adding event EV_READ|EV_TIMEOUT for SOCKET=%d\n", __FILE__, __LINE__, server->fd);
	event_add(&(server->event), &tv);

	// remove the entry from the pending_dbconn
	if (g_ptr_array_remove(backend->pending_dbconn, pscs) == FALSE)
		log_debug("%s.%d: internal error: g_ptr_array_remove failed", __FILE__, __LINE__);

	// we don't need this object anymore, the server was already added to the
	// backend queue

	// shouldn't ptrs inside pscs be freed before pscs?
	plugin_con_state_free((plugin_con_state *) (pscs->plugin_con_state));
	g_free(pscs);
	return 0;
}

int proxy_connection_pool_del(server_connection_state *pscs) {
	network_mysqld *srv = pscs->srv;
	network_socket *server = pscs->server;
	backend_t *backend = NULL;

	if (server->addr.str == NULL)
		return 0;

	// find the pool the socket is associated to
	for (size_t i = 0; i < srv->backend_pool->len; i++) {
		backend = (backend_t *) (srv->backend_pool->pdata[i]);

		if ((strcmp(backend->addr.str, server->addr.str) == 0) &&
				(strcmp(backend->config->default_db->str, server->default_db->str) == 0)) {
			break;
		}
		backend = NULL;
	}

	if (backend == NULL) {
		log_debug("%s.%d can't find pool for server = %s",
				__FILE__, __LINE__, server->addr.str);
		return 0;
	}

	if (g_ptr_array_remove(backend->pending_dbconn, pscs) == FALSE)
		log_debug("%s.%d: internal error: g_ptr_array_remove failed", __FILE__, __LINE__);

	// freed by caller
	//g_free(pscs);

	return 0;
}

/**
 * find and remove from the connection pool, return true on success
 */
bool proxy_get_pooled_connection(
		network_mysqld *srv,
		GString *address,
		GString *dbname,
		GString *username,
		network_socket **con) {
	backend_t *backend = NULL;


	assert(address != NULL && username != NULL);

	// find the pool the socket is associated to
	for (size_t i = 0; i < srv->backend_pool->len; i++) {
		backend = (backend_t *) (srv->backend_pool->pdata[i]);

		if ((strcmp(backend->addr.str, address->str) == 0) &&
				(strcmp(backend->config->default_db->str, dbname->str) == 0)) {
			break;
		}
		backend = NULL;
	}

	if (backend == NULL)
		return false;

	if (NULL == (*con = network_connection_pool_get(
					backend->pool,
					username,
					dbname))) {
		/* no connections in the pool */
		log_debug("%s.%d: unable to find a connection in the pool %s/%s",
				__FILE__, __LINE__, address->str, dbname->str);

		return false;
	}

	return true;
}

/**
  add the connection back to the connection pool, the client is done with it

*/
int proxy_connection_pool_add_con(network_mysqld *srv, network_socket *con) {
	network_connection_pool *pool;

	/* con-server is already disconnected, get out */
	if (!con)
		return 0;

	if (time(NULL) - con->last_write_time >= get_config_max_conn_idle_time()) {
		log_warning("%s.%d: backend connection socket=%d has been "
				"idle for too long, closing ...\n", __FILE__, __LINE__, con->fd);
		proxy_connection_pool_del_con(srv, con);
		network_socket_free(con);
		return 0;
	}

	pool = get_backend_conn_pool(srv, con);

	if (pool == NULL) {
		log_error("%s.%d can't find pool for server = %s",
				__FILE__, __LINE__, con->addr.str);
		return 0;
	}

	log_debug("%s.%d SOCKET=%d: add to backend connection pool.",
			__FILE__, __LINE__, con->fd);

	// should we determine if there are two many connections in the pool?
	// ignore adding or remove some?

	/* insert the server socket into the connection pool */
	network_connection_pool_add(pool, con);

	pool->num_conns_being_used--;

	// add the event to handle the pool if it times out
	struct timeval tv;
	event_set(&(con->event), con->fd, EV_READ | EV_TIMEOUT, network_mysqld_con_idle_handle, con);
	event_base_set(get_network_mysqld()->event_base, &(con->event));
	tv.tv_sec = get_config_max_conn_idle_time();
	tv.tv_usec = 0;
	log_debug("%s.%d: adding event EV_READ|EV_TIMEOUT for SOCKET=%d\n", __FILE__, __LINE__, con->fd);
	event_add(&(con->event), &tv);

	return 0;
}

/**
  remove all connections and put them back in the pool

  Add code to determine if the session is in a transaction or that we need to retain
  the server list
  */
void proxy_remove_server_connections(network_mysqld *srv, network_mysqld_con *con) {
	MULTIPART_DATA *pmd;

	/* con-server is already disconnected, get out */
	if (NULL == con || NULL == srv)
		return;

	if (con->client != NULL) {
		log_debug("%s.%d SOCKET=%d: proxy_remove_server_connections.",
				__FILE__, __LINE__, con->client->fd);
	}

	// enumerate the pool of sockets and add them back
	while (0 != con->servers->len) {
		pmd = (MULTIPART_DATA*) con->servers->pdata[0];

		proxy_connection_pool_add_con(srv, pmd->server);
		pmd->server = NULL;
		g_ptr_array_remove(con->servers, pmd);
		pmd_free(pmd);
	}

	while (0 != con->cache_servers->len) {
		pmd = (MULTIPART_DATA*) con->cache_servers->pdata[0];

		proxy_connection_pool_add_con(srv, pmd->server);

		pmd->server = NULL;
		g_ptr_array_remove(con->cache_servers, pmd);
		pmd_free(pmd);
	}
}

/**
 *  cahce backend server connections or put them back into the server pool if
 *  we are not in the middle of a transaction
 */
void proxy_cache_server_connections(network_mysqld *srv, network_mysqld_con *con) {
	MULTIPART_DATA *pmd;

	/* con-server is already disconnected, get out */
	if (NULL == con || NULL == srv)
		return;

	// enumerate the pool of sockets and add them back
	while (0 != con->servers->len) {
		pmd = (MULTIPART_DATA*) con->servers->pdata[0];

		g_ptr_array_remove(con->servers, pmd);
		if (con->tx_level)
			g_ptr_array_add(con->cache_servers, pmd);
		else {
			proxy_connection_pool_add_con(srv, pmd->server);
			pmd->server = NULL;
			pmd_free(pmd);
		}
	}
}

/*
   add a single connection to the client, return true on success
   */
bool proxy_add_server_connection(
		network_mysqld *srv,
		network_mysqld_con *con,
		GString *server_id,
		GString *sql) {
	MULTIPART_DATA *pmd;
	network_socket *server;
	size_t i;
	GString* hostname;
	GString* dbname;
	GString* usrname;
	GString* tableidxstr;
        GString* insertidstr;
	int tableidx,insertid;

	gchar *hostend = strchr(server_id->str, '|');

	assert(hostend != NULL);

	gchar *tableidxend = strchr(hostend + 1, '|');

	assert(tableidxend != NULL);
        
        gchar *insertidend = strchr(tableidxend + 1, '|');

	assert(insertidend != NULL);

	gchar *dbend = strchr(insertidend + 1, '|');

	assert(dbend != NULL);

	hostname = g_string_new_len(server_id->str, hostend - server_id->str);
	tableidxstr = g_string_new_len(hostend + 1, tableidxend - hostend - 1);
	tableidx = atoi(tableidxstr->str);
        insertidstr = g_string_new_len(tableidxend + 1, insertidend - tableidxend - 1);
        insertid = atoi(insertidstr->str);
	dbname = g_string_new_len(insertidend + 1, dbend - insertidend - 1);
	usrname = g_string_new(dbend + 1);


	/*
	// validate we didn't already add this server
	if (con->servers != NULL) {
		for (i = 0; i < con->servers->len; i++) {
			pmd = (MULTIPART_DATA *) (con->servers->pdata[i]);
			if (pmd != NULL) {
				if ((strcmp(pmd->server->addr.str, hostname->str) == 0) &&
						(strcmp(pmd->server->default_db->str, dbname->str) == 0) &&
						(strcmp(pmd->server->username->str, usrname->str) == 0)) {
					g_string_free(hostname, TRUE);
					g_string_free(dbname, TRUE);
					g_string_free(usrname, TRUE);
					return true; // already have this server
				}
			}
		}
	}
	*/

	// check the cash first to determine if we have it cached for this client
	if (con->cache_servers != NULL) {
		for (i = 0; i < con->cache_servers->len; i++) {
			pmd = (MULTIPART_DATA *) (con->cache_servers->pdata[i]);
			if (pmd != NULL) {
				if ((strcmp(pmd->server->addr.str, hostname->str) == 0) &&
						(strcmp(pmd->server->default_db->str, dbname->str) == 0) &&
						(strcmp(pmd->server->username->str, usrname->str) == 0)) {
					g_ptr_array_remove(con->cache_servers, pmd);
					g_ptr_array_add(con->servers, pmd);

					g_string_free(hostname, TRUE);
					g_string_free(dbname, TRUE);
					g_string_free(usrname, TRUE);

					return true;
				}
			}
		}
	}

	bool ok;
	if ((ok = proxy_get_pooled_connection(
					srv,
					hostname,
					dbname,
					usrname,
					&server))) {
		pmd = g_new0(MULTIPART_DATA, 1);
		pmd->con = con;
		pmd->server = server;
		pmd->tableidx = tableidx;
                pmd->insertid = insertid;

		g_ptr_array_add(con->servers, pmd);
	}

	g_string_free(hostname, TRUE);
	g_string_free(dbname, TRUE);
	g_string_free(usrname, TRUE);

	return ok;
}

/*
   add an array connection to the client, return true on success
   */
bool proxy_add_server_connection_array(
		network_mysqld *srv,
		network_mysqld_con *client,
		GPtrArray *server_hostnames,
		GString *sql) {
	GString *hostname;

	if (server_hostnames == NULL) {
		log_fatal("Could not add server connections, please make sure "
				"the backend servers are properly configured.!");
		exit(1);
	}


	for (size_t i = 0; i < server_hostnames->len; i++) {
		hostname = (GString *) (server_hostnames->pdata[i]);

		if (!proxy_add_server_connection(srv, client, hostname, sql))
			return false;
	}
	return true;
}

/*
 * select backend pool config 
 */

int pool_config_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data) {
	network_mysqld *srv = (network_mysqld *) user_data;
	backend_t *backend;
	backend_config *config;
	GPtrArray *row;

	/**
	 * show the current configuration 
	 *
	 * TODO: move to the proxy-module
	 */
	MYSQL_FIELD *field;
	gsize i;

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("id");
	field->type = FIELD_TYPE_LONG;
	field->flags = PRI_KEY_FLAG;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("type");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("addr");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("username");
	field->type = FIELD_TYPE_STRING;
	field->length = 64;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("db");
	field->type = FIELD_TYPE_STRING;
	field->length = 64;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("max_conn_pool");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	for (i = 0; i < srv->backend_pool->len; i++) {
		backend = (backend_t *) (srv->backend_pool->pdata[i]);
		config = backend->config;

		row = g_ptr_array_new();
		g_ptr_array_add(row, g_strdup_printf(F_SIZE_T, i));

		switch (config->connection_type) {
			case READ_ONLY:
				{
					g_ptr_array_add(row, g_strdup("read-only"));
					break;
				}
			case READ_WRITE:
				g_ptr_array_add(row, g_strdup("read-write"));
				break;
			case DEF_CONN:
				g_ptr_array_add(row, g_strdup("default"));
				break;
			default:
				g_ptr_array_add(row, g_strdup("unknown"));
				break;
		}

		if (config->address != NULL)
			g_ptr_array_add(row, g_strdup(config->address->str));
		else
			g_ptr_array_add(row, g_strdup("n/a"));

		if (config->default_username != NULL)
			g_ptr_array_add(row, g_strdup(config->default_username->str));
		else
			g_ptr_array_add(row, g_strdup("n/a"));

		if (config->default_db != NULL)
			g_ptr_array_add(row, g_strdup(config->default_db->str));
		else
			g_ptr_array_add(row, g_strdup("n/a"));

		g_ptr_array_add(row, g_strdup_printf("%d", config->max_conn_pool));

		g_ptr_array_add(rows, row);
	}

	return RET_SUCCESS;
}

/*
 * called to handle administrator select * from pool
 *
 */
int pool_connections_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data) {
	network_mysqld *srv = (network_mysqld *) user_data;
	network_connection_pool_entry *pool_entry = NULL;
	backend_t *backend;
	char sz[1024];
	GQueue *conns;
	network_socket *sock;
	GString *str;
	GPtrArray *row;

	/**
	 * show the current configuration 
	 *
	 * TODO: move to the proxy-module
	 */
	MYSQL_FIELD *field;
	gsize i;

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("backend id");
	field->type = FIELD_TYPE_LONG;
	field->flags = PRI_KEY_FLAG;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("state");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("added at");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("mysqld_version");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("thread id");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	PERF_MONITOR_ADD_FIELD_STR(fields);

	for (i = 0; i < srv->backend_pool->len; i++) {
		backend = (backend_t *) (srv->backend_pool->pdata[i]);

		conns = network_connection_pool_get_conns(
				backend->pool,
				backend->config->default_username,
				backend->config->default_db);
		if (conns) {
			GList *chunk = conns->head;

			do {
				pool_entry = (network_connection_pool_entry *) (chunk->data);

				row = g_ptr_array_new();

				// backend id
				g_ptr_array_add(row, g_strdup_printf(F_SIZE_T, i));

				// state
				switch (backend->state) {
					case BACKEND_STATE_UP:
						g_ptr_array_add(row, g_strdup("up"));
						break;
					case BACKEND_STATE_DOWN:
						g_ptr_array_add(row, g_strdup("down"));
						break;
					default:
						g_ptr_array_add(row, g_strdup("unk"));
						break;
				}

				// added time
				str = g_string_new("");
				g_ptr_array_add(row, g_strdup(g_timeval_string(&(pool_entry->added_ts), str)));
				g_string_free(str, TRUE);

				sock = pool_entry->sock;

				// mysqld_version
				g_ptr_array_add(row, g_strdup_printf("%u", sock->mysqld_version));

				// thread id
				g_ptr_array_add(row, g_strdup_printf("%u", sock->thread_id));

				PERF_MONITOR_ADD_ROW_STR(sock)

					g_ptr_array_add(rows, row);

				chunk = chunk->next;
			} while (chunk != NULL && chunk != conns->head);
		} else
			sz[0] = 0;
	}

	return RET_SUCCESS;
}
