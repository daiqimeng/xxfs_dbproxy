

#define SVN_REVISION "$Rev: 228 $"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>

#ifdef _WIN32
#include <process.h> /* getpid() */
#include <io.h>      /* open() */
#else
#include <unistd.h>
#endif

#include <glib.h>

#ifdef HAVE_LUA_H
#include <lua.h>
#endif

#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "sys-pedantic.h"
#include "partition.h"
#include "messages.h"
#include "network-mysqld-proxy.h"

/**
 * signal handlers have to be volatile
 */
#ifdef _WIN32
volatile int agent_shutdown = 0;
#define STDERR_FILENO 2
#else
volatile sig_atomic_t agent_shutdown = 0;
#endif

static network_mysqld *srv = NULL;

#ifndef _WIN32

static void signal_handler(int sig) {
	switch (sig) {
		case SIGINT: agent_shutdown = 1;
					 break;
		case SIGTERM: agent_shutdown = 1;
					  break;
		case SIGUSR1: srv->config.proxy.log_debug_messages = !srv->config.proxy.log_debug_messages;
					  set_debug_msg_logging(srv->config.proxy.log_debug_messages);
					  break;
		case SIGUSR2:
					  printf("reload dbmapping\n");
					  fflush(stdout);
					  database_lookup_load();
					  break;

	}
}
#endif

network_mysqld *get_network_mysqld() {
	return srv;
}

int get_config_log_debug_msgs() {
	return srv->config.proxy.log_debug_messages;
}

int help_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data) {
	/**
	 * show the available commands 
	 */
	//network_mysqld *srv = (network_mysqld *)user_data;
	MYSQL_FIELD *field;
	GPtrArray *row;

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("command");
	field->org_name = g_strdup("command");
	field->type = FIELD_TYPE_STRING;
	field->flags = PRI_KEY_FLAG;
	field->length = 50;

	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("description");
	field->org_name = g_strdup("description");
	field->type = FIELD_TYPE_STRING;
	field->length = 80;

	g_ptr_array_add(fields, field);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("select * from proxy_connections"));
	g_ptr_array_add(row, g_strdup("show information about proxy connections"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("select * from proxy_config"));
	g_ptr_array_add(row, g_strdup("show information about proxy configuration"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("select * from pool_connections"));
	g_ptr_array_add(row, g_strdup("show information about pool connections"));
	g_ptr_array_add(rows, row);

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("select * from pool_configs"));
	g_ptr_array_add(row, g_strdup("show information about pool configuration"));
	g_ptr_array_add(rows, row);


	/*
	 * Add new command descriptions above this comment
	 *
	 * */

	row = g_ptr_array_new();
	g_ptr_array_add(row, g_strdup("select * from help"));
	g_ptr_array_add(row, g_strdup("show the available commands"));
	g_ptr_array_add(rows, row);

	return 0;
}

int config_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data) {
	/**
	 * show the current configuration 
	 */
	network_mysqld *srv = (network_mysqld *) user_data;
	MYSQL_FIELD *field;
	GPtrArray *row;
	gsize i;

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("option");
	field->org_name = g_strdup("option");
	field->type = FIELD_TYPE_STRING;
	field->flags = PRI_KEY_FLAG;
	field->length = 32;

	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("value");
	field->org_name = g_strdup("value");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;

	g_ptr_array_add(fields, field);

#define RESULTSET_ADD(x) \
	row = g_ptr_array_new(); \
	g_ptr_array_add(row, g_strdup(#x)); \
	g_ptr_array_add(row, g_strdup_printf("%d", srv->config.x)); \
	g_ptr_array_add(rows, row);

#define RESULTSET_ADD_STR(x) \
	row = g_ptr_array_new(); \
	g_ptr_array_add(row, g_strdup(#x)); \
	g_ptr_array_add(row, g_strdup(srv->config.x)); \
	g_ptr_array_add(rows, row);

#define RESULTSET_ADD_STR_ARRAY(x) \
	for (i = 0; srv->config.x[i]; i++) { \
		row = g_ptr_array_new(); \
		g_ptr_array_add(row, g_strdup_printf("%s["F_SIZE_T"]", #x, i)); \
		g_ptr_array_add(row, g_strdup(srv->config.x[i])); \
		g_ptr_array_add(rows, row); \
	}

	RESULTSET_ADD_STR(admin.address);
	RESULTSET_ADD_STR(proxy.address);
	RESULTSET_ADD_STR(proxy.lua_script);
	RESULTSET_ADD_STR_ARRAY(proxy.backend_addresses);
	RESULTSET_ADD(proxy.fix_bug_25371);
	RESULTSET_ADD(proxy.profiling);
	RESULTSET_ADD(proxy.log_debug_messages);

	return 0;
}

int connections_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data) {
	network_mysqld *srv = (network_mysqld *) user_data;
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
	field->name = g_strdup("ip");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("type");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("state");
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add(fields, field);

	field = network_mysqld_proto_field_init();
	field->name = g_strdup("db");
	field->type = FIELD_TYPE_STRING;
	field->length = 64;
	g_ptr_array_add(fields, field);

	for (i = 0; i < srv->cons->len; i++) {
		GPtrArray *row;
		network_mysqld_con *rcon = (network_mysqld_con *) (srv->cons->pdata[i]);

		if (!rcon)
			continue;
		if (rcon->is_listen_socket)
			continue;

		row = g_ptr_array_new();

		g_ptr_array_add(row, g_strdup_printf(F_SIZE_T, i));

		if (rcon->server != NULL && rcon->server->addr.str != NULL)
			g_ptr_array_add(row, g_strdup(rcon->server->addr.str));
		else if (rcon->client != NULL && rcon->client->addr.str != NULL)
			g_ptr_array_add(row, g_strdup(rcon->client->addr.str));

		switch (rcon->config.network_type) {
			case NETWORK_TYPE_SERVER:
				{
					if (rcon->server != NULL && rcon->server->addr.str != NULL)
						g_ptr_array_add(row, g_strdup("admin ip:port"));
					else
						g_ptr_array_add(row, g_strdup("server"));
					break;
				}
			case NETWORK_TYPE_PROXY:
				g_ptr_array_add(row, g_strdup("proxy ip:port"));
				break;
		}

		if (sz_state[rcon->state] != NULL)
			g_ptr_array_add(row, g_strdup_printf("%s", sz_state[rcon->state]));
		else
			g_ptr_array_add(row, g_strdup_printf("%d", rcon->state));

		g_ptr_array_add(row, g_strdup(rcon && rcon->server && rcon->server->default_db->len ? rcon->server->default_db->str : ""));

		g_ptr_array_add(rows, row);
	}

	return 0;
}

const char upprof[] = "update proxy_config set profiling";
const char updbgmsg[] = "update proxy_config set log_debug_messages";

gchar *move_past(gchar *str, gchar c) {
	while (str[0] != 0 && str[0] == c)
		str++;

	return str;
}

int config_update(gchar *sql, gpointer user_data) { // only support updating profiling and debug messages
	int ival;
	network_mysqld *srv = (network_mysqld *) user_data;

	if (0 == g_ascii_strncasecmp(sql, upprof, sizeof (upprof) - 1)) {
		// advance past
		sql += sizeof (upprof);
		// move past ' = ' 
		sql = move_past(sql, ' ');
		sql = move_past(sql, '=');
		sql = move_past(sql, ' ');

		ival = atoi(sql);

		if (ival < 0 || ival > 1)
			return -1;

		srv->config.proxy.profiling = ival;
		return RET_SUCCESS;
	} else if (0 == g_ascii_strncasecmp(sql, updbgmsg, sizeof (updbgmsg) - 1)) { // advance past 

		sql += sizeof (updbgmsg);

		// move past ' = '
		sql = move_past(sql, ' ');
		sql = move_past(sql, '=');
		sql = move_past(sql, ' ');

		ival = atoi(sql);

		if (ival < 0 || ival > 1)
			return -1;

		srv->config.proxy.log_debug_messages = ival;
		set_debug_msg_logging(ival);
		return RET_SUCCESS;
	}

	return -1;
}

#ifndef _WIN32

/**
 * start the agent in the background 
 * 
 * UNIX-version
 */
static void daemonize(void) {
#ifdef SIGTTOU
	signal(SIGTTOU, SIG_IGN);
#endif
#ifdef SIGTTIN
	signal(SIGTTIN, SIG_IGN);
#endif
#ifdef SIGTSTP
	signal(SIGTSTP, SIG_IGN);
#endif
	if (fork() != 0) exit(0);

	if (setsid() == -1) exit(0);

	signal(SIGHUP, SIG_IGN);

	if (fork() != 0) exit(0);

	chdir("/");

	umask(0);
}
#endif

static void init_backend_pool(network_mysqld *srv) {
	/* init the pool */
	int k;
	std::vector<int> db_ids =  get_backend_list();
	for (k = 0; k < db_ids.size(); k++) {
	   int i = 0;
	   i = db_ids[k];

		backend_t *backend;
		gchar address[128];
		snprintf(address, sizeof (address), "%s:%d",
				get_config_backend_host(i),
				get_config_backend_port(i));

		backend = backend_init();
		backend->type = BACKEND_TYPE_RW;

		backend->config = g_new0(backend_config, 1);
		backend->config->address = g_string_new(address);
		backend->config->default_username = g_string_new(NULL);
		g_string_append(backend->config->default_username, get_config_backend_userid(i));
		backend->config->default_password = g_string_new(NULL);
		g_string_append(backend->config->default_password, get_config_backend_passwd(i));
		backend->config->default_db = g_string_new(NULL);
		g_string_append(backend->config->default_db, get_config_backend_default_db(i));
		backend->config->client_flags = DEFAULT_FLAGS;
		backend->config->charset = DEFAULT_CHARSET;
		backend->config->max_conn_pool = get_config_max_conn_pool_size();

		backend->pending_dbconn = g_ptr_array_new();

		if (0 != network_mysqld_con_set_address(&backend->addr, address)) {
			return;
		}

		g_ptr_array_add(srv->backend_pool, backend);
	}
}

#define GETTEXT_PACKAGE "xxfs_dbproxy"

int main(int argc, char **argv) {
	network_mysqld_table *table;

	/* read the command-line options */
	GOptionContext *option_ctx;
	GOptionGroup *option_grp;
	GError *gerr = NULL;
	int i;
	int exit_code = 0;
	int print_version = 0;
	int daemon_mode = 0;
	int start_proxy = 1;
	const gchar *check_str = NULL;

	gchar *partition_info_host = NULL;
	gchar *partition_info_db = NULL;
	gchar *db_user = NULL;
	gchar *db_passwd = NULL;
	gchar *config_file = NULL;
	gchar *log_file = NULL;
	gchar *max_conn_pool = NULL;
	int log_all_queries = 0;
	int log_debug_msgs = 0;
	int log_raw_data = 0;

	GOptionEntry admin_entries[] = {
		{ "admin-address", 'a', 0, G_OPTION_ARG_STRING, NULL, "listening address:port of internal admin-server (default: :4041)", "<host:port>"},

		{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
	};

	GOptionEntry proxy_entries[] = {
		{ "proxy-address", 'p', 0, G_OPTION_ARG_STRING, NULL, "listening address:port of the proxy-server (default: :4040)", "<host:port>"},

		{ "partition-info-host", 'h', 0, G_OPTION_ARG_STRING, NULL, "host name of table partition info (default: not set)", "<host>"},
		{ "partition-info-database", 'd', 0, G_OPTION_ARG_STRING, NULL, "database name of table partition info (default: not set)", "<database>"},
		{ "db-user", 'u', 0, G_OPTION_ARG_STRING, NULL, "db user for connecting to the proxy and database partititons (default: not set)", "<userid>"},
		{ "db-user-password", 'P', 0, G_OPTION_ARG_STRING, NULL, "db user password for connecting to the proxy and database partititons (default: not set)", "password"},

		{ "proxy-skip-profiling", 0, G_OPTION_FLAG_REVERSE, G_OPTION_ARG_NONE, NULL, "disables profiling of queries (default: enabled)", NULL},

		{ "proxy-fix-bug-25371", 0, 0, G_OPTION_ARG_NONE, NULL, "fix bug #25371 (mysqld > 5.1.12) for older libmysql versions", NULL},
		{ "proxy-lua-script", 0, 0, G_OPTION_ARG_STRING, NULL, "filename of the lua script (default: not set)", "<file>"},


		{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
	};

	GOptionEntry main_entries[] = {
		{ "version", 'V', 0, G_OPTION_ARG_NONE, NULL, "Show version", NULL},
		{ "daemon", 'D', 0, G_OPTION_ARG_NONE, NULL, "Start in daemon-mode", NULL},
		{ "pid-file", 0, 0, G_OPTION_ARG_STRING, NULL, "PID file in case we are started as daemon", "<file>"},
		{ "config-file", 'c', 0, G_OPTION_ARG_STRING, NULL, "configuration file (default is ./xxfs_dbproxy.conf)", "<file>"},
		{ "log-file", 'l', 0, G_OPTION_ARG_STRING, NULL, "log file (default is not set, using syslog)", "<file>"},
		{ "max-conn-pool-size", 'm', 0, G_OPTION_ARG_STRING, NULL, "max backend connections for each shard(default: 50)", "<number>"},
		{ "log-all-queries", 'L', 0, G_OPTION_ARG_NONE, NULL, "Log all queries(default: disabled)", NULL},
		{ "log-debug-messages", 'g', 0, G_OPTION_ARG_NONE, NULL, "Log debug messages(default: disabled)", NULL},
		{ "log-raw-data", 'r', 0, G_OPTION_ARG_NONE, NULL, "Log raw data sent/recved(default: disabled)", NULL},

		{ NULL, 0, 0, G_OPTION_ARG_NONE, NULL, NULL, NULL}
	};


	if (!GLIB_CHECK_VERSION(2, 6, 0)) {
		log_error("the glib header are too old, need at least 2.6.0, got: %d.%d.%d",
				GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION);
	}

	check_str = glib_check_version(GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION);

	if (check_str) {
		log_error("%s, got: lib=%d.%d.%d, headers=%d.%d.%d",
				check_str,
				glib_major_version, glib_minor_version, glib_micro_version,
				GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION, GLIB_MICRO_VERSION);
	}

	srv = network_mysqld_init();
	srv->config.network_type = NETWORK_TYPE_PROXY; /* doesn't matter anymore */
	srv->config.proxy.fix_bug_25371 = 0; /** double ERR packet on AUTH failures */
	srv->config.proxy.profiling = 1;
	srv->config.proxy.log_debug_messages = 1;
	set_debug_msg_logging(true);


	i = 0;
	admin_entries[i++].arg_data = &(srv->config.admin.address);

	i = 0;
	proxy_entries[i++].arg_data = &(srv->config.proxy.address);
	proxy_entries[i++].arg_data = &partition_info_host;
	proxy_entries[i++].arg_data = &partition_info_db;
	proxy_entries[i++].arg_data = &db_user;
	proxy_entries[i++].arg_data = &db_passwd;

	proxy_entries[i++].arg_data = &(srv->config.proxy.profiling);

	proxy_entries[i++].arg_data = &(srv->config.proxy.fix_bug_25371);
	proxy_entries[i++].arg_data = &(srv->config.proxy.lua_script);

	i = 0;
	main_entries[i++].arg_data = &(print_version);
	main_entries[i++].arg_data = &(daemon_mode);
	main_entries[i++].arg_data = &(srv->config.pid_file);
	main_entries[i++].arg_data = &config_file;
	main_entries[i++].arg_data = &log_file;
	main_entries[i++].arg_data = &max_conn_pool;
	main_entries[i++].arg_data = &log_all_queries;
	main_entries[i++].arg_data = &log_debug_msgs;
	main_entries[i++].arg_data = &log_raw_data;

	option_ctx = g_option_context_new("- SpockProxy");
	g_option_context_add_main_entries(option_ctx, main_entries, GETTEXT_PACKAGE);

	option_grp = g_option_group_new("admin", "admin module", "Show options for the admin-module", NULL, NULL);
	g_option_group_add_entries(option_grp, admin_entries);
	g_option_context_add_group(option_ctx, option_grp);

	option_grp = g_option_group_new("proxy", "proxy-module", "Show options for the proxy-module", NULL, NULL);
	g_option_group_add_entries(option_grp, proxy_entries);
	g_option_context_add_group(option_ctx, option_grp);

	if (FALSE == g_option_context_parse(option_ctx, &argc, &argv, &gerr)) {
		log_error("%s", gerr->message);

		g_error_free(gerr);

		return -1;
	}

	g_option_context_free(option_ctx);

	if (config_file && config_file[0] != '\0')
		load_config_file(config_file);
	else
		load_config_file("xxfs_dbproxy.conf");

	add_config_string("PARTITION_INFO_HOST", partition_info_host);
	add_config_string("PARTITION_INFO_DB", partition_info_db);
	add_config_string("DB_USER", db_user);
	add_config_string("DB_PASSWD", db_passwd);
	add_config_string("LOGFILE", log_file);
	add_config_string("MAX_CONN_POOL_SIZE", max_conn_pool);

	add_config_string("LOG_ALL_QUERIES", log_all_queries ? "1" : "0");
	add_config_string("LOG_DEBUG_MSG", log_debug_msgs ? "1" : "0");
	add_config_string("LOG_RAW_DATA", log_raw_data ? "1" : "0");

	if (srv->config.admin.address == NULL)
		srv->config.admin.address = g_strdup(get_config_string("ADMIN_ADDRESS"));
	if (srv->config.proxy.address == NULL)
		srv->config.proxy.address = g_strdup(get_config_string("PROXY_ADDRESS"));

	srv->config.proxy.profiling = get_config_int("SKIP_PROFILING", srv->config.proxy.profiling);
	srv->config.proxy.fix_bug_25371 = get_config_int("FIX_BUG_25371", srv->config.proxy.fix_bug_25371);
	if (srv->config.proxy.lua_script == NULL)
		srv->config.proxy.lua_script = get_config_string("LUA_SCRIPT");
	srv->config.proxy.log_debug_messages = get_config_int("LOG_DEBUG_MSG", srv->config.proxy.log_debug_messages);
	set_debug_msg_logging(srv->config.proxy.log_debug_messages);

	print_version = get_config_int("PRINT_PROXY_VERSION", print_version);
	daemon_mode = get_config_int("DAEMON_MODE", daemon_mode);
	if (srv->config.pid_file == NULL)
		srv->config.pid_file = get_config_string("PID_FILE");

#if defined(HAVE_LUA_H) && defined(LIBDIR)
	/**
	 * if the LUA_PATH is not set, set a good default 
	 */
	if (!g_getenv("LUA_PATH")) {
		g_setenv("LUA_PATH", LUA_PATHSEP LUA_PATHSEP LIBDIR "/?.lua", 1);
	}
#endif

	if (print_version) {
		printf("%s, build time: %s %s\r\n", PACKAGE_STRING, __DATE__, __TIME__);
		return 0;
	}

	log_info("%s, build time: %s %s\r\n", PACKAGE_STRING, __DATE__, __TIME__);

	if(database_lookup_load() <0) exit(0);

	if (start_proxy) {
		if (!srv->config.proxy.address) srv->config.proxy.address = g_strdup(":4040");
		if (!srv->config.proxy.backend_addresses) {
			srv->config.proxy.backend_addresses = g_new0(char *, 2);
			srv->config.proxy.backend_addresses[0] = g_strdup("127.0.0.1:3306");
		}
	}

	if (!srv->config.admin.address) srv->config.admin.address = g_strdup(":4041");

	/*
	 *  If you add a new command, please update help_select() above
	 *
	 */
	table = network_mysqld_table_init();
	table->select = connections_select;
	table->user_data = srv;
	g_hash_table_insert(srv->tables, g_strdup("proxy_connections"), table);

	table = network_mysqld_table_init();
	table->select = config_select;
	table->user_data = srv;
	g_hash_table_insert(srv->tables, g_strdup("proxy_config"), table);

	table = network_mysqld_table_init();
	table->select = help_select;
	table->user_data = srv;
	g_hash_table_insert(srv->tables, g_strdup("help"), table);

	init_backend_pool(srv);

#ifndef _WIN32	
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGUSR1, signal_handler);
	signal(SIGUSR2, signal_handler);
	signal(SIGPIPE, SIG_IGN);

	if (daemon_mode) {
		daemonize();
	}
#endif
	if (srv->config.pid_file) {
		int fd;
		gchar *pid_str;

		/**
		 * write the PID file
		 */

		if (-1 == (fd = open(srv->config.pid_file, O_WRONLY | O_TRUNC | O_CREAT, 0600))) {
			log_error("%s.%d: open(%s) failed: %s",
					__FILE__, __LINE__,
					srv->config.pid_file,
					strerror(errno));
			return -1;
		}

		pid_str = g_strdup_printf("%d", getpid());

		write(fd, pid_str, strlen(pid_str));
		g_free(pid_str);

		close(fd);
	}

	network_mysqld_init_libevent(srv);

	if (network_mysqld_thread(srv)) {
		/* looks like we failed */

		exit_code = -1;
	}

	network_mysqld_free(srv);

	return exit_code;
}

