

#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>

#include <errno.h>

#include "network-mysqld.h"
#include "network-mysqld-proxy.h"
#include "network-mysqld-proto.h"
#include "messages.h"

#include "sys-pedantic.h"

int config_update(gchar *sql, gpointer user_data);
int config_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data);
int connections_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data);
int help_select(GPtrArray *fields, GPtrArray *rows, gpointer user_data);

/**
 * a simple query handler
 *
 * we handle the basic statements that the mysql-client sends us
 *
 * TODO: we have to split the queries into a basic SQL syntax:
 *
 *   SELECT * 
 *     FROM <table>
 *   [WHERE <field> = <value>]
 *
 * - no joins
 * - no grouping
 *
 *   DELETE
 *     FROM <table>
 * 
 * - no WHERE clause
 *
 * - each table has to have a provider for a table 
 * - each plugin should able to provide tables as needed
 */
int network_mysqld_con_handle_stmt(network_mysqld *srv, network_mysqld_con *con, GString *s) {
	gsize i, j;
	GPtrArray *fields;
	GPtrArray *rows;
	GPtrArray *row;

#define C(x) x, sizeof(x) -1
	
	switch(s->str[NET_HEADER_SIZE]) {
	case COM_QUERY:
		fields = NULL;
		rows = NULL;
		row = NULL;

		if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("select @@version_comment limit 1"))) {
			MYSQL_FIELD *field;

			fields = network_mysqld_proto_fields_init();

			field = network_mysqld_proto_field_init();
			field->name = g_strdup("@@version_comment");
			field->type = FIELD_TYPE_VAR_STRING;
			g_ptr_array_add(fields, field);

			rows = g_ptr_array_new();
			row = g_ptr_array_new();
			g_ptr_array_add(row, g_strdup("MySQL Enterprise Agent"));
			g_ptr_array_add(rows, row);

			con->client->packet_id++;
			network_mysqld_con_send_resultset(con->client, fields, rows);
			
		} else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("select USER()"))) {
			MYSQL_FIELD *field;

			fields = network_mysqld_proto_fields_init();
			field = network_mysqld_proto_field_init();
			field->name = g_strdup("USER()");
			field->type = FIELD_TYPE_VAR_STRING;
			g_ptr_array_add(fields, field);

			rows = g_ptr_array_new();
			row = g_ptr_array_new();
			g_ptr_array_add(row, g_strdup("root"));
			g_ptr_array_add(rows, row);

			con->client->packet_id++;
			network_mysqld_con_send_resultset(con->client, fields, rows);
		} else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("update proxy_config set value=1 where option=\"proxy.profiling\""))) {
			srv->config.proxy.profiling = 1;

			con->client->packet_id++;
			network_mysqld_con_send_ok(con->client);
		} else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("update proxy_config set value=0 where option=\"proxy.profiling\""))) {
			srv->config.proxy.profiling = 0;
	
			con->client->packet_id++;
			network_mysqld_con_send_ok(con->client);
		} else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("stop instance"))) {
			/**
			 * connect to the server via the admin-connection and try to shut down the server
			 * with COM_SHUTDOWN
			 */

			con->client->packet_id++;
			network_mysqld_con_send_ok(con->client);
		} else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, C("start instance"))) {
			/**
			 * start the instance with fork() and monitor it
			 */

			con->client->packet_id++;
			network_mysqld_con_send_ok(con->client);
		}
		else if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, "update proxy_config", sizeof("update proxy_config") - 1)) 
		{
			// UPDATE proxy_config 
			if ( config_update(s->str + NET_HEADER_SIZE + 1, srv) != RET_SUCCESS)
			{
				char sz[256];
				snprintf(sz, sizeof(sz), "unsupported update command: %s", 
					s->str + NET_HEADER_SIZE);
				con->client->packet_id++;
				network_mysqld_con_send_error(con->client, (gchar*)sz, sizeof(sz));
			}
			else
			{
				const char update_resp[] = "Rows matched: %d  Changed: %d  Warnings: %d";
				char sz[128];
				/*
				 * 	30 00 00 01 00 00 00 02  0 . . . . . . .
					00 00 00 28 52 6f 77 73  . . . ( R o w s
					20 6d 61 74 63 68 65 64    m a t c h e d
					3a 20 30 20 20 43 68 61  :   0     C h a
					6e 67 65 64 3a 20 30 20  n g e d :   0  
					20 57 61 72 6e 69 6e 67    W a r n i n g
					73 3a 20 30  s :   0


					(Rows matched: %d  Changed: %d  Warnings: %d
				*/
				con->client->packet_id++;
				sprintf( sz, update_resp, 1, 1, 0 );	
				network_mysqld_con_send_ok_full(con->client, 1, 0, 0x0002, 0, sz);
			}
		}
		else 
		{
			int have_sent = 0;
			/* check if the table is known */
			if (0 == g_ascii_strncasecmp(s->str + NET_HEADER_SIZE + 1, "select * from ", sizeof("select * from ") - 1)) {
				network_mysqld_table *table;
				GString *table_name = g_string_new(NULL);

				g_string_append_len(table_name, 
						s->str + (NET_HEADER_SIZE + 1 + sizeof("select * from ") - 1),
						s->len - (NET_HEADER_SIZE + 1 + sizeof("select * from ") - 1));

				if ((table = (network_mysqld_table *)g_hash_table_lookup(srv->tables, table_name->str))) {
					if (table->select) {
						fields = network_mysqld_proto_fields_init();
						rows = g_ptr_array_new();

						table->select(fields, rows, table->user_data);
			
						con->client->packet_id++;
						network_mysqld_con_send_resultset(con->client, fields, rows);

						have_sent = 1;
					} 
				} 
				else if (0 == g_ascii_strncasecmp(table_name->str, "proxy_config", sizeof("proxy_config")))
				{
					fields = network_mysqld_proto_fields_init();
					rows = g_ptr_array_new();
					config_select(fields, rows, srv);
					con->client->packet_id++;
					network_mysqld_con_send_resultset(con->client, fields, rows);
					have_sent = 1;
				}
				else if (0 == g_ascii_strncasecmp(table_name->str,"proxy_connections", sizeof("proxy_connections")))
				{
					fields = network_mysqld_proto_fields_init();
					rows = g_ptr_array_new();
					connections_select(fields, rows, srv);
					con->client->packet_id++;
					network_mysqld_con_send_resultset(con->client, fields, rows);
					have_sent = 1;
				}	
				else if (0 == g_ascii_strncasecmp(table_name->str,"pool_connections", sizeof("pool_connections")))
				{
					fields = network_mysqld_proto_fields_init();
					rows = g_ptr_array_new();
					pool_connections_select(fields, rows, srv);
					con->client->packet_id++;
					network_mysqld_con_send_resultset(con->client, fields, rows);
					have_sent = 1;
				}
				else if (0 == g_ascii_strncasecmp(table_name->str,"pool_configs", sizeof("pool_configs")))
				{
					fields = network_mysqld_proto_fields_init();
					rows = g_ptr_array_new();
					pool_config_select(fields, rows, srv);
					con->client->packet_id++;
					network_mysqld_con_send_resultset(con->client, fields, rows);
					have_sent = 1;
				}
				else if ( g_ascii_strncasecmp(table_name->str, "help", sizeof("help")))
				{
					fields = network_mysqld_proto_fields_init();
					rows = g_ptr_array_new();
					help_select(fields, rows, srv);
					con->client->packet_id++;
					network_mysqld_con_send_resultset(con->client, fields, rows);
					have_sent = 1;

				}
				else 
				{
					log_info("table '%s' not found", table_name->str);
				}
				g_string_free(table_name, TRUE);
			} 
			

			if (!have_sent) {
				con->client->packet_id++;
				network_mysqld_con_send_error(con->client, C("booh"));
			}
		}

		/* clean up */
		if (fields) {
			network_mysqld_proto_fields_free(fields);
			fields = NULL;
		}

		if (rows) {
			for (i = 0; i < rows->len; i++) {
				row = (GPtrArray *)rows->pdata[i];

				for (j = 0; j < row->len; j++) {
					g_free(row->pdata[j]);
				}

				g_ptr_array_free(row, TRUE);
			}
			g_ptr_array_free(rows, TRUE);
			rows = NULL;
		}

		break;
	case COM_QUIT:
		break;
	default:
	{
		char sz[128];
		snprintf(sz, sizeof(sz), "unsupported COM_*(0x%x) command", 
				s->str[NET_HEADER_SIZE]);
		con->client->packet_id++;
		network_mysqld_con_send_error(con->client, (gchar*)sz, sizeof(sz));
		break;
	}
	}
#undef C					
	return 0;
}

retval_t proxy_create_handshake(network_mysqld *srv, network_mysqld_con *con);


NETWORK_MYSQLD_PLUGIN_PROTO(server_read_query) {
	GString *s;
	GList *chunk;
	network_socket *recv_sock;

	recv_sock = con->client;

	chunk = recv_sock->recv_queue->chunks->tail;
	s = (GString *)(chunk->data);

	if (s->len != recv_sock->packet_len + NET_HEADER_SIZE) return RET_SUCCESS;
	
	network_mysqld_con_handle_stmt(srv, con, s);
		
	con->parse.len = recv_sock->packet_len;

	g_string_free((GString *)(chunk->data), TRUE);
	recv_sock->packet_len = PACKET_LEN_UNSET;

	g_queue_delete_link(recv_sock->recv_queue->chunks, chunk);

	con->state = CON_STATE_SEND_QUERY_RESULT;

	return RET_SUCCESS;
}

NETWORK_MYSQLD_PLUGIN_PROTO_GLOBAL(proxy_init);
NETWORK_MYSQLD_PLUGIN_PROTO_GLOBAL(proxy_make_auth_resp);

int network_mysqld_server_connection_init(network_mysqld_con *con) 
{
	con->plugins.con_init             = proxy_init; //server_con_init;
	con->plugins.con_create_auth_result = proxy_make_auth_resp;

	con->plugins.con_read_auth        = NULL; //server_read_auth;
	con->plugins.con_read_query       = server_read_query;
	return 0;
}

int network_mysqld_server_init(network_mysqld_con *con) {
	gchar *address = con->config.admin.address;

	if (0 != network_mysqld_con_set_address(&(con->server->addr), address)) {
		log_error("%s.%d: network_mysqld_con_set_address(%s) failed", __FILE__, __LINE__, con->server->addr.str);
		return -1;
	}
	
	if (0 != network_mysqld_con_bind(con->server)) {
		log_error("%s.%d: network_mysqld_con_bind(%s) failed", __FILE__, __LINE__, con->server->addr.str);
		return -1;
	}

	return 0;
}


