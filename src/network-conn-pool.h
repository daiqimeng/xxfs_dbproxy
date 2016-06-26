
#ifndef _NETWORK_CONN_POOL_H_
#define _NETWORK_CONN_POOL_H_

#include <glib.h>

#include "network-socket.h"

typedef struct {
	GHashTable *users; /** GHashTable<GString, GQueue<network_connection_pool_entry>> */

    // number of connections being used by the clients,
    // they do not appear in users hash table
    int num_conns_being_used;
	
	guint max_idle_connections;
	guint min_idle_connections;
} network_connection_pool;

typedef struct {
	network_socket *sock;          /** the idling socket */
	
	network_connection_pool *pool; /** a pointer back to the pool */

	GTimeVal added_ts;             /** added at ... we want to make sure we don't hit wait_timeout */
} network_connection_pool_entry;

network_socket *network_connection_pool_get(network_connection_pool *pool,
		GString *username,
		GString *db);
network_connection_pool_entry *network_connection_pool_add(network_connection_pool *pool, network_socket *sock);
void network_connection_pool_del_byconn(network_connection_pool *pool, network_socket *sock);
void network_connection_pool_remove(network_connection_pool *pool, network_connection_pool_entry *entry);
GQueue *network_connection_pool_get_conns(network_connection_pool *pool, GString *username, GString *db);

int network_connection_pool_get_conns_count(network_connection_pool *pool, GString *username, GString *db);

network_connection_pool *network_connection_pool_init(void);
void network_connection_pool_free(network_connection_pool *pool);


#endif
