

#include <glib.h>
#include <stdio.h>


#include "network-conn-pool.h"
#include "glib-ext.h"
#include "sys-pedantic.h"

GString *make_lookup( GString *db, GString *username )
{
	GString *lookup = g_string_new(NULL);

	if ( db != NULL && db->str != NULL )
		g_string_append( lookup, db->str);
	else
		g_string_append( lookup, "nodb");

	if ( username != NULL && username->str != NULL )
		g_string_append( lookup, username->str );	
	else
		g_string_append( lookup, "nouser");

	return lookup;
}


/**
 * connection pools
 *
 * in the pool we manage idle connections
 * - keep them up as long as possible
 * - make sure we don't run out of seconds
 * - if the client is authed, we have to pick connection with the same user
 * - ...  
 */

/**
 * create a empty connection pool entry
 *
 * @return a connection pool entry
 */
network_connection_pool_entry *network_connection_pool_entry_init(void) {
	network_connection_pool_entry *e;

	e = g_new0(network_connection_pool_entry, 1);

	return e;
}

/**
 * free a conn pool entry
 *
 * @param e the pool entry to free
 * @param free_sock if true, the attached server-socket will be freed too
 */
void network_connection_pool_entry_free(network_connection_pool_entry *e, gboolean free_sock) {
	if (!e) return;

	if (e->sock && free_sock) {
		network_socket *sock = e->sock;
			
		event_del(&(sock->event));
		network_socket_free(sock);
	}

	g_free(e);
}

/**
 * free all pool entries of the queue
 *
 * used as GDestroyFunc in the user-hash of the pool
 *
 * @see network_connection_pool_init
 */
static void g_queue_free_all(gpointer q) {
	GQueue *queue = (GQueue *)q;
	network_connection_pool_entry *entry;

	while ((entry = (network_connection_pool_entry *)g_queue_pop_head(queue))) network_connection_pool_entry_free(entry, TRUE);

	g_queue_free(queue);
}

/**
 * init a connection pool
 */
network_connection_pool *network_connection_pool_init(void) {
	network_connection_pool *pool;

	pool = g_new0(network_connection_pool, 1);

	pool->users = g_hash_table_new_full(g_hash_table_string_hash, g_hash_table_string_equal, g_hash_table_string_free, g_queue_free_all);

	return pool;
}

static gboolean pool_hash_table_true(gpointer key, gpointer value, gpointer UNUSED_PARAM(u)) {
    return TRUE;
}

/**
 * free all entries of the pool
 *
 */
void network_connection_pool_free(network_connection_pool *pool) {
	if (!pool) return;

	g_hash_table_foreach_remove(pool->users, pool_hash_table_true, NULL);

	g_hash_table_destroy(pool->users);

	g_free(pool);
}

/**
 * find the entry which has more than max_idle connections idling
 * 
 * @return TRUE for the first entry having more than _user_data idling connections
 * @see network_connection_pool_get_conns 
 */
static gboolean find_idle_conns(gpointer UNUSED_PARAM(_key), gpointer _val, gpointer _user_data) {
	guint min_idle_conns = *(gint *)_user_data;
	GQueue *conns = (GQueue *)_val;

	return (conns->length > min_idle_conns);
}

GQueue *network_connection_pool_get_conns(network_connection_pool *pool, GString *username, GString *default_db) {
	GQueue *conns = NULL;

	if (username && username->len > 0) {
		GString *lookup = make_lookup( default_db, username );

		conns = (GQueue *)g_hash_table_lookup(pool->users, lookup);

		g_string_free( lookup, TRUE );

		/**
		 * if we know this use, return a authed connection 
		 */
#ifdef DEBUG_CONN_POOL
		log_debug("%s: (get_conns) get user-specific idling connection for '%s' -> %p", G_STRLOC, username->str, conns);
#endif
		if (conns) return conns;
	}

	/**
	 * we don't have a entry yet, check the others if we have more than 
	 * min_idle waiting
	 */

	conns = (GQueue *)g_hash_table_find(pool->users, find_idle_conns, &(pool->min_idle_connections));
#ifdef DEBUG_CONN_POOL
	log_debug("%s: (get_conns) try to find max-idling conns for user '%s' -> %p", G_STRLOC, username ? username->str : "", conns);
#endif

	return conns;
}

/**
 * get a connection count from the pool
 *
 * @param username (optional) name of the auth connection
 */

int network_connection_pool_get_conns_count(network_connection_pool *pool, GString *username, GString *db)
{
	GQueue *conns = network_connection_pool_get_conns(pool, username, db);

	if ( NULL == conns )
		return 0;

	return conns->length;
}


/**
 * get a connection from the pool
 *
 * make sure we have at lease <min-conns> for each user
 * if we have more, reuse a connect to reauth it to another user
 *
 * @param username (optional) name of the auth connection
 */
network_socket *network_connection_pool_get(network_connection_pool *pool,
		GString *username,
		GString *default_db) {

	network_connection_pool_entry *entry = NULL;
	network_socket *sock = NULL;
	GString *lookup = make_lookup( default_db, username );
	GQueue *conns = network_connection_pool_get_conns(pool, username, default_db);

	/**
	 * if we know this use, return a authed connection 
	 */
	if (conns) {
		entry = (network_connection_pool_entry *)g_queue_pop_head(conns);

		if (conns->length == 0) {
			/**
			 * all connections are gone, remove it from the hash
			 */
			g_hash_table_remove(pool->users, lookup);
		}
	}

	g_string_free( lookup, TRUE );

	if (!entry) {
#ifdef DEBUG_CONN_POOL
		log_debug("%s: (get) no entry for user '%s' -> %p", G_STRLOC, username ? username->str : "", conns);
#endif
		return NULL;
	}

	sock = entry->sock;

	network_connection_pool_entry_free(entry, FALSE);

	/* remove the idle handler from the socket */	
	event_del(&(sock->event));
		
#ifdef DEBUG_CONN_POOL
	log_debug("%s: (get) got socket for user '%s' -> %p", G_STRLOC, username ? username->str : "", sock);
#endif

    pool->num_conns_being_used ++;

	return sock;
}

/**
 * add a connection to the connection pool
 *
 */
network_connection_pool_entry *network_connection_pool_add(network_connection_pool *pool, network_socket *sock) {
	network_connection_pool_entry *entry;
	GQueue *conns = NULL;
	GString *lookup = make_lookup( sock->default_db, sock->username );
        entry = network_connection_pool_entry_init();
	entry->sock = sock;
	entry->pool = pool;

	g_get_current_time(&(entry->added_ts));
	
#ifdef DEBUG_CONN_POOL
	log_debug("%s: (add) adding socket to pool for user '%s' -> %p", G_STRLOC, sock->username->str, sock);
#endif

	if (NULL == (conns = (GQueue *)g_hash_table_lookup(pool->users, lookup))) {
		conns = g_queue_new();

		g_hash_table_insert(pool->users, lookup, conns);
	}
	else
		g_string_free( lookup, TRUE );

	g_queue_push_tail(conns, entry);

	return entry;
}

/**
 * remove the connection referenced by entry from the pool 
 */
void network_connection_pool_remove(network_connection_pool *pool, network_connection_pool_entry *entry) {
	network_socket *sock = entry->sock;
	GQueue *conns;
	GString *lookup = make_lookup( sock->default_db, sock->username );

	if (NULL == (conns = (GQueue *)g_hash_table_lookup(pool->users, lookup))) {
		g_string_free( lookup , TRUE);
		return;
	}

	g_string_free( lookup, TRUE );

	network_connection_pool_entry_free(entry, FALSE);

	g_queue_remove(conns, entry);
}

void network_connection_pool_del_byconn(network_connection_pool *pool, network_socket *sock) {

    int len = 0;
	GString *lookup = make_lookup( sock->default_db, sock->username );
	GQueue *conns = NULL;
    network_connection_pool_entry *entry = NULL;

	conns = (GQueue *)g_hash_table_lookup(pool->users, lookup);


    if (conns == NULL) {
        g_string_free( lookup, TRUE );
        return;
    }

    len = conns->length;

    for (; len > 0 ; len--) {
        entry = (network_connection_pool_entry *)g_queue_pop_head(conns);         
        g_queue_push_tail(conns, entry);

        if (entry->sock == sock)
            break;
        else
            entry = NULL;
    }

    if (entry) {
        network_connection_pool_remove(pool, entry);
    }

    if (conns->length == 0)
        g_hash_table_remove(pool->users, conns);
        
    g_string_free( lookup, TRUE );
}

