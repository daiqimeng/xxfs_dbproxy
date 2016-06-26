
#ifndef _NETWORK_SOCKET_H_
#define _NETWORK_SOCKET_H_

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <mysql.h>

#ifdef HAVE_SYS_TIME_H
/**
 * event.h needs struct timeval and doesn't include sys/time.h itself
 */
#include <sys/time.h>
#endif

#include <sys/types.h>      /** u_char */
#ifndef _WIN32
#include <sys/socket.h>     /** struct sockaddr */

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>     /** struct sockaddr_in */
#endif
#include <netinet/tcp.h>

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>         /** struct sockaddr_un */
#endif
/**
 * use closesocket() to close sockets to be compatible with win32
 */
#define closesocket(x) close(x)
#else
#include <winsock2.h>

#define socklen_t int
#endif
#include <glib.h>
#include <event.h>

#include "perf_monitor.h"


/* a input or output stream */
typedef struct {
	GQueue *chunks;
	size_t len; /* len in all chunks */
	size_t offset; /* offset over all chunks */
} network_queue;

typedef struct {
	union {
		struct sockaddr_in ipv4;
#ifdef HAVE_SYS_UN_H
		struct sockaddr_un un;
#endif
		struct sockaddr common;
	} addr;

	gchar *str;

	socklen_t len;
} network_address;

typedef enum {
    PARSE_COM_QUERY_INIT,
    PARSE_COM_QUERY_FIELD,
    PARSE_COM_QUERY_RESULT,
    PARSE_COM_QUERY_LOAD_DATA,
    PARSE_COM_QUERY_LOAD_DATA_END_DATA
} query_type;

typedef struct tag_server_state_data
{
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
	union 
	{
   		struct 
		{
       		int want_eofs;
            int first_packet;
        } prepare;

        query_type query;

        struct 
		{
        	char state; /** OK, EOF, ERR */
        } auth_result;

        /** track the db in the COM_INIT_DB */
        struct 
		{
       		GString *db_name;
        } init_db;
    } state;
} server_state_data;

typedef struct 
{
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
} server_query_status;

typedef enum {
    NET_RW_STATE_NONE,	// finished or nothing to do
    NET_RW_STATE_WRITE,
    NET_RW_STATE_READ,
    NET_STATE_READ,		// normal inline read
    NET_RW_STATE_ERROR,
    NET_RW_STATE_FINISHED
} read_write_state;

typedef struct {
	int fd;             /**< socket-fd */
	struct event event; /**< events for this fd */

	network_address addr;

	guint32 packet_len; /**< the packet_len is a 24bit unsigned int */
	guint8  packet_id;  /**< id which increments for each packet in the stream */
	

	network_queue *recv_queue;
	network_queue *send_queue;

    // using buffered send for big queries
    char send_buff[64 * 1024];  //default 64K
    int  send_buff_offset; // offset to send
    int send_buff_left;    // number of bytes to send

	off_t to_read;

	/**
	 * data extracted from the handshake  
	 *
	 * all server-side only
	 */
	guint32 mysqld_version;  /**< numberic version of the version string */
	guint32 thread_id;       /**< connection-id, set in the handshake packet */
	GString *scramble_buf;   /**< the 21byte scramble-buf */
	GString *username;       /**< username of the authed connection */
	GString *scrambled_password;  /**< scrambled_pass used to auth */
	GString *scrambled_hash;  /**< scrambled_hash used to send to the client for auth */

	/**
	 * store the auth-handshake packet to simulate a login
	 */
	GString *auth_handshake_packet;
	int is_authed;           /** did a client already authed this connection */

	/**
	 * store the default-db of the socket
	 *
	 * the client might have a different default-db than the server-side due to
	 * statement balancing
	 */	
	GString *default_db;     /** default-db of this side of the connection */

    time_t last_write_time; // last time any write on this socket, used to check idle

	struct
	{
		read_write_state state;

		int		last_errno;				// last error associated to this socket
		guint8 	read_after_write;		// read after the write completes?
		guint8	write_count;			// number of packets to send
	} rw;

    int  bytes_recved;  //for stats only, to log big queries

	// structure that used to be in network_mysqld_con, but needs to be server specific
	// the other one should be removed
	server_state_data		parse;
	server_query_status 	qstat;
	// sooner or later we need to keep profile data
	DEFINE_PERF
} network_socket;


network_queue *network_queue_init(void);
void network_queue_free(network_queue *queue);
int network_queue_append(network_queue *queue, const char *data, size_t len, int packet_id);
int network_queue_append_chunk(network_queue *queue, GString *chunk);

network_socket *network_socket_init(void);
void network_socket_free(network_socket *s);


#endif

