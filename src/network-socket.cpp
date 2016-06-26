

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "network-socket.h"
#include "network-mysqld-proto.h"
#include "messages.h"

network_queue *network_queue_init() {
	network_queue *queue;

	queue = g_new0(network_queue, 1);

	queue->chunks = g_queue_new();
	
	return queue;
}

void network_queue_free(network_queue *queue) {
	GString *packet;

	if (!queue) return;

	while ((packet = (GString *)g_queue_pop_head(queue->chunks))) g_string_free(packet, TRUE);

	g_queue_free(queue->chunks);

	g_free(queue);
}

int network_queue_append(network_queue *queue, const char *data, size_t len, int packet_id) {
	unsigned char header[4];
	GString *s;

	network_mysqld_proto_set_header(header, len, packet_id);

	s = g_string_sized_new(len + 4);

	g_string_append_len(s, (gchar *)header, 4);
	g_string_append_len(s, data, len);

	g_queue_push_tail(queue->chunks, s);

	return 0;
}

int network_queue_append_chunk(network_queue *queue, GString *chunk) {
	g_queue_push_tail(queue->chunks, chunk);

	return 0;
}

network_socket *network_socket_init() {
	network_socket *s;
	
	s = g_new0(network_socket, 1);

	s->send_queue = network_queue_init();
	s->recv_queue = network_queue_init();

	s->packet_len = PACKET_LEN_UNSET;

	s->default_db = g_string_new(NULL);
	s->username   = g_string_new(NULL);
	s->scrambled_password = g_string_new(NULL);
	s->scramble_buf = g_string_new(NULL);
	s->auth_handshake_packet = g_string_new(NULL);
	s->scrambled_hash = g_string_new(NULL);
	
	CREATE_PERF(s)

	return s;
}

void network_socket_free(network_socket *s) {
	if (!s) return;

	network_queue_free(s->send_queue);
	network_queue_free(s->recv_queue);

	if (s->fd != -1) {
            /*dqm
        log_info("%s:%d SOCKET=%d: closing, remote addr=%s.\n",
                __FILE__, __LINE__, s->fd, s->addr.str ? s->addr.str : "");
             * */
		closesocket(s->fd);
	}

	if (s->addr.str) {
		g_free(s->addr.str);
	}

	g_string_free(s->scramble_buf, TRUE);
	g_string_free(s->auth_handshake_packet, TRUE);
	g_string_free(s->username,   TRUE);
	g_string_free(s->default_db, TRUE);
	g_string_free(s->scrambled_password, TRUE);
	g_string_free(s->scrambled_hash, TRUE);

	if ((s->parse.command == COM_INIT_DB) && (s->parse.state.init_db.db_name != NULL) ) {
		g_string_free(s->parse.state.init_db.db_name, TRUE);
        s->parse.state.init_db.db_name = NULL;
    }

	DELETE_PERF(s)

	g_free(s);
}


