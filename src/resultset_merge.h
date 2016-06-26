

/**
* @package resultset_merge
*/
#ifndef __RESULTSET_MERGE__
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <glib.h>

#include <mysqld_error.h> /** for ER_UNKNOWN_ERROR */
#include "sys-pedantic.h"
#include "sql-tokenizer.h"
#include "network-mysqld.h"
#include "network-mysqld-proto.h"
#include "network-conn-pool.h"
#include "messages.h"



#define MAX_NAME_LEN 64 
#define MAX_ORDER_COLS 16 
#define MAX_LIMIT G_MAXINT32


struct ORDER_BY
{
    ORDER_BY()
    {
        name[0] = 0;
        desc = 0;
        type = 0;
        pos = 0;
    }
	char name[MAX_NAME_LEN];	//name of field ordered by
//	char expr[MAX_NAME_LEN];    	// not supported right now
	unsigned int desc;	    	// 0 for ASC(SQL Defalut), 1 for DESC
	unsigned int type;		// type of column(0x00-0x10,0xf6-0xff)
	unsigned int pos;		// pos of col:0 ... #col-1 
};

typedef struct
{
	guint offset;     /// default 0
	guint row_count;  /// default  G_MAXUINT64 
}LIMIT;


gint __is_prior_to(GString* pkt1, GString* pkt2, ORDER_BY order_array[], int order_array_size);


gint  skip_field(GString* packet, guint* _off, guint skip);

GList *get_field_attr(GList *chunk, ORDER_BY *order_array, guint order_array_size, guint* field_cnt);

gint resultset_merge(GQueue* send_queue,  GPtrArray* recv_queues, GPtrArray* sql_tokens);

gint __append_packet(GQueue* send, GString* pkt);

gint __pick_one_record();

sql_token * get_token(GPtrArray* tokens, unsigned int iter);

gint get_order_by(GPtrArray* tokens, int* iter_ptr, ORDER_BY order_array[], int* order_array_size_ptr);

gint get_limit(GPtrArray *tokens, int* iter_ptr, LIMIT* limit_ptr);

gint sql_parser(GPtrArray *tokens, ORDER_BY order_array[], int* order_array_size_ptr, LIMIT* limit_ptr);

gint get_str_len(GString* pkt, uint *str_len);

int get_col_type(GList* chunk_head, const char* str);

int is_decimal(int type);
int is_float(int type);

int unix_timestamp(GQueue* send_queue, GPtrArray* recv_queues, guint *pkt_count);

int stored_procedures(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count);

int sum(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count);

int max(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count);

int min(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count);

int count(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count);

int avg(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count);



#endif// __RESULTSET_MERGE__
