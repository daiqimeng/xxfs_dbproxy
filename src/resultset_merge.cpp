

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
#include "resultset_merge.h"
/**
*	\author Michael Wang
*	\brief  resulset_merge: merging results from multiple databases
*	\test	testing cases for resultset_merge()	
*/

const char EPOCH[] = "1970-01-01 00:00:00";
const char* type_name[] =
{
"FIELD_TYPE_DECIMAL", 	//0x00   
"FIELD_TYPE_TINY", 	//0x01   
"FIELD_TYPE_SHORT", 	//0x02 
"FIELD_TYPE_LONG", 	//0x03 
"FIELD_TYPE_FLOAT",     //0x04    
"FIELD_TYPE_DOUBLE",    //0x05 
"FIELD_TYPE_NULL",      //0x06 
"FIELD_TYPE_TIMESTAMP",	//0x07 
"FIELD_TYPE_LONGLONG", 	//0x08   
"FIELD_TYPE_INT24", 	//0x09   
"FIELD_TYPE_DATE", 	//0x0a  
"FIELD_TYPE_TIME",     	//0x0b   
"FIELD_TYPE_DATETIME", 	//0x0c   
"FIELD_TYPE_YEAR", 	//0x0d   
"FIELD_TYPE_NEWDATE", 	//0x0e   
"FIELD_TYPE_VARCHAR",	//0x0f (new in MySQL 5.0)
"FIELD_TYPE_BIT", 	//0x10   (new in MySQL 5.0)
"FIELD_TYPE_NEWDECIMAL",//0xf6 (new in MYSQL 5.0)
"FIELD_TYPE_ENUM", 	//0xf7   
"FIELD_TYPE_SET",  	//0xf8   
"FIELD_TYPE_TINY_BLOB", //0xf9   
"FIELD_TYPE_MEDIUM_BLOB",//0xfa   
"FIELD_TYPE_LONG_BLOB", //0xfb   
"FIELD_TYPE_BLOB", 	//0xfc   
"FIELD_TYPE_VAR_STRING",//0xfd   
"FIELD_TYPE_STRING",	//0xfe  
"FIELD_TYPE_GEOMETRY"	//0xff   
};
char *ConvertBufToHex(unsigned char *pBuf, unsigned int *iLength); //gcc will complain if without declaration
/**
 *  	OK Packet                   0x00
 *   	Error Packet                0xff  255
 *    	Result Set Packet           1-250 (first byte of Length-Coded Binary)
 *     	Field Packet                1-250 ("")
 *      Row Data Packet             1-250 ("")
 *      EOF Packet                  0xfe  254
 */
guchar __get_pkt_type(GString* pkt)
{
	//get the packet type
	return (unsigned char)pkt->str[NET_HEADER_SIZE];
}

/**
*	is_prior_to Relation(record_A * record_B) defined ORDER BY
*       Do the comparison work for __pick_one_record()	
*	return 1 if record A is prior to record B 
*       else   0
*/
gint __is_prior_to(GString* pkt1, GString* pkt2, ORDER_BY order_array[], int order_array_size)
{

#if 0 
{
	unsigned int iLength = pkt1->len;
	char *pData ;
	pData = ConvertBufToHex((unsigned char*) (pkt1->str), (unsigned int *)&iLength );
	fprintf(stderr,"pkt1\n%s\n", pData );
	free( pData );
	
	iLength = pkt2->len;
	pData = ConvertBufToHex((unsigned char*) (pkt2->str), (unsigned int *)&iLength );
	fprintf(stderr, "pkt2\n%s\n", pData );
	free( pData );
}
#endif


	int i=0;
	for(i=0; i<= order_array_size; i++)
	{
		guint off_1 = NET_HEADER_SIZE;// + order_array[i].offset;
		guint off_2 = NET_HEADER_SIZE;// + order_array[i].offset;
		gchar* str1 = "";
		gchar* str2 = "";
		int ret = 0; 
		switch(order_array[i].type)
		{
			case FIELD_TYPE_NEWDECIMAL:	//0xf6 (new in MYSQL 5.0)
			case FIELD_TYPE_DECIMAL: 	//0x00   
			case FIELD_TYPE_TINY: 		//0x01   
		  	case FIELD_TYPE_SHORT: 		//0x02 
			case FIELD_TYPE_LONG:	 	//0x03 
			case FIELD_TYPE_LONGLONG:	//0x08   
			case FIELD_TYPE_INT24: 		//0x09   
				//convert into integer
				log_debug("[%d] type:%d:%s\n", i, order_array[i].type, type_name[(order_array[i].type > 0x10 ? order_array[i].type - 0xf6 + 0x11:order_array[i].type)]);
				//move offset to the target field
				skip_field(pkt1, &off_1, order_array[i].pos);
				skip_field(pkt2, &off_2, order_array[i].pos);
				str1 = network_mysqld_proto_get_string_column(pkt1, &off_1);
				str2 = network_mysqld_proto_get_string_column(pkt2, &off_2);

				// convert str to longlong
				glong integer_1;
				glong integer_2;
				if( NULL == str1 )
					integer_1 = G_MINLONG;
				else
					integer_1 = atoll(str1); 
				if( NULL == str2 )
					integer_2 = G_MINLONG;
				else		
					integer_2 = atoll(str2); 
				log_debug("integer_1:%d, integer_2:%d \n", integer_1, integer_2);
				g_free(str1);
				g_free(str2);
				if( integer_1 == integer_2)
					return 1;
				if((order_array[i].desc && integer_1 > integer_2) || (!order_array[i].desc && integer_1 < integer_2))
					//desc > ; asc <
					return 1;
				if((order_array[i].desc && integer_1 < integer_2) || (!order_array[i].desc && integer_1 > integer_2))
					//desc < ; asc >
					return 0;
				//otherwise, we need look further at next order by field
				break;
			case FIELD_TYPE_FLOAT:		//0x04    
			case FIELD_TYPE_DOUBLE:    	//0x05 
				{
					//convert into double
					log_debug("[%d] type:%d:%s\n", i, order_array[i].type, type_name[(order_array[i].type > 0x10 ? order_array[i].type - 0xf6 + 0x11:order_array[i].type)]);

					skip_field(pkt1, &off_1, order_array[i].pos);
					skip_field(pkt2, &off_2, order_array[i].pos);
					str1 = network_mysqld_proto_get_string_column(pkt1, &off_1);
					str2 = network_mysqld_proto_get_string_column(pkt2, &off_2);

					gdouble double_1;
					gdouble double_2;
					if(str1 == NULL)
						double_1 = G_MINDOUBLE;
					else
						double_1 = strtod(str1, NULL); // convert str to longlong

					if(str2 == NULL)
						double_2 = G_MINDOUBLE;
					else
						double_2 = strtod(str2, NULL); // convert str to longlong
					log_debug("double_1:%f, double_2:%f \n", double_1, double_2);

					g_free(str1);
					g_free(str2);
					if( double_1 == double_2 )
						return 1;
					if((order_array[i].desc && double_1 > double_2) || (!order_array[i].desc && double_1 < double_2))
						//desc > ; asc <
						return 1;
					if((order_array[i].desc && double_1 < double_2) || (!order_array[i].desc && double_1 > double_2))
						//desc < ; asc >
						return 0;
					//otherwise, we need look further at next order by field

					break;
				}

			case FIELD_TYPE_DATE:	 	//0x0a  
				{
					skip_field(pkt1, &off_1, order_array[i].pos);
					skip_field(pkt2, &off_2, order_array[i].pos);
					str1 = network_mysqld_proto_get_string_column(pkt1, &off_1);
					str2 = network_mysqld_proto_get_string_column(pkt2, &off_2);
					if(str1 == NULL)
					{
						str1 = g_strndup(EPOCH, strlen(EPOCH));
					}
					if(str2 == NULL)
					{
						str2 = g_strndup(EPOCH, strlen(EPOCH));
					}

					struct tm tm1;
					struct tm tm2;
					bzero(&tm1, sizeof(struct tm));
					bzero(&tm2, sizeof(struct tm));
					strptime(str1, "%Y-%m-%d", &tm1);
					strptime(str2, "%Y-%m-%d", &tm2);

					int diff[6] ;
					diff[0]	= tm1.tm_year - tm2.tm_year; 
					diff[1]	= tm1.tm_mon  - tm2.tm_mon;
					diff[2]	= tm1.tm_mday - tm2.tm_mday;

					for(int p=0; p<3; p++)
					{
						if(order_array[i].desc && diff[p]>0 || !order_array[i].desc && diff[p]<0) 
							return 1;
						if(order_array[i].desc && diff[p]<0 || !order_array[i].desc && diff[p]>0)
							return 0;
					}
					return 1;
				}

			case FIELD_TYPE_TIME:    	//0x0b   
				{
					skip_field(pkt1, &off_1, order_array[i].pos);
					skip_field(pkt2, &off_2, order_array[i].pos);
					str1 = network_mysqld_proto_get_string_column(pkt1, &off_1);
					str2 = network_mysqld_proto_get_string_column(pkt2, &off_2);

					struct tm tm1;
					struct tm tm2;
					bzero(&tm1, sizeof(struct tm));
					bzero(&tm2, sizeof(struct tm));
					strptime(str1, "%H:%M:%S", &tm1);
					strptime(str2, "%H:%M:%S", &tm2);

					int diff[3] ;
					diff[0] = tm1.tm_hour - tm2.tm_hour;
					diff[1] = tm1.tm_min  - tm2.tm_min;
					diff[2] = tm1.tm_sec  - tm2.tm_sec;

					for(int p=0; p<3; p++)
					{
						if(order_array[i].desc && diff[p]>0 || !order_array[i].desc && diff[p]<0) 
							return 1;
						if(order_array[i].desc && diff[p]<0 || !order_array[i].desc && diff[p]>0)
							return 0;
					}
					return 1;
				}

			case FIELD_TYPE_TIMESTAMP:	//0x07 
			case FIELD_TYPE_DATETIME: 	//0x0c   
				{
					skip_field(pkt1, &off_1, order_array[i].pos);
					skip_field(pkt2, &off_2, order_array[i].pos);
					str1 = network_mysqld_proto_get_string_column(pkt1, &off_1);
					str2 = network_mysqld_proto_get_string_column(pkt2, &off_2);
					if(str1 == NULL)
					{
						str1 = g_strndup(EPOCH, strlen(EPOCH));
					}
					if(str2 == NULL)
					{
						str2 = g_strndup(EPOCH, strlen(EPOCH));
					}
					//fprintf(stderr, "%s %s \n", str1, str2);	
					struct tm tm1;
					struct tm tm2;
					bzero(&tm1, sizeof(struct tm));
					bzero(&tm2, sizeof(struct tm));
					strptime(str1, "%Y-%m-%d %H:%M:%S", &tm1);
					strptime(str2, "%Y-%m-%d %H:%M:%S", &tm2);

					int diff[6] ;
					diff[0]	= tm1.tm_year - tm2.tm_year; 
					diff[1]	= tm1.tm_mon  - tm2.tm_mon;
					diff[2]	= tm1.tm_mday - tm2.tm_mday;
					diff[3] = tm1.tm_hour - tm2.tm_hour;
					diff[4] = tm1.tm_min  - tm2.tm_min;
					diff[5] = tm1.tm_sec  - tm2.tm_sec;

					for(int p=0; p<6; p++)
					{
						if(order_array[i].desc && diff[p]>0 || !order_array[i].desc && diff[p]<0) 
							return 1;
						if(order_array[i].desc && diff[p]<0 || !order_array[i].desc && diff[p]>0)
							return 0;
					}
					return 1;
				}
			case FIELD_TYPE_YEAR:	 	//0x0d   
				{
					skip_field(pkt1, &off_1, order_array[i].pos);
					skip_field(pkt2, &off_2, order_array[i].pos);
					str1 = network_mysqld_proto_get_string_column(pkt1, &off_1);
					str2 = network_mysqld_proto_get_string_column(pkt2, &off_2);
					if(str1 == NULL)
					{
						str1 = g_strndup(EPOCH, strlen(EPOCH));
					}
					if(str2 == NULL)
					{
						str2 = g_strndup(EPOCH, strlen(EPOCH));
					}
					if(order_array[i].desc) 
						return atol(str1) > atol(str2); 	
					else
						return atol(str1) < atol(str2); 	
				}
			case FIELD_TYPE_NEWDATE: 	//0x0e   
				log_debug("[%d] type:%d:%s\n", i, order_array[i].type, type_name[(order_array[i].type > 0x10 ? order_array[i].type - 0xf6 + 0x11:order_array[i].type)]);

				return 1;
//			case FIELD_TYPE_VARCHAR:	//0x0f (new in MySQL 5.0)
			case FIELD_TYPE_VAR_STRING:	//0xfd   
			case FIELD_TYPE_STRING:		//0xfe  
				log_debug("[%d] type:%d:%s\n", i, order_array[i].type, type_name[(order_array[i].type > 0x10 ? order_array[i].type - 0xf6 + 0x11:order_array[i].type)]);

				skip_field(pkt1, &off_1, order_array[i].pos);
				skip_field(pkt2, &off_2, order_array[i].pos);
				str1 = network_mysqld_proto_get_string_column(pkt1, &off_1);
				str2 = network_mysqld_proto_get_string_column(pkt2, &off_2);

				if(str1 == NULL && str2 != NULL)
					ret = -1;
				if(str1 != NULL && str2 == NULL)
					ret = 1;
				if(str1 != NULL && str2 != NULL)
					ret = strcmp(str1, str2); //cmpare str  
				if(str1 == NULL && str2 == NULL)
					ret = 0;
				//identical value
				g_free(str1);
				g_free(str2);
				if(ret == 0)
					return 1;
				if((order_array[i].desc && ret>0) || (!order_array[i].desc && ret<0))
					return 1;
				if((order_array[i].desc && ret<0) || (!order_array[i].desc && ret>0))
					return 0;
				break;
			case FIELD_TYPE_NULL:		//0x06 
			case FIELD_TYPE_BIT:		//0x10   (new in MySQL 5.0)
			case FIELD_TYPE_ENUM: 		//0xf7   
			case FIELD_TYPE_SET: 		//0xf8   
			case FIELD_TYPE_TINY_BLOB:	//0xf9   
			case FIELD_TYPE_MEDIUM_BLOB:	//0xfa   
			case FIELD_TYPE_LONG_BLOB: 	//0xfb   
			case FIELD_TYPE_BLOB: 		//0xfc   
			case FIELD_TYPE_GEOMETRY:	//0xff   
				g_warning("Not supported type:[%d]: %d:%s\n", i, order_array[i].type, (type_name[(order_array[i].type > 0x10 ? order_array[i].type - 0xf6 + 0x11:order_array[i].type)]) );
				return 1;
			default:
				g_warning("Unkonw Field Type: %d\n", order_array[i].type);
				return 1;
		}
	}
	log_debug("After all checking all order_by fields, if not returned yet, we could return 1 \n");	
	return 1;
}

/**
*	skipping fields by increase offset
*/
gint  skip_field(GString* packet, guint* _off, guint skip)
{
	if(packet)
	{
#if 0
{
	unsigned int iLength = packet->len;
	char *pData ;
	pData = ConvertBufToHex((unsigned char*) (packet->str), (unsigned int *)&iLength );
	fprintf(stderr,"packet:\n%s\n", pData );
	free( pData );
}
#endif
		guint64 len;
		guint   off = *_off;
		guint iter=0;
		//skip 4 items
		for(iter=0; iter<skip; iter++)
		{
			if(((unsigned char)packet->str[off]) == 0xfb )
				len = 0;
			else
				len = network_mysqld_proto_decode_lenenc(packet, &off);
			if(off + len > packet->len)
				return -1;
			off += len;
		}
		*_off = off;
	}
	else
		return -1;		

	return 0;
}

/**
	get_field_attr(): to get field attributes: type,pos from fields packet and fill in ORDER_BY array
	network_mysqld_result_parse_fields(GList *chunk, GPtrArray *fields) could do it but we only need type, pos
	so MW simplified network_mysqld_result_parse_fields() skipping unwanted fields
*/
GList *get_field_attr(GList *chunk, ORDER_BY *order_array, guint order_array_size, guint* pkt_cnt)
{
	GString *packet = (GString*) chunk->data;
	guint8 field_count;
	guint i;

	if(packet->len <= NET_HEADER_SIZE)
		return NULL;
	/* the first chunk is the length
	 *  */
	if (packet->len != NET_HEADER_SIZE + 1)
		return NULL;
	
	field_count = (guint8)(packet->str[NET_HEADER_SIZE]); 
	/* the byte after the net-header is the field-count */
	//we need to info caller how many fields we got here by increasing the counter
	(*pkt_cnt)++;
	(*pkt_cnt)  += field_count;

	/* the next chunk, the field-def */
	for (i = 0; i < field_count; i++) 
	{
		guint off = NET_HEADER_SIZE;

		chunk = chunk->next;
		packet = (GString*)chunk->data;
		
		//skip: catalog,db,table,org_table 
		skip_field(packet, &off, 4);
	
		gchar*   name = network_mysqld_proto_get_lenenc_string(packet, &off);

//		field->org_name  = 
//		network_mysqld_proto_get_lenenc_string(packet, &off);
		skip_field(packet, &off, 1);
		//network_mysqld_proto_skip(packet, &off, 1); /* filler */
		off++;
		//field->charsetnr = 
		//network_mysqld_proto_get_int16(packet, &off);
		off += 2;
		//field->length    = 
		//network_mysqld_proto_get_int32(packet, &off);
		off += 4;
		size_t iter;
		for(iter=0; iter< order_array_size; iter++)
		{
			if(strcmp(order_array[iter].name, name) == 0)
			{
				order_array[iter].pos  = i; 	
				order_array[iter].type = network_mysqld_proto_get_int8(packet, &off); //get type
			}	
		}

	//	field->flags     = 
	//	network_mysqld_proto_get_int16(packet, &off);
		off += 2;
	//	field->decimals  = 
	//	network_mysqld_proto_get_int8(packet, &off);
		off += 1;

	//	network_mysqld_proto_skip(packet, &off, 2); /* filler */
		off += 2;

	//	g_ptr_array_add(fields, field);
		g_free(name);
	}

	/* this should be EOF chunk */
	chunk = chunk->next;
	packet = (GString*)chunk->data;
	
	if(packet->str[NET_HEADER_SIZE] != MYSQLD_PACKET_EOF)
	{
		log_error("%s:%d packet->str[NET_HEADER_SIZE] != MYSQLD_PACKET_EOF", __FILE__, __LINE__);
		return NULL;
	}
	(*pkt_cnt)++;
	//now pkt_cnt == 1 + field_count + 1
	return chunk;
}

/**
 * serving UNIX_TIMESTAMP() 
 * 	return the first timestamp I got
 */
int unix_timestamp(GQueue* send_queue, GPtrArray* recv_queues, guint *pkt_count)
{
	size_t p = 0; 
	for(p=0; p< recv_queues->len; p++) 
	{
		GList* pkt = ((network_queue*)recv_queues->pdata[p])->chunks->head;
		//only check the first packet in each recv_queue
		if(pkt != NULL && pkt->data != NULL && ( (GString*) pkt->data)->len > NET_HEADER_SIZE) 
		{
			__append_packet(send_queue, (GString*)pkt->data);	
			//move pkt from recv_queue 
			g_queue_delete_link(((network_queue*)recv_queues->pdata[p])->chunks, pkt); 
			(*pkt_count)++;
			break;
		}
	}
	return 0;
}

/**
 * serving SQL Stored Procedures
 * 	lookup_profile_ids 
 	get_profiles_xml_for_api
	@searchProfileResults 
	@searchDetails
//SELECT lookup_profile_ids() || SELECT get_profiles_xml_for_api()
//SELECT @searchDetails || SELECT @searchProfileResults
//assuming that there's only one row in each resultset
 */
int stored_procedures(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count)
{
	size_t null_row_cnt 	= 0;
	int null_row_index 	= 0;
	guint str_len 		= 0;
	guint byte_len 		= 0;
	GString* id_str = g_string_new(NULL);	
	unsigned int iter;
	for( iter=0; iter<recv_queues->len; iter++)
	{
		if(candidate_ptrs[iter] != NULL && __get_pkt_type((GString*) candidate_ptrs[iter]->data) != 0xfe)
		{
			GString* pkt = (GString*) candidate_ptrs[iter]->data;
			if(__get_pkt_type(pkt) == 0x0)
				continue;
			get_str_len(pkt, &str_len);
			if( str_len == 0)
			{
				null_row_cnt ++;
				null_row_index = iter;
				continue;	
			}
			g_string_append_len(id_str, pkt->str + pkt->len - str_len , str_len);
		}
		else
		{
			g_critical("%s:%d packet corrupted in recv_queue[%u]", __FILE__, __LINE__, iter);
			g_string_free(id_str, TRUE);
			return -1;
		}
	}
	if(null_row_cnt == recv_queues->len)
	{
		__append_packet(send_queue, (GString*)candidate_ptrs[null_row_index]->data);	
		g_queue_delete_link(((network_queue*)recv_queues->pdata[null_row_index])->chunks, candidate_ptrs[null_row_index]); 
	}
	else
	{
		GString *packet = g_string_sized_new(4);
		packet->len     = 4;
		packet->str[3]  = (*pkt_count)+1;
		network_mysqld_proto_append_lenenc_string_len(packet, id_str->str, id_str->len); 
		switch((unsigned char)packet->str[4])
		{
			case 0xfc:
				byte_len = 2;
				break;
			case 0xfd:
				byte_len = 3;
				break;
			case 0xfe:
				byte_len = 8;
				break;
/*			case 0xfb:
				byte_len = 0;
				*/
			default:	
				byte_len = 0;
				break;
		}	
		network_mysqld_proto_set_header_len((unsigned char*)packet->str, 1 + byte_len + id_str->len);
		__append_packet( send_queue, (GString*)packet );	
#if 0

		GString* pkt = packet;
		unsigned int iLength = pkt->len;
		char *pData ;
		pData = ConvertBufToHex( pkt->str, &iLength );
		fprintf(stderr, "[%d]%s\n", iter, pData );
		free( pData );
#endif
	}
	(*pkt_count)++;
	g_string_free(id_str, TRUE);
    return 0;
}

/**
 * avg() support not accurate
 * use sum()/count() instead
 */
int avg(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count)
{
	gdouble total_ave = G_MINDOUBLE ;
	int iter = 0;
	int null_cnt = 0;
	for( iter=0; iter<int(recv_queues->len); iter++)
	{
		if(candidate_ptrs[iter] != NULL && 
				__get_pkt_type((GString*) candidate_ptrs[iter]->data) != 0xfe)
		{
			GString* pkt = (GString*) candidate_ptrs[iter]->data;
			guint 	off = NET_HEADER_SIZE;
			gchar* str  = network_mysqld_proto_get_string_column(pkt, &off);
			if(NULL == str || strcmp(str, "") == 0)
			{
				g_free(str);
				null_cnt ++;
				continue;
			}
			gdouble ave = strtod(str, NULL); // convert str to longlong
			total_ave += ave;	
			g_free(str);
		}
		else
		{
			g_critical("%s:%d packet corrupted in recv_queue[%d]", __FILE__, __LINE__, iter);
			return -1;
		}
	}
	if( total_ave != G_MINDOUBLE)
	{
		GString *packet = g_string_sized_new(4);
		packet->len     = 4;
		packet->str[3]  = (*pkt_count)+1;
		char buffer [64] = {0};                       
		total_ave = total_ave/(recv_queues->len - null_cnt);
		sprintf(buffer, "%f", total_ave);
		network_mysqld_proto_append_lenenc_string(packet, buffer);
		network_mysqld_proto_set_header_len((unsigned char*)packet->str, packet->str[4] + 1);
		__append_packet( send_queue, packet );	
		//lost some accuracy for average()
		(*pkt_count)++;
	}
	return 0;
}

/*
 * count()
 * 	select count()
 */
int count(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count)
{
	glong total_count = 0;
	unsigned int iter = 0;
	for( iter=0; iter<recv_queues->len; iter++)
	{
		if(candidate_ptrs[iter] != NULL && 
				__get_pkt_type((GString*) candidate_ptrs[iter]->data) != 0xfe)
		{
			GString* pkt = (GString*) candidate_ptrs[iter]->data;
			guint 	off = NET_HEADER_SIZE;
			gchar* str  = network_mysqld_proto_get_string_column(pkt, &off);
			if( NULL == str || strcmp(str, "") == 0)
			{
				g_free(str);
				continue;
			}
			total_count += atol(str);	
			g_free(str);
		}
		else
		{
			g_critical("%s:%d packet corrupted in recv_queue[%u]", __FILE__, __LINE__, iter);
			return -1;
		}
	}
	GString *packet = g_string_sized_new(4);
	packet->len     = 4;
	packet->str[3]  = (*pkt_count)+1;
	char buffer [33] = {0};
	sprintf(buffer, "%ld", total_count);
	network_mysqld_proto_append_lenenc_string(packet, buffer); 
	network_mysqld_proto_set_header_len((unsigned char*)packet->str, 1 + packet->str[4]);
	__append_packet( send_queue, packet );	
	(*pkt_count)++;
	return 0;
}

/**
 * min()
 * 	select min()
 */
int min(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count)
{
	GList* head = ((network_queue*) recv_queues->pdata[1])->chunks->head; 
	int type = get_col_type(head, "min");

	long total_long_min   = G_MAXLONG;
	double total_double_min = G_MAXDOUBLE;
	unsigned int iter = 0;
	for( iter=0; iter<recv_queues->len; iter++)
	{
		if(candidate_ptrs[iter] != NULL && 
				__get_pkt_type((GString*) candidate_ptrs[iter]->data) != 0xfe)
		{
			GString* pkt = (GString*)  candidate_ptrs[iter]->data;
			guint 	off = NET_HEADER_SIZE;
			gchar* str  = network_mysqld_proto_get_string_column(pkt, &off);
			if(  NULL == str || strcmp(str, "") == 0)
			{
				g_free(str);
				continue;
			}
			if(is_decimal(type))
			{
				int  min  = atol(str);
				if( total_long_min > min )
					total_long_min = min;	
			}
			if(is_float(type))
			{
				double min = strtod(str, NULL);
				if( total_double_min > min)
					total_double_min = min;
			}
			g_free(str);
		}
		else
		{
			g_critical("%s:%d packet corrupted in recv_queue[%u]", __FILE__, __LINE__, iter);
			return -1;
		}
	}
	if(total_long_min == G_MAXLONG && total_double_min == G_MAXDOUBLE)
	{
		GString *packet = g_string_sized_new(5);
		packet->len     = 5;
		packet->str[3]  = (*pkt_count)+1;
		packet->str[4]  = 0xfb;
		network_mysqld_proto_set_header_len((unsigned char*)packet->str, 1);
		__append_packet( send_queue, packet );	
	}	
	else
	{
		GString *packet = g_string_sized_new(4);
		packet->len     = 4;
		packet->str[3]  = (*pkt_count)+1;
		char buffer [33] = {0};                       
		if(is_decimal(type))
			sprintf(buffer, "%ld", total_long_min);
		if(is_float(type))
			sprintf(buffer, "%f", total_double_min);
		network_mysqld_proto_append_lenenc_string(packet, buffer);
		network_mysqld_proto_set_header_len((unsigned char*)packet->str, packet->str[4] + 1);
		__append_packet( send_queue, packet );	
	}
	(*pkt_count)++;
    return 0;
}

/**
 * max()
 * 	select max()
 */
int max(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count)
{
	GList* head = ((network_queue*) recv_queues->pdata[1])->chunks->head; 
	int type = get_col_type(head, "max");

	long 	total_long_max   = G_MINLONG;
	double 	total_double_max = G_MINDOUBLE;
	unsigned int iter 		 = 0;
	gchar*  str 		 = NULL;
	for( iter=0; iter<recv_queues->len; iter++)
	{
		if(candidate_ptrs[iter] != NULL && __get_pkt_type((GString*) candidate_ptrs[iter]->data) != 0xfe)
		{
			GString* pkt = (GString*) candidate_ptrs[iter]->data;
			guint 	off = NET_HEADER_SIZE;
			str  = network_mysqld_proto_get_string_column(pkt, &off);
			if(NULL == str || strcmp(str, "") == 0)
			{
				g_free(str);
				continue;
			}
			if(is_decimal(type))
			{
				long  max  = atol(str);
				if( total_long_max < max )
					total_long_max = max;	
			}
			if(is_float(type))
			{
				double max = strtod(str, NULL);
				if( total_double_max < max )
					total_double_max = max;
			}
			g_free(str);
		}
		else
		{
			g_critical("%s:%d packet corrupted in recv_queue[%u]", __FILE__, __LINE__, iter);
			return -1;
		}
	}
	if(total_long_max == G_MININT && total_double_max == G_MINDOUBLE )
	{
		GString *packet = g_string_sized_new(5);
		packet->len     = 5;
		packet->str[3]  = (*pkt_count)+1;
		packet->str[4]  = 0xfb;
		network_mysqld_proto_set_header_len((unsigned char*)packet->str, 1);
		__append_packet( send_queue, packet );	
	}	
	else
	{
		GString *packet = g_string_sized_new(4);
		packet->len     = 4;
		packet->str[3]  = (*pkt_count)+1;
		char buffer [33] = {0};
		if(is_decimal(type))
			sprintf(buffer, "%ld", total_long_max);
		if(is_float(type))
			sprintf(buffer, "%f", total_double_max);
		network_mysqld_proto_append_lenenc_string(packet, buffer);
		network_mysqld_proto_set_header_len((unsigned char*)packet->str, packet->str[4] + 1);
		__append_packet( send_queue, packet );	
	}
	(*pkt_count)++;
    return 0;
}

/*
 * get_col_type()  return the field_type of a single column row
 * designed for sum(), max(), min(), avg()
 */
int get_col_type(GList* chunk_head, const char* col_name)
{
	guint decoy_pkt_count = 0;
	ORDER_BY order_array[1];
	strcpy(order_array[0].name, col_name);
	get_field_attr(chunk_head, order_array, 1, &decoy_pkt_count);
	return order_array[0].type;
}

int is_decimal(int type)
{
	switch(type)
	{
		case 0x00: // FIELD_TYPE_DECIMAL
		case 0x01: // FIELD_TYPE_TINY
		case 0x02: // FIELD_TYPE_SHORT
		case 0x03: // FIELD_TYPE_LONG
		case 0x09: // FIELD_TYPE_INT24
		case 0xf6: // FIELD_TYPE_NEWDECIMAL (new in MYSQL 5.0)
				return 1;
		default:	
				return 0;
	}
}

int is_float(int type)
{
	switch(type)
	{
		case 0x04:  // FIELD_TYPE_FLOAT
		case 0x05:  // FIELD_TYPE_DOUBLE
				return 1;
		default:
				return 0;
	}
}
/**
 * sum()
 * 	select sum()
 */
int sum(GQueue* send_queue, GPtrArray* recv_queues, GList** candidate_ptrs, guint *pkt_count)
{
	GList* head = ((network_queue*) recv_queues->pdata[1])->chunks->head; 
	int type = get_col_type(head, "sum");
	//fprintf(stderr, "name: %s type: %d\n", order_array[0].name, order_array[0].type);

	long 	total_long_sum   = 0; 
	double 	total_double_sum = 0;
	unsigned int iter 		 = 0;
	gchar*  str 		 = NULL;
	for( iter=0; iter<recv_queues->len; iter++)
	{
		if(candidate_ptrs[iter] != NULL && 
				__get_pkt_type((GString*) candidate_ptrs[iter]->data) != 0xfe)
		{
			GString* pkt = (GString*)  candidate_ptrs[iter]->data;
			guint 	off = NET_HEADER_SIZE;
			str  = network_mysqld_proto_get_string_column(pkt, &off);
			if(NULL == str || strcmp(str, "") == 0)
			{
				g_free(str);
				continue;
			}
			if(is_decimal(type))
			{
				total_long_sum += atol(str);	
			}
			if(is_float(type))	
			{
				total_double_sum += strtod(str, NULL);	
			}
			g_free(str);
		}
		else
		{
			g_critical("%s:%d packet corrupted in recv_queue[%u]", __FILE__, __LINE__, iter);
			return -1;
		}
	}

	GString *packet = g_string_sized_new(4);
	packet->len     = 4;
	packet->str[3]  = (*pkt_count)+1;
	char buffer [33] = {0};
	if(is_decimal(type))
		sprintf(buffer, "%ld", total_long_sum);
	if(is_float(type))
		sprintf(buffer, "%f", total_double_sum);
	network_mysqld_proto_append_lenenc_string(packet, buffer); 
	network_mysqld_proto_set_header_len((unsigned char*)packet->str, packet->str[4] + 1);
	__append_packet( send_queue, packet );	

	(*pkt_count)++;
    return 0;
}

/**
 * get the string length 
 */
gint get_str_len(GString* pkt, uint *str_len)
{
	guint off = 5;
	switch((unsigned char)pkt->str[4])
	{
		case 0xfc:
				*str_len = network_mysqld_proto_get_int_len(pkt, &off, 2);
				break;
		case 0xfd:
				*str_len = network_mysqld_proto_get_int_len(pkt, &off, 3);
				break;
		case 0xfe:
				*str_len = network_mysqld_proto_get_int_len(pkt, &off, 8);
				break;
		case 0xfb:
				*str_len  = 0;
		default:	
				*str_len = (unsigned char) pkt->str[4];
				break;
	}
	return 0;
}

/**
*	\parama 
*	\return retval_t 
*	\todo	standerize error code !
*/
gint resultset_merge(GQueue* send_queue,  GPtrArray* recv_queues, GPtrArray* sql_tokens)
{
	log_debug("Omg, resultsets are coming~~");
	if(NULL == send_queue || NULL == recv_queues || NULL == sql_tokens)
	{
		log_error("%s:%d packet->str[NET_HEADER_SIZE] != MYSQLD_PACKET_EOF", __FILE__, __LINE__);
		return -1;
	}
// for debug to dump all pkts
#if 0
	{
		int iter;
		for(iter=0; iter<recv_queues->len; iter++)
		{
			GList* pkt = ((network_queue*)recv_queues->pdata[iter])->chunks->head;
			while(pkt != NULL && pkt->data != NULL)
			{
				unsigned int iLength = ((GString*)pkt->data)->len;
				char *pData ;
				pData = ConvertBufToHex( ((unsigned char*)((GString*)pkt->data)->str), &iLength );
				fprintf(stderr, "[%d]%s\n", iter, pData );
				free( pData );
				pkt = pkt->next;
			}
		}
	}
#endif
	//SELECT|INSERT|UPDATE|DELETE
	//deal with query syntax error here
	size_t p = 0; 
	for(p=0; p< recv_queues->len; p++) 
	{
		GList* pkt = ((network_queue*)recv_queues->pdata[p])->chunks->head;
		//only check the first packet in each recv_queue
		if(pkt != NULL && pkt->data != NULL && ( (GString*) pkt->data)->len > NET_HEADER_SIZE) 
		{
			guchar pkt_type = __get_pkt_type((GString*)pkt->data);
			if(pkt_type == 0xff || pkt_type == 0xfe)
			{	
				//ERROR
				//one error veto all
				__append_packet(send_queue, (GString*)pkt->data);	
				//move pkt from recv_queue 
				g_queue_delete_link(((network_queue*)recv_queues->pdata[p])->chunks, pkt); 
				return 0;
			}
		}
		else
		{
			log_error("First Packet at [%d] recv_queue is invalid", p);
			return 0;
		}
	}

	sql_token *token_0 = get_token(sql_tokens, 0);
	sql_token *token_1 = get_token(sql_tokens, 1);
	switch( token_0->token_id )
	{
		case TK_SQL_SELECT :
			{
				//SELECT col_name from tbl order by col limit offset,row_count	
				ORDER_BY order_array[MAX_ORDER_COLS];
				/** all 0s for name,desc(0 default ASC),type(0x00 FIELD_TYPE_DECIMAL),pos */
				bzero(order_array, sizeof(ORDER_BY)*MAX_ORDER_COLS); 
				int order_array_size = 0;	/// number of ORDER_BY Columns 
				LIMIT limit;
				limit.offset = 0; 		/** default offset = 0*/
				//limit.row_count = G_MAXUINT;  /** default row_count=G_MAXUINT*/
				limit.row_count = G_MAXINT32;  	/** default row_count=G_MAXINT32*/
				sql_parser(sql_tokens, order_array, &order_array_size, &limit);

				//  (Result Set Header Packet)  the number of columns
				//  (Field Packets)             column descriptors
				//  (EOF Packet)                marker: end of Field Packets
				//  (Row Data Packets)          row contents
				//  (End Packet)                marker: end of Data Packets
				//we only need to extract the field attributes once because all resultsets share the same columns
				//obtain and parse the fields packet
				guint pkt_count = 0;
				network_queue* recv_q = (network_queue*) recv_queues->pdata[0]; 
				if(recv_q != NULL && recv_q->chunks != NULL && recv_q->chunks->head != NULL)
				{
					// parse the fields packet, fill in order_array, increase count
					// return  pointer to EOF packet
					get_field_attr(recv_q->chunks->head, order_array, order_array_size, &pkt_count);
				}

				GList*  candidate_ptrs[recv_queues->len];
				int	candidate_iter = 0;
				//insert head of recv_queues into candiate_ptrs
				size_t iter;
				for(iter=0; iter<recv_queues->len; iter++)
				{
					GList* pkt_list = ((network_queue*)recv_queues->pdata[iter])->chunks->head;
					guint counter = pkt_count;
					//sending result header, fields and EOF once 
					while(counter>0)
					{
						if(pkt_list != NULL)
						{
							GList* ptr_to_unlink = pkt_list;
							pkt_list = pkt_list->next;
							if(iter == 0)
							{
								//adding resultset header, fields, EOF packets into send_queue
								__append_packet(send_queue, (GString*) (ptr_to_unlink->data));	
								//unlink pkt pointer from recv_queue, because they belong to send_queue now
								g_queue_delete_link(((network_queue*)recv_queues->pdata[iter])->chunks, ptr_to_unlink); 
							}
						}
						else
						{
							log_error("%s:%d recv_queues[%d] corrupted", __FILE__, __LINE__, iter);
							return -1;
						}
						counter--;
					}
					candidate_ptrs[candidate_iter] = pkt_list;	
					candidate_iter++;
				}
				size_t p = 0; 
				for(p=0; p< recv_queues->len; p++) 
				{
					GList* pkt = candidate_ptrs[p];
					//only check the first packet in incoming row packets 
					if(pkt != NULL && pkt->data != NULL && ( (GString*) pkt->data)->len > NET_HEADER_SIZE) 
					{
						guchar pkt_type = __get_pkt_type((GString*)pkt->data);
						if(pkt_type == 0xff)
						{	
							//ERROR in excecution
							//one error veto all
							__append_packet(send_queue, (GString*)pkt->data);	
							//move pkt from recv_queue 
							g_queue_delete_link(((network_queue*)recv_queues->pdata[p])->chunks, pkt); 
							return 0;
						}
					}
					else
					{
						log_error("%s:%d First Packet at [%d] recv_queue is invalid", __FILE__, __LINE__, p);
						return -1;
					}
				}
#if 0 
	{
		int iter;
		for(iter=0; iter<recv_queues->len; iter++)
		{
			GList* pkt = candidate_ptrs[iter];
			while(pkt != NULL && pkt->data != NULL)
			{
				unsigned int iLength = ((GString*)pkt->data)->len;
				char *pData ;
				pData = ConvertBufToHex( (((GString*)pkt->data)->str), &iLength );
				fprintf(stderr, "[%d]%s\n", iter, pData );
				free( pData );
				pkt = pkt->next;
			}
		}
	}
#endif

				if( strcasecmp(token_1->text->str, "UNIX_TIMESTAMP") == 0 ) 
				{
					unix_timestamp(send_queue, recv_queues, &pkt_count);
				}
				else
				if( strcasecmp(token_1->text->str, "lookup_profile_ids") == 0 
					|| strcasecmp(token_1->text->str, "get_profiles_xml_for_api") == 0
					||strcasecmp(token_1->text->str, "@searchProfileResults") == 0 
					|| strcasecmp(token_1->text->str, "@searchDetails") == 0)
				{
					stored_procedures(send_queue, recv_queues, candidate_ptrs, &pkt_count);
									}
				else
				if( strcasecmp(token_1->text->str, "sum") == 0)
				{
					sum(send_queue, recv_queues, candidate_ptrs, &pkt_count);
				}
				else
				if( strcasecmp(token_1->text->str, "max") == 0)
				{
					max(send_queue, recv_queues, candidate_ptrs, &pkt_count);
				}
				else
				if( strcasecmp(token_1->text->str, "min") == 0)
				{
					min(send_queue, recv_queues, candidate_ptrs, &pkt_count);
				}
				else
				if( strcasecmp(token_1->text->str, "count") == 0)
				{
					count(send_queue, recv_queues, candidate_ptrs, &pkt_count);
				}
				else
				if( strcasecmp(token_1->text->str, "avg") == 0)
				{
					avg(send_queue, recv_queues, candidate_ptrs, &pkt_count);
				}
				else	
				{
					guint  candidate_index = 0;
					GList* candidate = NULL; 
					size_t row_cnter = 0;
					size_t off_pos   = 0;

					if(order_array_size > 0)
					{
						//merge sort
						while(row_cnter < limit.row_count)
						{
							if(candidate == NULL || __get_pkt_type((GString*) candidate->data) == 0xfe)
							{
								//filtering out EOF packet because EOF pkt contains no data and would crash __is_prio_to() 
								//move candidate ptr to next non-null
								for(iter=0; iter<recv_queues->len; iter++)
									if(candidate_ptrs[iter] != NULL && 
											__get_pkt_type((GString*) candidate_ptrs[iter]->data) != 0xfe)
									{
										candidate_index = iter;
										candidate	= candidate_ptrs[iter];
										break;
									}				
							}
							//if candidate is still NULL, all possible candidates have been exhausted
							if(candidate == NULL || __get_pkt_type((GString*) candidate->data) == 0xfe)
								break;
							//to obtain candiate ptr and its index in recv_queues by scanning candidate_ptrs once 
							for(iter=0; iter<recv_queues->len; iter++)
							{
								//don't compare with itself
								if(iter == candidate_index)
									continue;
								else
								{
									GList* tmp_list = candidate_ptrs[iter];
									//some recv_queue may be shorter than others
									if(tmp_list == NULL || __get_pkt_type((GString*) tmp_list->data) == 0xfe)
										continue;
									if(! __is_prior_to((GString*) candidate->data, (GString*)tmp_list->data, order_array, order_array_size) )
									{
										candidate 	= tmp_list;
										candidate_index = iter;
									}
									//else: candidate already pointing at the packet to add
								}
							}	
							//update the sequence number of candidate packet
							//header packet
							//Bytes                 Name
							//3                     Packet Length
							//1                     Packet Number
							if(candidate->data == NULL || ((GString*)candidate->data)->len <= 4)
							{
								log_error( "%s:%d packet corrupted", __FILE__, __LINE__ );
								return -1;
							}
							if( off_pos < limit.offset)
							{
								off_pos ++;
								candidate_ptrs[candidate_index] = candidate->next;
								candidate = candidate->next;
								continue;
							}
							else
							{
								((GString*)candidate->data)->str[3] = pkt_count+1;
								++pkt_count;
								//append candidate row packet into send_queue
								__append_packet(send_queue, (GString*)candidate->data);	
								candidate_ptrs[candidate_index] = candidate->next;
								//candidate->next is likely to be next candidate
								GList* ptr_to_unlink = candidate;
								candidate = candidate->next;
								//unlink pkt pointer from recv_queue, because they belong to send_queue now
								g_queue_delete_link(((network_queue*)recv_queues->pdata[candidate_index])->chunks, ptr_to_unlink); 
								row_cnter ++;
							}
						}
					}
					else
					{
						GList* candidate = NULL; 
						//add all incoming packets into send_queue without merge_sort 
						//to obtain candiate ptr and its index in recv_queues by scanning candidate_ptrs once 
						for(iter=0; iter<recv_queues->len; iter++)
						{

							candidate = candidate_ptrs[iter]; 
							while(candidate != NULL)
							{
								if(row_cnter == limit.row_count)
										break;
								if( off_pos < limit.offset)
								{
									off_pos ++;
									candidate = candidate->next;
									continue;
								}
								else
								{
									if(candidate->data == NULL || ((GString*)candidate->data)->len <= 4)
									{
										log_error( "%s:%d packet corrupted", __FILE__, __LINE__ );
										return -1;
									}
									if(__get_pkt_type((GString*) candidate->data) == 0xfe)
										break;
									((GString*)candidate->data)->str[3] = pkt_count+1;
									++pkt_count;
									//append candidate row packet into send_queue
									__append_packet(send_queue, (GString*)candidate->data);	
									//candidate->next is likely to be next candidate
									GList* ptr_to_unlink = candidate;
									candidate = candidate->next;
									//unlink pkt pointer from recv_queue, because they belong to send_queue now
									g_queue_delete_link(((network_queue*)recv_queues->pdata[iter])->chunks, ptr_to_unlink); 
									row_cnter ++;
								}
							}
						}
					}
				}
				//after adding all packets we don't need candidate list anymore

				//need to append EOF after all Row Data Packets?? Yes
				//update packet number in header 
				GString* eof_pkt = g_string_new_len("\x05\x00\x00\x07\xfe\x00\x00\x22\x00", 9);
				eof_pkt->str[3] = pkt_count+1;
				__append_packet(send_queue, eof_pkt);
				//when to free eof_pkt ??
			}
			return 0;
		case TK_SQL_INSERT :
		case TK_SQL_UPDATE :
		case TK_SQL_DELETE :
		case TK_SQL_CALL   :
		case TK_SQL_SET   :
		case TK_SQL_START:
		case TK_SQL_BEGIN:
		case TK_SQL_COMMIT:
		case TK_SQL_ROLLBACK:
		//INSERT/UPDATE/DELETE expecting OK packet
			{
				guint64 all_affected_rows = 0;
				guint64 all_warnings      = 0;
				size_t p = 0; 
				for(p=0; p< recv_queues->len; p++) 
				{
					GList* pkt = ((network_queue*)recv_queues->pdata[p])->chunks->head;
					//only check the first packet in each recv_queue
					if(pkt != NULL && pkt->data != NULL && ( (GString*) pkt->data)->len > NET_HEADER_SIZE) 
					{
						guchar pkt_type = __get_pkt_type((GString*)pkt->data);
						guint64 affected_rows = 0;
						int warnings = 0;
						GString s;
						switch(pkt_type)
						{
							case 0x00:
								//OK
								s.str = ((GString*)pkt->data)->str + NET_HEADER_SIZE;
								s.len = ((GString*)pkt->data)->len - NET_HEADER_SIZE;
								//no way to pass multi-server status back to client, so just ignore it
								network_mysqld_proto_decode_ok_packet(&s, &affected_rows, NULL, NULL, &warnings, NULL);
								//add up all affected_rows 
								all_affected_rows += affected_rows;
								all_warnings += warnings;
								break;
							case 0xfe:
								//EOF
								break;	
							case 0xff:
								//ERROR
								//one error veto all
								__append_packet(send_queue, (GString*)pkt->data);	
								//move pkt from recv_queue 
								g_queue_delete_link(((network_queue*)recv_queues->pdata[p])->chunks, pkt); 
								return 0;
							default:
								break;
						}
					}
					else
					{
						log_error("%s:%d First Packet at [%d] recv_queue is invalid", __FILE__, __LINE__, p);
						return -1;
					}
				}
				GString *packet = g_string_sized_new(4);
				packet->len     = 4;
				packet->str[3]  = 1;
				//not sure about wether those items are useful, so fill in some dummy value
				int insert_id     = 0;
				int server_status = 0x0002;
				network_mysqld_proto_append_int8(packet, 0); /* no fields */
				network_mysqld_proto_append_lenenc_int(packet, all_affected_rows);
				network_mysqld_proto_append_lenenc_int(packet, insert_id);
				network_mysqld_proto_append_int16(packet, server_status); /* autocommit */
				network_mysqld_proto_append_int16(packet, all_warnings); /* no warnings */

				char message [64] = {0};
				sprintf(message, "Rows matched: %u  Changed: %u  Warnings: %u",
                        (unsigned)all_affected_rows,
                        (unsigned)all_affected_rows,
                        (unsigned)all_warnings);
				network_mysqld_proto_append_lenenc_string(packet, message); 
				network_mysqld_proto_set_header_len((unsigned char*)packet->str, packet->len - NET_HEADER_SIZE);

				__append_packet(send_queue, packet);	
				return 0;
			}
		default:
			log_debug("%s:%d Unsupported T(%s, \"%s\");", __FILE__, __LINE__, sql_token_get_name(token_0->token_id), token_0->text->str);
			return -1;
	}
	return 0;
}


/**
*	add one packet into the send_queue
*/
gint __append_packet(GQueue* send, GString* pkt)
{
	if( send == NULL || pkt == NULL)
		return -1;
//[for debug
#if 0 
	unsigned int iLength = pkt->len;
	char *pData ;
	pData = ConvertBufToHex((unsigned char*) (pkt->str), (unsigned int *)&iLength );

	fprintf(stderr, "appending packet:\n%s\n", pData );
	free( pData );
#endif
//]
	g_queue_push_tail(send, pkt);
	return 0;
}

/**
*	pick up one record among current candidates	
*	increase current index of each recv_queue by 1
*/
gint __pick_one_record()
{
	return 0;
}


sql_token * get_token(GPtrArray* tokens, unsigned int iter)
{
	if(tokens == NULL || iter < 0 || iter >= tokens->len)
		return NULL;
	return (sql_token*) tokens->pdata[iter];	
}

/**
*	\brief  extract name and desc from ORDER BY
* 	\author MW
*	\date   
*	\param  GPtrArray tokens, iter_ptr pointer to the first token of ORDER BY
*	\return integer: 
*		-# 0 for success, 
		-# <0 for error
*/

gint get_order_by(GPtrArray* tokens, int* iter_ptr, ORDER_BY order_array[], int* order_array_size_ptr)
{
	///TO DO: we need to agree on standerized error codes
	if(tokens == NULL || iter_ptr == NULL || order_array_size_ptr == NULL || *iter_ptr == 0 || *iter_ptr >= int(tokens->len) )
		return -1;
	sql_token * tk 	= get_token(tokens, *iter_ptr);				
	sql_token* next	= get_token(tokens, (*iter_ptr)+1); 

	///looping for "ORDER BY"	
	while( tk != NULL && (tk->token_id == TK_SQL_DESC || tk->token_id == TK_COMMA || tk->token_id == TK_LITERAL
				|| tk->token_id == TK_DOT || tk->token_id == TK_SQL_ASC ))
	{
		if(tk->token_id == TK_LITERAL)
		{
			
			if(next == NULL || next->token_id != TK_DOT)
			{
				strcpy(order_array[*(order_array_size_ptr)].name, tk->text->str);
				/// increase num of ORDER_BY columns
				(*order_array_size_ptr)++;
				if(*(order_array_size_ptr) > MAX_ORDER_COLS)
				{
					log_error("%s:%d *(order_array_size_ptr) > MAX_ORDER_COLS", __FILE__, __LINE__);
					return -1;
				}
			}
		}
		if( tk->token_id == TK_SQL_DESC )
			//DESC always after column_name
			order_array[*(order_array_size_ptr)-1].desc = 1;
		//move to next
		(*iter_ptr)++; 
		tk	= get_token(tokens, *iter_ptr);
		next	= get_token(tokens, (*iter_ptr)+1);
	}
	///move backward by 1
	--(*iter_ptr);  
    return 0;
}
/**
* 	\param  - 
		-# GPtrArray *tokens, array of tokens
		-# int* iter_ptr,     iterator of tokens array
		-# LIMIT* limit_ptr,  LIMIT struct
	\return integer: 
		- 0
*/
gint get_limit(GPtrArray *tokens, int* iter_ptr, LIMIT* limit_ptr)
{
	sql_token* tk = get_token(tokens, (*iter_ptr));				
	sql_token* next = get_token(tokens, (*iter_ptr)+1);
	if(tk != NULL && tk->token_id == TK_INTEGER )
	{
		if( next == NULL || (next != NULL && next->token_id != TK_COMMA))
		{
			/// if only 1 integer after LIMIT
			/// then it is row_count, offset is default 0 
			glong row_count = atol(tk->text->str);	
			//default max limit = 100
			if(row_count > 0 && row_count <= MAX_LIMIT) 
				limit_ptr->row_count = row_count;
		}		
		if( next != NULL && next->token_id == TK_COMMA)	
		{
			/// the first integer is offset
			limit_ptr->offset = atol(tk->text->str);
			// check out the second integer after ',' assign to row_count
			(*iter_ptr) += 2; // skip ','
			tk = get_token(tokens, (*iter_ptr));	
			if(tk != NULL && tk->token_id == TK_INTEGER )
			{
				glong row_count = atol(tk->text->str);	
				//default max limit = 100
				if( row_count > 0 && row_count <= MAX_LIMIT) 
					limit_ptr->row_count = row_count;
			}
			else
			{
				g_warning("SQL syntax error");
				return -1;
			}
		}
		if( next != NULL && next->token_id == TK_SQL_OFFSET )	
		{
			//LIMIT ROW_COUNT OFFSET offset
			glong row_count = atol(tk->text->str);	
			//default max limit = 100
			if(row_count > 0 && row_count <= MAX_LIMIT) 
				limit_ptr->row_count = row_count;
			// skip 'OFFSET'
			(*iter_ptr) += 2; 
			tk = get_token(tokens, (*iter_ptr));	
			if(tk != NULL && tk->token_id == TK_INTEGER )
			{
				limit_ptr->offset = atol(tk->text->str);	
			}
			else
			{
				g_warning("SQL syntax error");
				return -1;
			}
		}

	}
	else
	{
		g_warning("SQL syntax error\n");
		return -1;
	}
	return 0;
}


gint sql_parser(GPtrArray *tokens, ORDER_BY order_array[], int* order_array_size_ptr, LIMIT* limit_ptr)
{
	int iter; 
	for (iter = 0; iter < int(tokens->len); iter++) 
	{
		sql_token *token = get_token(tokens,iter);
		sql_token* tk    = NULL;
		switch(token->token_id)
		{
			case TK_SQL_ORDER:	
				log_debug("%d Got %s\n", iter, sql_token_get_name(token->token_id));
				iter++; //move to "BY"
				tk = get_token(tokens, iter);
				if(tk != NULL && tk->token_id == TK_SQL_BY)
				{
					iter++;
					get_order_by(tokens, &iter, order_array, order_array_size_ptr);	
				}
				else
					g_warning("SQL Syntax Error: 'BY' missing for 'ORDER BY'\n");
				break;
			case TK_SQL_LIMIT:	
				log_debug("%d Got %s\n", iter, sql_token_get_name(token->token_id));
				iter++; //move to the offset or row_count 
				get_limit(tokens, &iter, limit_ptr);
				break;
			default:
				log_debug("#%"G_GSIZE_FORMAT": T(%s, \"%s\");", iter, sql_token_get_name(token->token_id), token->text->str);
				break;
		}	
	}

	return 0;
}
