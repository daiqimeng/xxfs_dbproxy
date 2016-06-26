
#include "perf_monitor.h"
#include "network-mysqld-proto.h"

char *perf_types[] = 
{
	"NONE",
	"QUERY",
	"SEND",
	"RECV",
	"MERGE",
	"LOOKUP",
	"CONNECT"
};

void PerfData::print() 
{
	char s_time[64];

	memset((void*)s_time, 0, sizeof(s_time));
	strftime(s_time, 
			sizeof(s_time), 
			"%Y-%m-%d %H:%M:%S", 
			gmtime(&m_start.tv_sec));

/*
	sprintf(msg, "%s:%s took %d.%06ld s. ID=%s \n", 
			s_time, 
			perf_types[(m_type & PF_TYPE_MASK)], 
			(m_start.tv_usec > m_end.tv_usec)?(m_end.tv_sec - m_start.tv_sec - 1):(m_end.tv_sec - m_start.tv_sec),
			(m_start.tv_usec > m_end.tv_usec)?((999999+m_end.tv_usec) - m_start.tv_usec):(m_end.tv_usec - m_start.tv_usec),
			m_unique
			);

	log_debug(msg);
*/
}

PerfParent::PerfParent()
{
	GTimeVal tvSum;

	tvSum.tv_sec = 0;
	tvSum.tv_usec = 0;

	// add dummy place holders specifically for the SELECT/add row code
	m_sum_data[PF_QUERY] = PerfSumData(((int)PF_QUERY), tvSum, "");
	m_sum_data[PF_SEND] = PerfSumData(((int)PF_SEND), tvSum, "");
	m_sum_data[PF_RECV] = PerfSumData(((int)PF_RECV), tvSum, "");
	m_sum_data[PF_MERGE] = PerfSumData(((int)PF_MERGE), tvSum, "");
	m_sum_data[PF_LOOKUP] = PerfSumData(((int)PF_LOOKUP), tvSum, "");
	m_sum_data[PF_CONNECT] = PerfSumData(((int)PF_CONNECT), tvSum, "");
}

void PerfParent::start( char *unique, int32_t type )
{
	IPerfDataMap it = m_data.find( type & PF_TYPE_MASK );
	if ( it != m_data.end() )
	{
		m_data.erase(it);
		return;
	}

	PerfData pf( unique, type );
	m_data[(type & PF_TYPE_MASK)] = pf;
	
		return;
}

void PerfParent::end( int32_t type )
{
	IPerfDataMap it = m_data.find( type & PF_TYPE_MASK );
	if ( it != m_data.end() )
	{
		it->second.end();

		if ( type & PF_PRINT )
		{
			it->second.print();
		}

		// append the sum data to the sum map
		IPerfSumDataMap itsum = m_sum_data.find( (type & PF_TYPE_MASK) );
		if ( itsum == m_sum_data.end() )
		{
			GTimeVal tvSum;
			if ( it->second.get_end().tv_usec <= it->second.get_start().tv_usec )
			{
				tvSum.tv_sec = (it->second.get_end().tv_sec - 1) - it->second.get_start().tv_sec;
				tvSum.tv_usec = (1000000 + it->second.get_end().tv_usec) - it->second.get_start().tv_usec;
			}
			else
			{
				tvSum.tv_sec = it->second.get_end().tv_sec - it->second.get_start().tv_sec;
				tvSum.tv_usec = it->second.get_end().tv_usec - it->second.get_start().tv_usec;
			}
			m_sum_data[ (type & PF_TYPE_MASK) ] = PerfSumData((int)(it->second.get_type() & PF_TYPE_MASK), tvSum, it->second.get_unique());
		}
		else
		{
			GTimeVal tvSum;
			if ( it->second.get_end().tv_usec <= it->second.get_start().tv_usec )
			{
				tvSum.tv_sec = (it->second.get_end().tv_sec - 1) - it->second.get_start().tv_sec;
				tvSum.tv_usec = (1000000 + it->second.get_end().tv_usec) - it->second.get_start().tv_usec;
			}
			else
			{
				tvSum.tv_sec = it->second.get_end().tv_sec - it->second.get_start().tv_sec;
				tvSum.tv_usec = it->second.get_end().tv_usec - it->second.get_start().tv_usec;
			}

			itsum->second += PerfSumData((int)(it->second.get_type() & PF_TYPE_MASK), tvSum, it->second.get_unique());
		}

		//m_data.erase(it);
	}
}

void PerfParent::print( int32_t type )
{
	IPerfDataMap it = m_data.find( type & PF_TYPE_MASK );
	if ( it != m_data.end() )
	{
		it->second.print();
	}

	return;
}


void PerfParent::print_sum()
{
	for(IPerfSumDataMap it = m_sum_data.begin();
		it != m_sum_data.end();
		it++ )
	{
		it->second.get_type();
/*
		sprintf(msg, "%s Total Time:%d.%06ld s | Count: %d | Avg: %d.%06ld s. Max %d.%06ld at %d ID=%s\n", 
			perf_types[ (it->second.get_type() & PF_TYPE_MASK) ], 
			it->second.get_sum().tv_sec,
			it->second.get_sum().tv_usec,
			it->second.get_count(),
			(it->second.get_count() == 0)?0:(it->second.get_sum().tv_sec / it->second.get_count()),
			(it->second.get_count() == 0)?0:(it->second.get_sum().tv_usec / it->second.get_count()),
			it->second.get_longest().tv_sec,
			it->second.get_longest().tv_usec,
			it->second.get_longest_pos(),
			it->second.get_unique()
			);

		log_debug(msg);
*/
	}
}

perf_parent * create_perf( int type )
{
	return new PerfParent();
}

void delete_perf( perf_parent *perf)
{
	((PerfParent*)perf)->print_sum();
	delete (PerfParent*)perf;
}

void print_perf( perf_parent *parent, int32_t type_mode )
{
	((PerfParent*)parent)->print( type_mode );
}

void perf_start( perf_parent *parent, char *unique, int32_t type_mode )
{
	((PerfParent*)parent)->start( unique, type_mode );
}

void perf_end( perf_parent *parent, int32_t mode )
{
	((PerfParent*)parent)->end( mode );
}

void add_data_row( perf_parent *parent, GPtrArray *row )
{
	((PerfParent*)parent)->add_data_row( row );
}

void add_field_row( GPtrArray *row )
{
	MYSQL_FIELD *field;

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "connected" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "used" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "QUERY Total/Count/Avg/Max" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "SEND Total/Count/Avg/Max" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "RECV Total/Count/Avg/Max" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "MERGE Total/Count/Avg/Max" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "LOOKUP Total/Count/Avg/Max" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );

	field = network_mysqld_proto_field_init();
	field->name = g_strdup( "CONNECT Total/Count/Avg/Max" );
	field->type = FIELD_TYPE_STRING;
	field->length = 32;
	g_ptr_array_add( row, field );
}

extern gchar * g_timeval_string(GTimeVal *t1, GString *str);

void PerfParent::add_data_row( GPtrArray *row )
{
	char msg[256];
	GString *str;

	// conencted is the start time of PF_CONNECT
	IPerfDataMap it = m_data.find( PF_CONNECT );
	if ( it == m_data.end() )
	{
		g_ptr_array_add( row, g_strdup("n/a") );
	}
	else
	{
		str = g_string_new("");
		g_timeval_string( it->second.get_pstart(), str);
        g_ptr_array_add( row, g_strdup( str->str ) );
		g_string_free( str, TRUE );
	}
	
	it = m_data.find( PF_SEND );

	if ( it == m_data.end() )
	{
		g_ptr_array_add( row, g_strdup( "n/a") );
	}
	else
	{
		str = g_string_new("");
		g_timeval_string( it->second.get_pend(), str);
        g_ptr_array_add( row, g_strdup( str->str ) );
		g_string_free( str, TRUE );
	}

	memset((void*)msg, 0, sizeof(msg));
	for(IPerfSumDataMap it = m_sum_data.begin();
		it != m_sum_data.end();
		it++ )
	{
	/*
		sprintf(msg, "%d.%03ld/%d/%d.%04ld/%d.%04ld", 
			it->second.get_sum().tv_sec,
			it->second.get_sum().tv_usec,
			it->second.get_count() - 1,
			(it->second.get_count() == 0)?0:(it->second.get_sum().tv_sec / it->second.get_count()),
			(it->second.get_count() == 0)?0:(it->second.get_sum().tv_usec / it->second.get_count()),
			it->second.get_longest().tv_sec,
			it->second.get_longest().tv_usec
			);

		g_ptr_array_add( row, g_strdup(msg) );
	*/
	}
}
