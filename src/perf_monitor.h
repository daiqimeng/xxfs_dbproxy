
#ifndef _PERF_MONITOR_H__
#define _PERF_MONITOR_H__

#include <mysql.h>
#include <errmsg.h>
#include <mysql_com.h>
#include <stdint.h>
#include <memory.h>
#include "glib.h"

// performance modes
#define PF_NONE				0x00000000
#define PF_OVERWRITE		0x10000000
#define PF_APPEND			0x20000000
#define PF_PRINT			0x40000000
#define PF_CLEAR			0x80000000

#define PF_MODE_MASK		0xFF000000
#define PF_TYPE_MASK		0x00FFFFFF

// perfromance types
#define PF_QUERY			1		// a QUERY is initiated
#define PF_SEND				2
#define PF_RECV				3
#define PF_MERGE			4
#define PF_LOOKUP			5
#define PF_CONNECT			6

typedef void perf_parent;


perf_parent * create_perf( int type );
void delete_perf( perf_parent *parent );
void print_perf( perf_parent *parent, int32_t type_mode );
void perf_start( perf_parent *parent, char *unique, int32_t type_mode );
void perf_end( perf_parent *parent, int32_t mode );
void add_data_row( perf_parent *parent, GPtrArray *row );
void add_field_row( GPtrArray *fields );

extern char *perf_types[];

/*
#define DEFINE_PERF							perf_parent	*perf;
#define CREATE_PERF( structure )			structure->perf =create_perf(PF_NONE);
#define DELETE_PERF( structure )			delete_perf(structure->perf);

#define START_PERF( structure, ID, TYPE )	if ( srv->config.proxy.profiling == 1 ) perf_start( structure->perf, ID, TYPE );
#define END_PERF( structure, TYPE )			perf_end( structure->perf, TYPE );
#define PERF_MONITOR_ADD_ROW_STR(structure)	add_data_row( structure->perf, row );
#define PERF_MONITOR_ADD_FIELD_STR(fields)	add_field_row( fields );
*/

#define DEFINE_PERF		
#define CREATE_PERF( structure )	
#define DELETE_PERF( structure )	

#define START_PERF( structure, ID, TYPE )
#define END_PERF( structure, TYPE )		
#define PERF_MONITOR_ADD_ROW_STR(structure)	
#define PERF_MONITOR_ADD_FIELD_STR(fields)


#include <vector>
#include <ext/hash_map>

#define MAX_UNIQUE_STR		128

class PerfData
{
	public:
		PerfData(const char *unique = NULL, int type = PF_QUERY)
		{
			start();
			memset((void*)&m_end, 0, sizeof(GTimeVal));	
			m_type = type;
			memset((void*)m_unique, 0, sizeof(m_unique));
			if ( unique != NULL )
				strncpy( m_unique, unique, strlen(unique)>MAX_UNIQUE_STR?MAX_UNIQUE_STR-1:strlen(unique));
		}

		PerfData(const char *unique, int type, GTimeVal tStart, GTimeVal tEnd )
		{
			m_type = type;
			if ( unique != NULL )
				strncpy( m_unique, unique, strlen(unique)>MAX_UNIQUE_STR?MAX_UNIQUE_STR-1:strlen(unique));
			else
				memset((void*)m_unique, 0, sizeof(m_unique));
			m_start.tv_sec = tStart.tv_sec;
			m_start.tv_usec = tStart.tv_usec;
			m_end.tv_sec = tEnd.tv_sec;
			m_end.tv_usec = tEnd.tv_usec;
		}

		~PerfData() {}

		void start()
		{
			g_get_current_time(&m_start);
		}

		void end() 
		{
			g_get_current_time(&m_end);
		}

		void print();

		PerfData	&operator=(const PerfData &src)
		{
			m_start = src.get_start();
			m_end 	= src.get_end();
			m_type 	= src.get_type();
			if ( src.get_unique() != NULL )
				strcpy( m_unique, src.get_unique());
			return *this;
		}

		GTimeVal		get_start() const { return m_start; }
		GTimeVal		get_end() const { return m_end; }
		int				get_type() const { return m_type; }
		const char*		get_unique() const { return m_unique; }

		GTimeVal		*get_pstart() { return &m_start; }
		GTimeVal		*get_pend() { return &m_end; }
	protected:
		char			m_unique[MAX_UNIQUE_STR];
		GTimeVal		m_start;
		GTimeVal		m_end;
		int				m_type;
};

class PerfSumData
{
	public:
		PerfSumData()
		{
			m_type = PF_NONE;
			m_sum.tv_sec = 0;
			m_sum.tv_usec = 0;
			m_count = 1;
			m_pos = 0;
			m_longest.tv_sec = 0;
			m_longest.tv_usec = 0;
			memset((void*)m_unique, 0, sizeof(m_unique));
		}

		PerfSumData(int type, GTimeVal tSum, const char *unique )
		{
			m_type = type;
			m_sum.tv_sec = tSum.tv_sec;
			m_sum.tv_usec = tSum.tv_usec;
			m_count = 1;
			m_pos = 0;
			m_longest.tv_sec = 0;
			m_longest.tv_usec = 0;
			memset((void*)m_unique, 0, sizeof(m_unique));
			if ( unique != NULL )
				strncpy( m_unique, unique, strlen(unique)>MAX_UNIQUE_STR?MAX_UNIQUE_STR-1:strlen(unique));
		}

		~PerfSumData() 
		{
		}

		void print();

		PerfSumData	&operator=(const PerfSumData &src)
		{
			m_sum.tv_sec = src.get_sum().tv_sec;
			m_sum.tv_usec = src.get_sum().tv_usec;
			m_type 	= src.get_type();
			m_pos = src.get_longest_pos();
			m_longest.tv_sec = src.get_longest().tv_sec;
			m_longest.tv_usec = src.get_longest().tv_usec;
			if ( src.get_unique() != NULL )
				strcpy( m_unique, src.get_unique() );
			return *this;
		}

		PerfSumData	&operator+=(const PerfSumData &src)
		{
			if ( m_longest.tv_sec < src.get_sum().tv_sec )
			{
				m_longest.tv_sec = src.get_sum().tv_sec;
				m_longest.tv_usec = src.get_sum().tv_usec;
				m_pos = m_count;
			}
			else if ( m_longest.tv_sec == src.get_sum().tv_sec )
			{
				if ( m_longest.tv_usec < src.get_sum().tv_usec )
				{
					m_longest.tv_usec = src.get_sum().tv_usec;
					m_pos = m_count;
				}
			}

			m_sum.tv_sec += src.get_sum().tv_sec;

			if ((m_sum.tv_usec + src.get_sum().tv_usec) >= 1000000 )
			{
				m_sum.tv_sec += 1;
				m_sum.tv_usec = (m_sum.tv_usec + src.get_sum().tv_usec - 1000000);
			}
			else
				m_sum.tv_usec = m_sum.tv_usec + src.get_sum().tv_usec;

			m_count++;

			return *this;
		}

		GTimeVal		get_sum() const { return m_sum; }
		GTimeVal		get_longest() const { return m_longest; }
		int				get_longest_pos() const { return m_pos; }
		int				get_type() const { return m_type; }
		int				get_count() const { return m_count; }
		const char*		get_unique() const { return m_unique; }

	protected:
		GTimeVal		m_sum;
		int				m_type;
		int				m_count;

		int				m_pos;
		GTimeVal		m_longest;
		char			m_unique[MAX_UNIQUE_STR];
};
using namespace __gnu_cxx;  // this is the namespace for hash_set, hash_map etc

class PerfParent
{
	public:
		PerfParent();

		~PerfParent()
		{
			m_data.clear();
			m_sum_data.clear();
		}

		void start( char *unique, int32_t type );
		void end( int32_t type );
		void print( int32_t type );
		void print_sum();

		void add_data_row( GPtrArray *row );
		
	protected:
		typedef hash_map<int32_t, PerfData> PerfDataMap;
		typedef PerfDataMap::iterator IPerfDataMap;

		PerfDataMap		m_data;

		typedef hash_map<int32_t, PerfSumData> PerfSumDataMap;
		typedef PerfSumDataMap::iterator IPerfSumDataMap;

		PerfSumDataMap		m_sum_data;
};

#endif
