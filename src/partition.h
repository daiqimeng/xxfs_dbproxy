
#ifndef  __PARTITION_H__
#define  __PARTITION_H__

#include <mysql.h>
#include "sql-tokenizer.h"
#include <vector>

/**
 * interface for db mapping lookups
 */


    int database_lookup_load();

    typedef enum {
        RET_DB_LOOKUP_SUCCESS,
        RET_USE_DEFAULT_DATABASE,
        RET_USE_ALL_DATABASES,
        RET_USE_ANY_PARTITION,
        RET_USE_ALL_PARTITIONS,
        RET_ERROR_UNPARSABLE,
        RET_DB_LOOKUP_ERROR
    } db_lookup_retval_t;

    /**
     * the caller must free the db_connections array
     * @return RET_SUCCESS, RET_USE_DEFAULT_DATABASE or RET_ERROR_UNPARSABLE
     */
    db_lookup_retval_t database_lookup_from_sql(enum_server_command cmdType, GPtrArray *sqlTok, GPtrArray **db_connections, GString *sqlStr, int *txLevel,bool parseMaster);

    /** configuration handling */
    void load_config_file(const char *conf_file);
    const char *get_config_string(const char *conf_name);
    int get_config_int(const char *conf, int default_val);
    void add_config_string(const char *confName, const char *confVal);

    // backend database configurations
	const   std::vector<int> get_backend_list();
    int get_config_num_backend_addresses();
    const char *get_config_backend_host(int idx);
    int get_config_backend_port(int idx);
    const char *get_config_backend_userid(int idx);
    const char *get_config_backend_passwd(int idx);
    const char *get_config_backend_default_db(int idx);
    const char *get_config_default_database();
    int get_config_max_conn_idle_time();
    int get_config_max_conn_pool_size();

    int get_config_log_all_queries();
    int get_config_log_raw_data();


#include <queue>
#include <ext/hash_map>
#include "mysql_wrapper.h"

using namespace __gnu_cxx;  // this is the namespace for hash_set, hash_map etc

typedef pthread_mutex_t Mutex;

class IdMapping {
    public:

        IdMapping(int32_t interval) : idInterval(interval) {
            idMappingOffsets.reserve(100000);
            idMappingList.reserve(100000);
        } 
        ~IdMapping() {};

        /** find the db that stores data for the given id
         *  @param id is the given id in partition
         *  @return -1 if not found
         */
        int16_t findDb(const std::string &tableName,uint64_t id,int *tableidx,bool usemaster);  

        void insertIdMapping(const std::string &tableName,uint64_t no,uint64_t database_id);

    private:

        /**
         * update idMappingOffsets for all the affected entries
         */
        void updateOffsets(uint64_t startId, uint64_t endId, int32_t offset);

        /** given an Id, find the right entry in idMappingList
         *  @return true when found, and entryIdx points to that entry,
         *   otherwise return false, and entryIdx is new entry to be inserted
         */
        bool findMappingEntry(const std::string &tableName,uint64_t id, int *entryIdx,int *tableidx,bool usemaster);

        struct IdMappingEntry {
            IdMappingEntry()
            {
               
            }

            IdMappingEntry(std::string table_Name,uint64_t table_no,uint64_t table_database_id)
            {
                tableName = table_Name;
                no = table_no;
                database_id = table_database_id;
            }
            std::string tableName;
            uint64_t no;
            uint64_t database_id;
        };

        /** stores the db ids for groups of Ids. the ids do not overlap and are
         *  sorted in asending order.
         */
        typedef std::vector<IdMappingEntry> IdMappingList;
        IdMappingList idMappingList;

        struct Range {
            Range() { low = -1; high = -1;}
            int low;
            int high;
        };
        typedef std::vector<Range> IdMappingOffsets;
        IdMappingOffsets idMappingOffsets;

        // id internal in building IdMappingOffsets
        int32_t idInterval;
};

/** hash function for std::string
 *  used by string hash_set, hash_map etc.
 */
struct StringHash
{
    bool operator()(const std::string &str) const
    {
        return hash<const char *>()(str.c_str());
    }
};


/** maintain the set of available databases.
 *  add to the set if the db is not in the set yet and also assign
 *  the index to it
 */
class DbSet {
    public:
       DbSet() {}
       ~DbSet() {}

       int32_t addDb(const std::string &db);
       std::string getDbByIdx(int32_t idx) const;

       void clear()
       {
          dbNames.clear();
          indicesMap.clear();
       }

    private:

       int32_t getDbIdx(const std::string &db) const;

        typedef std::vector<std::string> StringVector ;

       // all avaiable dbs, the name could be "host:db";
        StringVector dbNames;

        // we need this map so we can find the db index quickly giving a db name
        typedef hash_map<std::string, int32_t, StringHash> DbIndicesMap;
        DbIndicesMap indicesMap;
};

class DbPartitions {
    public:

        DbPartitions() 
        {
            cacheHint = 1000000; enabled = false; sharedIdMapping = NULL;
            configDb = NULL;
            pthread_mutex_init(&mutexForUniqueIds, NULL);
        }

        ~DbPartitions()
        {
            for (TablePartitions::iterator itr = tablePartitions.begin();
                 itr != tablePartitions.end();
                 itr++)
                delete itr->second;

           delete sharedIdMapping;
           delete configDb;
        }

    
       // this is the case all tables are sharing one id range mapping
       void insertDbMapping(const std::string &tableName,uint64_t no,uint64_t database_id);

       // get the default master db, last one in dbList
       void getDefaultDb(std::string &dbStr) const;

       bool getDbInfo(int idx, DbInfo &dbinfo) const;
       // @return "host:port|database|user" string to be used by the caller
       void getDbString(int idx, std::string &dbStr,int tableidx,uint64_t insertid) const;

       /**
        * given a table , a column and an ID, find which db the id is stored in.
        */
       void getDbMapping(const std::string &tableName, const std::string &col, uint64_t id, std::string &dbStr,bool usemaster,uint64_t insertid) const;

       /** cache hint is the id intervals in building first level indices in IdMapping
        *  defalult is 1M
        */
       void setCacheHint(int32_t n = 1000000)
       { cacheHint = n; }


       /** load mapping info from the given database and query.
        *  @return true on success
        */
       bool loadDbMapping(const std::string &host, const std::string &db,
                          const std::string &user, const std::string &passwd,
                          const std::string &mappingSql,
                          const std::string &dbListSql,
                          const std::string &tableColSql);

       void getPartitionKey(const std::string &table, std::string &key) const;
       void getPartitionNum(const std::string &table,uint64_t *num) const; 
       bool isPartitionedTable(const std::string &table);
       int getNumDbPartitions() const { return dbList.size() - 1; }
       bool getNextUniqueId(const std::string &table, uint64_t *id);
       void prefetchUniqueIds(const std::string &table, int num);
       bool needFetchUniqueIds(const std::string &table);
       void getAutoIncrementColumn(const std::string &table, std::string &column);

       bool isEnabled() const { return enabled; }

       const hash_map<int, DbInfo> &getDbList() const { return dbList; }


      /**
       * reset all the stored data in case we need to reload
       */
       void reset();

       void setFetchingdone(const std::string &table);

    private:

        struct AutoLock {
            AutoLock(Mutex *mx) : mutex(mx) { pthread_mutex_lock(mutex); }
            ~AutoLock() { pthread_mutex_unlock(mutex); }
            Mutex *mutex;
        };
        
        /**
         *  the map of a table to its column the partition is based on
         */
       typedef std::queue<uint64_t> UniqueIds;
            struct PartitionInfo {
            std::string partitionColumn;
            std::string autoIncrementColumn;
            UniqueIds uniqueIds;
            bool inFetching;
            uint64_t partitionNum;

            PartitionInfo(const std::string &partKey, const std::string &autoCol,uint64_t partNum) :
                partitionColumn(partKey), autoIncrementColumn(autoCol), inFetching(false),partitionNum(partNum)
            {}
        };
        typedef hash_map<std::string, PartitionInfo, StringHash> TablePartitionInfo;
        TablePartitionInfo tablePartitionInfo;

        void updateTablePartitionInfo(const std::string &table, const PartitionInfo &info);

        int getUniqueIdPoolSize() const;
        
        /**
         * all the available databases
         */
        DbSet dbSet;

        //detailed info about all available backend databases;
        hash_map<int, DbInfo> dbList;

        /**
         * maps a table name to its id partiton mapping
         */
        typedef hash_map<std::string, IdMapping *, StringHash>
            TablePartitions; 
        TablePartitions tablePartitions;

        Mutex  mutexForUniqueIds;

        IdMapping *sharedIdMapping; // all the partitioned tables share this mapping

        MySql *configDb;

        int32_t cacheHint;
        bool enabled;
};

#endif
