#include <stdlib.h>
#include <stdio.h>
#include "partition.h"
#include "mysql_wrapper.h"
#include "sql-parser.h"
#include "messages.h"
#include "network-mysqld-proto.h"

DbPartitions dbPartitions;

DbPartitions *SqlParser::dbPart = &dbPartitions;

void IdMapping::insertIdMapping(const std::string &tableName, uint64_t no, uint64_t database_id) {
    IdMappingEntry entry(tableName, no, database_id);
    idMappingList.push_back(entry);
    return;
}

bool IdMapping::findMappingEntry(const std::string &tableName, uint64_t id, int *entryIdx, int *tableIdx, bool usemaster) {
    uint64_t totalnum;
    uint64_t num;
    *entryIdx = -2;
    dbPartitions.getPartitionNum(tableName, &totalnum);
    if (totalnum > 1) {
        num = id % totalnum;
        for (size_t i = 0; i < idMappingList.size(); i++) {
            if (idMappingList[i].no == num && idMappingList[i].tableName == tableName) {
                *entryIdx = idMappingList[i].database_id;
                *tableIdx = num;
                break;
            }
        }
    } else {
        for (size_t i = 0; i < idMappingList.size(); i++) {
            if (idMappingList[i].tableName == tableName) {
                *entryIdx = idMappingList[i].database_id;
                *tableIdx = -2;
                break;
            }
        }
    }
    if (*entryIdx > 0 && !usemaster) {
        for (hash_map<int, DbInfo>::const_iterator itr = dbPartitions.getDbList().begin();
                itr != dbPartitions.getDbList().end();
                itr++) {
            if (itr->second.masterid == *entryIdx) {
                *entryIdx = itr->second.id;
            }
        }
    }
    if (*entryIdx < 0) {
        return false;
    } else {
        return true;
    }

    //dqm
    /*
    if (low > high)
        return false;

    int mid = low;

    while (low <= high) {
        mid = (low + high) / 2;
        if (idMappingList[mid].startId <= id && id <= idMappingList[mid].endId) {
            if (entryIdx)
     *entryIdx  = mid;
            return true;
        }
        if (idMappingList[mid].startId > id)
            high = mid - 1;
        else
            low = mid + 1;
    }

    if (entryIdx) {
        if (idMappingList[mid].endId < id)
     *entryIdx = mid + 1;
        else
     *entryIdx = mid;
    }
     */
}

/*
void IdMapping::updateOffsets(uint64_t startId, uint64_t endId, int offset)
{
    size_t endIdx = endId / idInterval;
    if (endIdx + 1 > idMappingOffsets.size()) {
        idMappingOffsets.resize(endIdx + 1);
    }

    for (size_t i = startId / idInterval; i <= endIdx; i++) {
        if (idMappingOffsets[i].low == -1)
            idMappingOffsets[i].low = offset;
        else if (offset < idMappingOffsets[i].low) 
            idMappingOffsets[i].low = offset;

        if (idMappingOffsets[i].high == -1)
            idMappingOffsets[i].high = offset;
        else if (offset > idMappingOffsets[i].high) 
            idMappingOffsets[i].high = offset;
    }
}
 */
int16_t IdMapping::findDb(const std::string &tableName, uint64_t id, int *tableidx, bool usemaster) {
    int idx;
    if (findMappingEntry(tableName, id, &idx, tableidx, usemaster))
        return idx;
    return -1;
}

int32_t DbSet::addDb(const std::string &db) {
    int32_t idx = getDbIdx(db);

    if (idx >= 0) // db is already in the set
        return idx;

    dbNames.push_back(db);
    indicesMap.insert(std::make_pair(db, dbNames.size() - 1));

    return dbNames.size() - 1;
}

int32_t DbSet::getDbIdx(const std::string &db) const {
    DbIndicesMap::const_iterator itr = indicesMap.find(db);

    if (itr != indicesMap.end())
        return itr->second;
    return -1;
}

std::string DbSet::getDbByIdx(int32_t idx) const {
    if (idx >= 0 && idx < (int32_t) (dbNames.size()))
        return dbNames[idx];
    else
        return "";
}

bool DbPartitions::isPartitionedTable(const std::string &table) {
    TablePartitionInfo::iterator itr = tablePartitionInfo.find(table);

    if (itr == tablePartitionInfo.end() || itr->second.partitionColumn.empty())
        return false;
    return true;
}

void DbPartitions::getPartitionKey(const std::string &table,
        std::string &key) const {
    TablePartitionInfo::const_iterator itr = tablePartitionInfo.find(table);
    if (itr != tablePartitionInfo.end())
        key = itr->second.partitionColumn;
    else
        key.erase();
}

void DbPartitions::getPartitionNum(const std::string &table,
        uint64_t *num) const {
    TablePartitionInfo::const_iterator itr = tablePartitionInfo.find(table);
    if (itr != tablePartitionInfo.end())
        *num = itr->second.partitionNum;
    else
        *num = 0;
}

void DbPartitions::getAutoIncrementColumn(const std::string &table, std::string &column) {
    TablePartitionInfo::const_iterator itr = tablePartitionInfo.find(table);
    if (itr != tablePartitionInfo.end())
        column = itr->second.autoIncrementColumn;
    else
        column.erase();
}

void DbPartitions::updateTablePartitionInfo(const std::string &table,
        const PartitionInfo &info) {
    TablePartitionInfo::iterator itr = tablePartitionInfo.find(table);
    if (itr != tablePartitionInfo.end()) {
        log_warning("more than one partition info entry "
                "specified for table %s.", table.c_str());
    } else {
        tablePartitionInfo.insert(std::make_pair(table, info));
    }
}

void DbPartitions::insertDbMapping(const std::string &tableName,
        uint64_t no,
        uint64_t database_id) {
    if (sharedIdMapping == NULL)
        sharedIdMapping = new IdMapping(cacheHint);

    sharedIdMapping->insertIdMapping(tableName, no, database_id);
}

void DbPartitions::getDefaultDb(std::string &dbStr) const {
    // the last one in dbList is the default master
    getDbString(0, dbStr, -2, 0);
}

bool DbPartitions::getDbInfo(int idx, DbInfo &dbinfo) const {
    hash_map<int, DbInfo>::const_iterator itr = dbList.find(idx);
    if (itr != dbList.end()) {
        dbinfo = itr->second;
        return true;
    }
    return false;
}

void DbPartitions::getDbString(int idx, std::string &dbStr, int tableidx, uint64_t insertid) const {
    DbInfo dbInfo;
    getDbInfo(idx, dbInfo);
    char str[50];
    snprintf(str, sizeof (str), ":%d|%d|%ld|", dbInfo.port, tableidx, insertid);
    dbStr = dbInfo.host + str + dbInfo.db + "|" + dbInfo.user;
}

void DbPartitions::getDbMapping(const std::string &tableName,
        const std::string &colName,
        uint64_t id,
        std::string &dbStr, bool usemaster, uint64_t insertid) const {
    int tableidx;
    if (sharedIdMapping) {
        int i = sharedIdMapping->findDb(tableName, id, &tableidx, usemaster);
        if (i >= 0) {
            getDbString(i, dbStr, tableidx, insertid);
        } else
            dbStr = "";
        return;
    }

    TablePartitions::const_iterator itr =
            tablePartitions.find(tableName + ":" + colName);

    if (itr == tablePartitions.end()) {
        dbStr = "";
        return;
    }

    int32_t idx = itr->second->findDb(tableName, id, &tableidx, usemaster);

    dbStr = dbSet.getDbByIdx(idx);
}

void DbPartitions::reset() {
    for (TablePartitions::iterator itr = tablePartitions.begin();
            itr != tablePartitions.end();
            itr++)
        delete itr->second;

    tablePartitions.clear();
    dbSet.clear();
    dbList.clear();

    tablePartitionInfo.clear();

    delete sharedIdMapping;
    sharedIdMapping = NULL;

    delete configDb;
    configDb = NULL;
}

static void *fetchUniqueIds(void *arg) {
    const char *table = (const char *) arg;

    pthread_t thId = pthread_self();

    log_debug("feching next ids for table %s, thread id = %u", table, thId);
    dbPartitions.prefetchUniqueIds(table, -1);

    dbPartitions.setFetchingdone(table);

    delete []table;

    log_debug("thread %u done for fetching next ids.", thId);
    return NULL;
}

//start a thread to fetch unique ids if necessary

static void startFetchingUniqueIdThread(const std::string &table) {
    char *tableStr = new char[table.size() + 1];
    strcpy(tableStr, table.c_str());

    pthread_t fetchingThread;
    if (pthread_create(&fetchingThread, NULL, fetchUniqueIds, tableStr)) {
        log_fatal("Error in creating thread.\n");
        exit(1);
    }

    pthread_detach(fetchingThread);
}

void DbPartitions::setFetchingdone(const std::string &table) {
    TablePartitionInfo::iterator itr = tablePartitionInfo.find(table);

    AutoLock lock(&mutexForUniqueIds);

    if (itr != tablePartitionInfo.end())
        itr->second.inFetching = false;
    else {
        log_error("%s.%d: could not find partition info for table %s\n",
                __FILE__, __LINE__, table.c_str());
    }
}

bool DbPartitions::getNextUniqueId(const std::string &table, uint64_t *id) {
    bool rv = true;

    if (dbPartitions.needFetchUniqueIds(table)) {
        startFetchingUniqueIdThread(table);
        prefetchUniqueIds(table, 1);
    }

    UniqueIds *ids = NULL;
    TablePartitionInfo::iterator itr = tablePartitionInfo.find(table);
    if (itr != tablePartitionInfo.end())
        ids = &(itr->second.uniqueIds);
    else
        return false;

    pthread_mutex_lock(&mutexForUniqueIds);

    if (!ids->empty()) {
        *id = ids->front();
        ids->pop();
        rv = true;
    } else
        rv = false;

    pthread_mutex_unlock(&mutexForUniqueIds);
    return rv;
}

int DbPartitions::getUniqueIdPoolSize() const {
    static int sz = -1;
    if (sz > 0)
        return sz;

    const char *conf = get_config_string("UNIQUE_ID_POOL_SIZE");
    if (conf == NULL)
        sz = 100; //default
    else
        sz = atoi(conf);
    return sz;
}

bool DbPartitions::needFetchUniqueIds(const std::string &table) {
    AutoLock al(&mutexForUniqueIds);

    TablePartitionInfo::iterator itr = tablePartitionInfo.find(table);
    if (itr != tablePartitionInfo.end()) {
        if (itr->second.inFetching)
            return false;
        int sz = itr->second.uniqueIds.size();

        // if the queue is less than 1/3 full
        if (sz <= (getUniqueIdPoolSize() / 3)) {
            itr->second.inFetching = true;
            return true;
        };
    }

    return false;
}

void DbPartitions::prefetchUniqueIds(const std::string &table, int num) {
    UniqueIds *ids = NULL;
    TablePartitionInfo::iterator itr = tablePartitionInfo.find(table);

    if (itr != tablePartitionInfo.end())
        ids = &(itr->second.uniqueIds);
    else {
        log_error("%s.%d: could find partition info for table %s\n",
                __FILE__, __LINE__, table.c_str());
        return;
    }

    if (num <= 0) {
        num = getUniqueIdPoolSize();
    }

    pthread_mutex_lock(&mutexForUniqueIds);
    int needed = int(ids->size()) >= num ? 0 : num - int(ids->size());
    pthread_mutex_unlock(&mutexForUniqueIds);

    if (needed <= 0)
        return;

    char sql[256];
    snprintf(sql, sizeof (sql), "SELECT get_next_id('%s', %d)", table.c_str(), needed);

    std::vector<std::string> res;
    if (!configDb->query(sql, &res)) {
        return;
    }

    uint64_t id = uint64_t(atoll(res[0].c_str()));
    pthread_mutex_lock(&mutexForUniqueIds);
    for (; needed > 0; needed--) {
        ids->push(id);
        id++;
    }
    pthread_mutex_unlock(&mutexForUniqueIds);
}

bool DbPartitions::loadDbMapping(const std::string &host, const std::string &db,
        const std::string &user, const std::string &passwd,
        const std::string &mappingSql,
        const std::string &dbListSql,
        const std::string &tableColSql) {
    const int defaultMysqlPort = 3306;
    DbInfo dbInfo(0, host, defaultMysqlPort, db, user, passwd, 0);

    configDb = new MySql(dbInfo);

    if (!configDb->connect()) {
        log_warning("failed in loadDbMapping ...\n");
        enabled = false;
        return false;
    }

    // query the db to get db mapping info
    std::vector<std::string> res;
    if (!configDb->query(mappingSql.c_str(), &res)) {
        log_warning("failed in loadDbMapping ...\n");
        enabled = false;
        return false;
    };


    for (size_t i = 0; i < res.size(); i += 3) {
        insertDbMapping(res[i], atoi(res[i + 1].c_str()), atoi(res[i + 2].c_str()));
    }

    // query the db to get db partition list
    res.clear();
    if (!configDb->query(dbListSql.c_str(), &res)) {
        log_warning("failed in loadDbMapping ...\n");
        enabled = false;
        return false;
    };
    for (size_t i = 0; i < res.size(); i += 7) {

        DbInfo db(atoi(res[i].c_str()), res[i + 1], atoi(res[i + 2].c_str()), res[i + 3], res[i + 4], res[i + 5], atoi(res[i + 6].c_str()));
        dbList.insert(std::make_pair(atoi(res[i].c_str()), db));
    }

    //add default database
    dbList.insert(std::make_pair(0, dbInfo));
    // query the db to get table partition info
    res.clear();
    if (!configDb->query(tableColSql.c_str(), &res)) {
        log_warning("failed in loadDbMapping ...\n");
        enabled = false;
        return false;
    };

    for (size_t i = 0; i < res.size(); i += 4) {
        PartitionInfo info((atoi(res[i + 3].c_str()) > 1) ? res[i + 1] : "", res[i + 2], atoi(res[i + 3].c_str()));
        updateTablePartitionInfo(res[i], info);
        if (!info.autoIncrementColumn.empty())
            prefetchUniqueIds(res[i], -1);
    }

    enabled = true;
    return true;
}

const std::vector<int> get_backend_list() {
    std::vector<int> sid;
    for (hash_map<int, DbInfo>::const_iterator itr = dbPartitions.getDbList().begin(); itr != dbPartitions.getDbList().end(); itr++) {
        sid.push_back(itr->second.id);
    }
    return sid;
}

int get_config_num_backend_addresses() {
    return dbPartitions.getDbList().size();
}

const char *get_config_default_database() {
    static int first = 1;
    static const char *db = NULL;
    if (first) {
        first = false;
        db = get_config_string("PARTITION_INFO_DB");
    }
    return db;
}

const char *get_config_backend_host(int idx) {
    DbInfo dbInfo;
    dbPartitions.getDbInfo(idx, dbInfo);
    return dbInfo.host.c_str();
}

int get_config_backend_port(int idx) {
    DbInfo dbInfo;
    dbPartitions.getDbInfo(idx, dbInfo);
    return dbInfo.port;
}

const char *get_config_backend_userid(int idx) {
    DbInfo dbInfo;
    dbPartitions.getDbInfo(idx, dbInfo);
    return dbInfo.user.c_str();
}

const char *get_config_backend_passwd(int idx) {
    DbInfo dbInfo;
    dbPartitions.getDbInfo(idx, dbInfo);
    return dbInfo.password.c_str();
}

const char *get_config_backend_default_db(int idx) {
    DbInfo dbInfo;
    dbPartitions.getDbInfo(idx, dbInfo);
    return dbInfo.db.c_str();
}

int database_lookup_load() {
    time_t start = time(NULL);
    log_info("loading db mapping info ...\n");

    const char *host = get_config_string("PARTITION_INFO_HOST");
    const char *db = get_config_string("PARTITION_INFO_DB");
    const char *usr = get_config_string("DB_USER");
    const char *pw = get_config_string("DB_PASSWD");

    if (!host || !db || !usr || !pw) {
        log_warning("database mapping info is not set up properly, mapping is disabled.\n");
        return 0;
    }

    if (!dbPartitions.loadDbMapping(host, db, usr, pw,
            "SELECT table_name,no,database_id FROM table_setting ORDER by table_name",
            "SELECT database_id,host_name, port_number, database_name,user,passwd,master_sid from db_setting where active=1",
            "SELECT table_name, column_name, increment_column, table_num FROM kind_setting")) {
        log_warning("database mapping loading failed.\n");
        return -1;
    } else {
        log_info("done db mapping info loading in %d seconds.\n", time(NULL) - start);
    }
    return 0;
}

db_lookup_retval_t database_lookup_from_sql(enum_server_command cmdType, GPtrArray *sqlTok, GPtrArray **db_connections, GString *sqlStr, int *txLevel, bool parseMaster) {

    static int nextAnyDb = 0;

    if (!dbPartitions.isEnabled())
        return RET_USE_DEFAULT_DATABASE;

    SqlParser parser(sqlTok, sqlStr);
    std::set<std::string> dbs;

    db_lookup_retval_t rv;

    switch (cmdType) {
        case COM_QUERY:
            rv = parser.parseSql(dbs, txLevel, parseMaster);
            break;
        case COM_FIELD_LIST:
        case COM_STATISTICS:
        case COM_PING:
            rv = RET_USE_DEFAULT_DATABASE;
            break;
        case COM_INIT_DB:
        {
            const char *db = get_config_default_database();
            if (db) {
                g_string_truncate(sqlStr, NET_HEADER_SIZE + 1);
                g_string_append(sqlStr, db);
                network_mysqld_proto_set_header_len((unsigned char *) (sqlStr->str),
                        sqlStr->len - NET_HEADER_SIZE);
            }
            rv = RET_USE_DEFAULT_DATABASE;
            break;
        }
        default:
            log_warning("unsupported query command type (%d), "
                    "using default database.\n", cmdType);
            rv = RET_USE_DEFAULT_DATABASE;
            break;
    }

    *db_connections = g_ptr_array_new();

    for (std::set<std::string>::iterator itr = dbs.begin(); itr != dbs.end(); itr++) {
        g_ptr_array_add(*db_connections, g_string_new(itr->c_str()));
    }


    switch (rv) {
        case RET_USE_ALL_PARTITIONS:
        {
            /*
            for (int i = 0; i < dbPartitions.getNumDbPartitions(); i++) {
                std::string db;
                dbPartitions.getDbString(i, db,-1);
                g_ptr_array_add(*db_connections, g_string_new(db.c_str()));
            }
             * */
            return RET_DB_LOOKUP_SUCCESS;
        }

        case RET_USE_ALL_DATABASES:
        {
             
            for (hash_map<int, DbInfo>::const_iterator itr = dbPartitions.getDbList().begin();
                    itr != dbPartitions.getDbList().end();
                    itr++) {
                if (itr->second.masterid == 0) {
                    std::string db;
                    dbPartitions.getDbString(itr->second.id, db,-2, 0);
                    g_ptr_array_add(*db_connections, g_string_new(db.c_str()));
                }
            }
            return RET_DB_LOOKUP_SUCCESS;
            /*
            for (int i = 0; i < dbPartitions.getNumDbPartitions() + 1; i++) {
                std::string db;
                dbPartitions.getDbMapping(table, partitionKey, keyValues[k], db, 1, 0);
                dbPartitions.getDbString(i, db, -1);
                g_ptr_array_add(*db_connections, g_string_new(db.c_str()));
            }
            return RET_DB_LOOKUP_SUCCESS;*/
        }

        case RET_USE_ANY_PARTITION:
        {
            std::string db;
            nextAnyDb = (nextAnyDb + 1) % dbPartitions.getNumDbPartitions();

            dbPartitions.getDbString(nextAnyDb, db, -1, 0);
            g_ptr_array_add(*db_connections, g_string_new(db.c_str()));
            return RET_DB_LOOKUP_SUCCESS;
        }

        case RET_USE_DEFAULT_DATABASE:
        {
            std::string db;
            dbPartitions.getDefaultDb(db);
            g_ptr_array_add(*db_connections, g_string_new(db.c_str()));
            return RET_DB_LOOKUP_SUCCESS;
        }
        default:
            break;
    }

    return rv;
}

typedef hash_map<std::string, std::string, StringHash> Config;
static Config config;

void load_config_file(const char *confFile) {
    FILE *fp = fopen(confFile, "r");
    if (fp == NULL) {
        //        log_warning("Error in opening file %s for read.\n", confFile);
        return;
    }

    char buf[4096];

    while (fgets(buf, sizeof (buf), fp)) {
        buf[strlen(buf) - 1 ] = '\0'; // remove '\n';
        if (buf[0] == '#') //skip comments
            continue;

        bool empty = true;
        for (size_t i = 0; i < strlen(buf); i++) {
            if (!strchr("\n\t ", buf[i])) {
                empty = false;
                break;
            }
        }

        if (empty)
            continue;

        char *sep = strchr(buf, '=');

        if (sep == NULL) {
            log_warning("bad format in line: %s\n", buf);
            continue;
        }

        std::string key(buf, sep - buf);
        std::string val(sep + 1);

        //remove trailing and leading white spaces
        while (!key.empty() && strchr("\t ", key[0]))
            key.erase(key.begin());
        while (!key.empty() && strchr("\t ", *(key.rbegin())))
            key.erase(key.end() - 1);
        while (!val.empty() && strchr("\t ", val[0]))
            val.erase(val.begin());
        while (!val.empty() && strchr("\t ", *(val.rbegin())))
            val.erase(val.end() - 1);

        config.insert(std::make_pair(key, val));

        if (key == "LOGFILE")
            set_log_file(val.c_str());
    }

    fclose(fp);
}

void add_config_string(const char *confName, const char *confVal) {
    if (confName && confVal) {
        config.erase(confName);
        config.insert(std::make_pair(confName, confVal));

        if (strcmp(confName, "LOGFILE") == 0)
            set_log_file(confVal);
    }
}

const char *get_config_string(const char *confName) {
    Config::iterator itr = config.find(confName);
    if (itr == config.end())
        return NULL;
    return itr->second.c_str();
}

int get_config_int(const char *confName, int defaultVal) {
    Config::iterator itr = config.find(confName);
    if (itr == config.end())
        return defaultVal;
    return atoi(itr->second.c_str());
}

int get_config_max_conn_idle_time() {
    static int maxIdle = -1;

    if (maxIdle < 0) {
        maxIdle = get_config_int("MAX_CONN_IDLE_TIME", 7200); //default is 2 hours.
    }
    return maxIdle;
}

int get_config_max_conn_pool_size() {
    static int maxSize = -1;
    if (maxSize == -1) {
        maxSize = get_config_int("MAX_CONN_POOL_SIZE", 10); //default is 50
    }

    return maxSize;
}

int get_config_log_all_queries() {
    static int logAllQueries = -1;
    if (logAllQueries == -1)
        logAllQueries = get_config_int("LOG_ALL_QUERIES", 0);

    return logAllQueries;
}

int get_config_log_raw_data() {
    static int logRaw = -1;
    if (logRaw == -1)
        logRaw = get_config_int("LOG_RAW_DATA", 0);

    return logRaw;
}

