
#ifndef  __SQL_PARSER_H__
#define __SQL_PARSER_H__

#include <string>
#include <vector>
#include <set>

#include "network-mysqld.h"
#include "sql-tokenizer.h"
#include "partition.h"

/** parse sql statement to get the table and partition key info,
 *  and then check the db mapping to decide which partition to use
 */
class SqlParser {
    public:
        typedef std::vector<std::string> StringVector;

        SqlParser(GPtrArray *tk, GString *sql);
        ~SqlParser() {
            if (needFreeTokens) {
                for (int i = 0; i < getTokensLen(); i++) {
                    sql_token *token = (sql_token *)tokens->pdata[i];
                    sql_token_free(token);
                }
                g_ptr_array_free(tokens, TRUE);
            }
        }

        db_lookup_retval_t parseSql(std::set<std::string> &dbs, int *txLevel,bool parseMaster);
        void printTokens(const char *str = NULL) const;

        static void setDbPartitions(DbPartitions *dp) { dbPart = dp; }

    private:

        int tokComp(int idx, const std::string &str) const;
        sql_token_id getTokenId(int idx) const;
        uint64_t tokenToUint64(int idx) const;
        std::string getTokenStr(int idx) const;
        int getTokensLen() const { return tokens->len; }

        bool findToken(int start, int end, int tokId, int *where) const;
        bool findTokens(int start, int end, int *tokIds, int size, int *where) const;
        bool parseSimpleTableNameAndAlias(int start, int end,
                                          StringVector &tableNames,
                                          StringVector &aliases) const;
        bool parseTableNameAndAlias(int start, int end,
                                    StringVector &tables,
                                    StringVector &aliases) const;

        bool getSqlFrom(int begin, int *start, int *end) const;
        bool getSqlWhere(int begin, int *start, int *end) const;
        bool findPartitionKeyValue(int start, int end,
                                   const std::string &table,
                                   const std::string &alias,
                                   const std::string &partKey,
                                   std::vector<uint64_t> &keyValues) const;

        void getPartitionKey(const std::string &table, std::string &key) const;
        void getDbMapping(const std::string &table,
                          const std::string &partkey,
                          uint64_t id, std::string &db,bool usemaster,uint64_t insertid) const;

        bool modifySqlForInsert(const std::string &column, uint64_t id);
        bool setDefaultLimit();

        static DbPartitions *dbPart;
        GPtrArray *tokens;
        GString *inputSql;
        bool needFreeTokens;
};

#endif
