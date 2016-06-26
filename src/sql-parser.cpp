#include "sql-parser.h"
#include <stdlib.h>
#include <stdio.h>
#include "network-mysqld-proto.h"
#include "messages.h"

SqlParser::SqlParser(GPtrArray *tk, GString *sql) :
tokens(tk), inputSql(sql) {
    needFreeTokens = tokens == NULL;

    if (tokens == NULL) {
        tokens = g_ptr_array_new();
        sql_tokenizer(tokens, sql->str, sql->len);
    }
}

int SqlParser::tokComp(int idx, const std::string &str) const {
    const sql_token *tk = (const sql_token *) (tokens->pdata[idx]);
    return str.compare(0, str.size(), tk->text->str, tk->text->len);
}

sql_token_id SqlParser::getTokenId(int idx) const {
    return ((const sql_token *) (tokens->pdata[idx]))->token_id;
}

void SqlParser::printTokens(const char *str) const {
    std::string msg(str ? str : "");
    if (inputSql) {
        msg.append("\"");
        msg.append(inputSql->str + NET_HEADER_SIZE + 1, inputSql->len - NET_HEADER_SIZE - 1);
        msg.append("\".");
    }

    log_warning(msg.c_str());

    for (size_t i = 0; i < tokens->len; i++) {
        log_debug("SQL Tokens: %2d %20s: \"%s\"\n", i,
                sql_token_get_name(getTokenId(i)),
                getTokenStr(i).c_str());
    }

}

uint64_t SqlParser::tokenToUint64(int idx) const {
    uint64_t b = 0;
    const sql_token *tk = (const sql_token *) (tokens->pdata[idx]);

    const char *p = tk->text->str;
    for (size_t i = 0; i < tk->text->len; i++, p++) {
        b = b * 10 + *p - '0';
    }
    return b;
}

std::string SqlParser::getTokenStr(int idx) const {
    const sql_token *tk = (const sql_token *) (tokens->pdata[idx]);
    return std::string(tk->text->str, tk->text->len);
}

bool SqlParser::findToken(int start, int end, int tokId, int *where) const {
    int i = start;

    while (i < end && getTokenId(i) != tokId)
        i++;

    *where = i;
    return i < end;
}

bool SqlParser::findTokens(int start, int end, int *tokIds, int size, int *where) const {
    int i;
    for (i = start; i < end; i++) {
        int id = getTokenId(i);
        for (int k = 0; k < size; k++) {
            if (tokIds[k] == id) {
                *where = i;
                return true;
            }
        }
    }

    *where = i;
    return false;
}

bool SqlParser::parseSimpleTableNameAndAlias(int start, int end,
        StringVector &tableNames,
        StringVector &aliases) const {
    if (end - start == 1) {
        if (getTokenId(start) == TK_LITERAL) {
            tableNames.push_back(getTokenStr(start));
            aliases.push_back("");
            return true;
        }
    } else if (end - start == 2) {
        if (getTokenId(start) == TK_LITERAL &&
                getTokenId(start + 1) == TK_LITERAL) {
            tableNames.push_back(getTokenStr(start));
            aliases.push_back(getTokenStr(start + 1));
            return true;
        }
    } else if (end - start == 3 && getTokenId(start + 1) == TK_SQL_AS) {
        if (getTokenId(start) == TK_LITERAL &&
                getTokenId(start + 2) == TK_LITERAL) {
            tableNames.push_back(getTokenStr(start));
            aliases.push_back(getTokenStr(start + 2));
            return true;
        }
    }

    return false;
}

bool SqlParser::parseTableNameAndAlias(int start, int end,
        StringVector &tables,
        StringVector &aliases) const {
    for (int i = start; i < end;) {

        // Assume ',' separated mutiple table list
        // this is not always true

        // find the first table part
        int keyIds[] = {TK_SQL_INNER, TK_SQL_CROSS, TK_SQL_STRAIGHT_JOIN,
            TK_SQL_LEFT, TK_SQL_RIGHT, TK_SQL_NATURAL, TK_SQL_JOIN, TK_COMMA};

        int table0End;
        if (findTokens(i, end, keyIds, sizeof (keyIds) / sizeof (int), &table0End)) {
            if (!parseSimpleTableNameAndAlias(i, table0End, tables, aliases))
                return false;
            if (getTokenId(table0End) == TK_COMMA) {
                i = table0End + 1;
                continue;
            }
        } else {
            return parseSimpleTableNameAndAlias(i, table0End, tables, aliases);
        }

        bool firstJoin = true;
        while (1) {
            // find the second table in join
            int joinKw[] = {TK_SQL_JOIN, TK_SQL_STRAIGHT_JOIN};
            int table1Start;
            if (!findTokens(table0End, end, joinKw, sizeof (joinKw) / sizeof (int),
                    &table1Start))
                return !firstJoin;

            table1Start++;

            int table1End;
            int condKw[] = {TK_SQL_ON, TK_SQL_USING, TK_COMMA};
            bool found = findTokens(table1Start, end, condKw, sizeof (condKw) / sizeof (int), &table1End);

            if (!parseSimpleTableNameAndAlias(table1Start, table1End, tables, aliases))
                return false;

            i = table1End + 1;
            table0End = i;
            firstJoin = false;

            if (found && getTokenId(table1End) == TK_COMMA)
                break;
            else if (found)
                continue;
            else
                return true;
        }
    }

    return true;
}

bool SqlParser::getSqlFrom(int begin, int *start, int *end) const {
    if (!findToken(begin, tokens->len, TK_SQL_FROM, start))
        return false;

    (*start)++;

    int ids[] = {TK_SQL_WHERE, TK_SQL_GROUP, TK_SQL_HAVING, TK_SQL_ORDER,
        TK_SQL_LIMIT, TK_SQL_PROCEDURE, TK_SQL_INTO, TK_SQL_FOR,
        TK_SQL_LOCK, TK_SQL_USE, TK_SQL_IGNORE, TK_SQL_FORCE};

    findTokens(*start, tokens->len, ids, sizeof (ids) / sizeof (int), end);
    return true;
}

bool SqlParser::getSqlWhere(int begin, int *start, int *end) const {
    if (!findToken(begin, tokens->len, TK_SQL_WHERE, start))
        return false;

    (*start)++;

    int ids[] = {TK_SQL_GROUP, TK_SQL_HAVING, TK_SQL_ORDER,
        TK_SQL_LIMIT, TK_SQL_PROCEDURE, TK_SQL_INTO, TK_SQL_FOR,
        TK_SQL_LOCK};

    findTokens(*start, tokens->len, ids, sizeof (ids) / sizeof (int), end);
    return true;
}

bool SqlParser::findPartitionKeyValue(int start, int end,
        const std::string &table,
        const std::string &alias,
        const std::string &partKey,
        std::vector<uint64_t> &keyValues) const {
    int i = start;
    while (i < end) {
        if (getTokenId(i) != TK_LITERAL || tokComp(i, partKey)) {
            i++;
            continue;
        }

        // check the prefix if there is any
        if (i - start >= 2 && getTokenId(i - 1) == TK_DOT &&
                getTokenId(i - 2) == TK_LITERAL) {
            if (tokComp(i - 2, table) && tokComp(i - 2, alias)) {
                i++;
                continue;
            }
        }

        // id = NUM case
        if ((i + 2 < end) && getTokenId(i + 1) == TK_EQ &&
                getTokenId(i + 2) == TK_INTEGER) {
            keyValues.push_back(tokenToUint64(i + 2));
            i += 3;
            continue;
        }

        // IN (...) case
        if (i + 3 < end && getTokenId(i + 1) == TK_SQL_IN &&
                getTokenId(i + 2) == TK_OBRACE) {

            i += 3;
            for (int k = i; k < end; k++, i++) {
                if (getTokenId(k) == TK_CBRACE)
                    break;
                if (getTokenId(k) == TK_INTEGER) {
                    if (getTokenId(k - 1) != TK_COMMA &&
                            getTokenId(k - 1) != TK_OBRACE)
                        return false;

                    keyValues.push_back(tokenToUint64(k));
                }
            }
            continue;
        }
        i++;
    }
    return true;
}

void SqlParser::getPartitionKey(const std::string &table, std::string &key) const {
    dbPart->getPartitionKey(table, key);
}

bool SqlParser::modifySqlForInsert(const std::string &column, uint64_t id) {
    if (!inputSql)
        return true;

    // find the position of ") VALUES (" first

    //make the gstring NULL terminated first
    g_string_append_c(inputSql, '\0');

    const char *inputStr = inputSql->str;
    const char *start = inputStr + NET_HEADER_SIZE + 1; //specific for mysql query encoding

    const char *valPtr = NULL;

    while ((valPtr = strcasestr(start, "VALUES")) != NULL) {

        // confirm following '('
        const char *p = valPtr + 6;

        // skip white spaces
        while (*p && strchr("\n\t \f", *p))
            p++;

        if (*p != '(') {
            start = p;
            continue;
        }

        const char *valueEnd = p + 1;

        //confirm ')'
        p = valPtr - 1;
        // skip white spaces
        while (p > inputStr && strchr("\n\t \f", *p))
            p--;

        if (*p != ')') {
            start += 6;
            continue;
        }

        const char *firstInsert = p;

        const char *lastInsert = inputStr + inputSql->len - 1;
        //find the last ')'
        p = lastInsert;
        // skip white spaces
        while (p > valueEnd && strchr("\n\t \f", *p))
            p--;

        if (*p != ')') {
            return false;
        }

        lastInsert = p;

        char buf[32];
        snprintf(buf, sizeof (buf), ", %qu", (unsigned long long) id);
        g_string_insert(inputSql, lastInsert - inputStr, buf);

        std::string tmpStr = ", " + column;
        g_string_insert(inputSql, firstInsert - inputStr, tmpStr.c_str());

        //remove the trailing '\0';
        g_string_truncate(inputSql, inputSql->len - 1);

        network_mysqld_proto_set_header_len((unsigned char *) (inputSql->str), inputSql->len - NET_HEADER_SIZE);

        return true;
    }

    return false;
}

void SqlParser::getDbMapping(const std::string &table,
        const std::string &partKey,
        uint64_t id, std::string &dbstr, bool usemaster, uint64_t insertid) const {
    dbPart->getDbMapping(table, partKey, id, dbstr, usemaster, insertid);
}

bool SqlParser::setDefaultLimit() {
    static const char *defaultLimit = NULL;
    if (defaultLimit == NULL) {
        defaultLimit = get_config_string("DEFAULT_SELECT_LIMIT");
        if (defaultLimit == NULL)
            defaultLimit = "500";
    }

    int limitPos;
    if (!findToken(1, getTokensLen(), TK_SQL_LIMIT, &limitPos)) {
        g_string_append(inputSql, " LIMIT ");
        g_string_append(inputSql, defaultLimit);
        network_mysqld_proto_set_header_len((unsigned char *) (inputSql->str), inputSql->len - NET_HEADER_SIZE);

        return true;
    }

    if (limitPos + 3 > getTokensLen() - 1) // no offset
        return true;

    if (limitPos + 3 < getTokensLen() - 1) {
        printTokens("only queries with LIMIT at the last field is supported now!");
        return false;
    }

    int offset, rowCount;
    if (getTokenId(limitPos + 2) == TK_COMMA) {
        offset = atoi(getTokenStr(limitPos + 1).c_str());
        rowCount = atoi(getTokenStr(limitPos + 3).c_str());
    } else if (getTokenId(limitPos + 2) == TK_SQL_OFFSET) {
        offset = atoi(getTokenStr(limitPos + 3).c_str());
        rowCount = atoi(getTokenStr(limitPos + 1).c_str());
    } else {
        printTokens("Unrecognized LIMIT OFFSET format:");
        return false;
    }

    // TODO: the tokenizer needs to have the field offset info
    // for now, we search LIMIT from the end
    char *p = inputSql->str + inputSql->len - 1;
    while (toupper(*p) != 'L') p--;

    // remove the old LIMIT OFFSET info
    //
    g_string_truncate(inputSql, p - inputSql->str);

    // add new LIMIT OFFSET info
    char buff[128];
    snprintf(buff, sizeof (buff), "LIMIT %d", offset + rowCount);
    g_string_append(inputSql, buff);
    network_mysqld_proto_set_header_len((unsigned char *) (inputSql->str), inputSql->len - NET_HEADER_SIZE);

    return true;
}

db_lookup_retval_t SqlParser::parseSql(std::set<std::string> &dbs, int *txLevel, bool parseMaster) {
    dbs.clear();

    StringVector tables, aliases;

    if (getTokensLen() <= 0) {
        log_warning("empty sql for dababase lookup!\n");
        return RET_ERROR_UNPARSABLE;
    }

    switch (getTokenId(0)) {
        case TK_SQL_SELECT:
        {
            int usemaster = 0;
            if (parseMaster) usemaster = 1;
            // special handling for our get unique id function call.
            if (getTokensLen() > 1 && getTokenStr(1) == "get_next_id")
                return RET_USE_DEFAULT_DATABASE;

            int fromStart, fromEnd;

            if (!getSqlFrom(0, &fromStart, &fromEnd)) {
                if ((getTokensLen() > 3 && getTokenId(1) == TK_LITERAL &&
                        getTokenId(2) == TK_OBRACE) ||
                        (getTokensLen() == 2 && getTokenId(1) == TK_LITERAL)) {

                    // for special stored procedures
                    return RET_USE_ALL_PARTITIONS;
                }

                printTokens("no FROM found, using default db: ");
                return RET_USE_DEFAULT_DATABASE;
            }

            if (!parseTableNameAndAlias(fromStart, fromEnd, tables, aliases)) {
                printTokens("could not parse table alias, using default db: ");
                return RET_USE_DEFAULT_DATABASE;
            }

            // for non-partitioned tables, we can use any db
            // since each db should have a view of it
            bool partitioned = false;
            for (size_t i = 0; i < tables.size(); i++) {
                if (dbPart->isPartitionedTable(tables[i])) {
                    partitioned = true;
                    break;
                }
            }
            if (!setDefaultLimit()) {
                printTokens("error in modifying LIMIT: ");
                return RET_ERROR_UNPARSABLE;
            }
            /*
               if (!partitioned)
               return ((*txLevel) > 0 ? RET_USE_DEFAULT_DATABASE : RET_USE_ANY_PARTITION);
             */
            int whereStart, whereEnd;
            if (!getSqlWhere(fromEnd, &whereStart, &whereEnd)) {
                // add LIMIT, change the offset to 0 if needed
                uint64_t aa = 0;
                dbPart->getPartitionNum(tables[0], &aa);

                for (size_t i = 0; i < aa; i++) {
                    std::string db;
                    getDbMapping(tables[0], "", i, db, usemaster, 0);
                    if (!db.empty())
                        dbs.insert(db);
                }
                return RET_USE_ALL_PARTITIONS;
            }

            for (size_t i = 0; i < tables.size(); i++) {
                std::string partitionKey;
                getPartitionKey(tables[i], partitionKey);
                if (partitionKey.empty()) {
                    std::string db;
                    getDbMapping(tables[i], "", 0, db, usemaster, 0);
                    if (!db.empty())
                        dbs.insert(db);
                    continue;
                }


                std::vector<uint64_t> keyValues;
                if (!findPartitionKeyValue(whereStart, whereEnd, tables[i],
                        aliases[i], partitionKey, keyValues)) {
                    printTokens("unrecognized key ranges: ");
                    return RET_ERROR_UNPARSABLE;
                }
                if (keyValues.size() == 0) {
                    uint64_t aa = 0;
                    dbPart->getPartitionNum(tables[0], &aa);

                    for (size_t i = 0; i < aa; i++) {
                        std::string db;
                        getDbMapping(tables[0], "", i, db, usemaster, 0);
                        if (!db.empty())
                            dbs.insert(db);
                    }
                    return RET_USE_ALL_PARTITIONS;
                }

                // find the db partition for all the IDs
                for (size_t k = 0; k < keyValues.size(); k++) {
                    std::string db;
                    getDbMapping(tables[i], partitionKey, keyValues[k], db, usemaster, 0);
                    if (!db.empty())
                        dbs.insert(db);
                }
            }



            if (dbs.empty())
                return RET_USE_ALL_PARTITIONS;

            return RET_DB_LOOKUP_SUCCESS;
        }
        case TK_SQL_UPDATE:
        {
            int setPos;
            if (!findToken(0, getTokensLen(), TK_SQL_SET, &setPos)) {
                printTokens("could not find SET in UPDATE: ");
                return RET_ERROR_UNPARSABLE;
            };

            if (getTokenId(setPos - 1) != TK_LITERAL) {
                printTokens("expecting table name before SET: ");
                return RET_ERROR_UNPARSABLE;
            }

            std::string table = getTokenStr(setPos - 1);

            // for nonpartitioned tables, update the default master db
            if (!(dbPart->isPartitionedTable(table))) {
                std::string db;
                getDbMapping(table, "", 0, db, 1, 0);
                if (!db.empty())
                    dbs.insert(db);
                return RET_USE_ALL_PARTITIONS;
            }

            int whereStart, whereEnd;
            if (!getSqlWhere(setPos + 1, &whereStart, &whereEnd)) {
                printTokens("no WHERE found: ");
                return RET_ERROR_UNPARSABLE;
            }

            std::string partitionKey;
            getPartitionKey(table, partitionKey);

            g_assert(!partitionKey.empty());

            std::vector<uint64_t> keyValues;
            if (!findPartitionKeyValue(whereStart, whereEnd, table, "",
                    partitionKey, keyValues)) {
                printTokens("unrecognized ranges: ");
                return RET_ERROR_UNPARSABLE;
            }

            // find the db partition for all the IDs
            for (size_t k = 0; k < keyValues.size(); k++) {
                std::string db;
                getDbMapping(table, partitionKey, keyValues[k], db, 1, 0);
                if (!db.empty())
                    dbs.insert(db);
            }

            if (dbs.empty())
                return RET_USE_ALL_PARTITIONS;

            return RET_DB_LOOKUP_SUCCESS;
        }
        case TK_SQL_INSERT:
        { // support format: INSERT  ... <table> (...) VALUES (....)

            int pos;
            uint64_t insertid = 0;
            if (!findToken(1, getTokensLen(), TK_LITERAL, &pos)) {
                printTokens("could not find table name: ");
                return RET_ERROR_UNPARSABLE;
            }

            std::string table = getTokenStr(pos);

            std::string partitionKey;
            getPartitionKey(table, partitionKey);

            if (getTokenId(++pos) != TK_OBRACE) {
                printTokens("unrecognized INSERT: ");
                return RET_ERROR_UNPARSABLE;
            }

            pos++;

            std::string autoIncrementColumn;
            dbPart->getAutoIncrementColumn(table, autoIncrementColumn);

            int keyPos = -1;
            int autoColPos = -1;
            for (int i = pos; i < getTokensLen(); i++) {
                if ((getTokenId(i) == TK_CBRACE) ||
                        (autoColPos >= 0 && keyPos >= 0))
                    break;
                if (getTokenId(i) == TK_LITERAL &&
                        tokComp(i, partitionKey) == 0) {
                    keyPos = i - pos;
                    continue;
                }
                if (getTokenId(i) == TK_LITERAL &&
                        tokComp(i, autoIncrementColumn) == 0) {
                    autoColPos = i - pos;
                }
            }

            if ((!partitionKey.empty()) && keyPos == -1 && partitionKey != autoIncrementColumn) {
                log_warning("could not find the partition key %s:", partitionKey.c_str());
                printTokens();
                return RET_ERROR_UNPARSABLE;
            }

            if ((!partitionKey.empty()) && keyPos == -1) {
                // special handling for the case in which partition key type is auto increment.
                // need to get the id first and then modify the INSERT
                uint64_t id;
                if (!dbPart->getNextUniqueId(table, &id)) {
                    log_warning("could not get next unique id for %s", partitionKey.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
                insertid = id;
                std::string db;
                getDbMapping(table, partitionKey, id, db, 1, id);
                if (!db.empty())
                    dbs.insert(db);
                else {
                    printTokens("could not find db for id %d: ");
                    return RET_DB_LOOKUP_ERROR;
                }

                if (modifySqlForInsert(partitionKey, id)) {
                    if (partitionKey == autoIncrementColumn || autoIncrementColumn.empty())
                        return RET_DB_LOOKUP_SUCCESS;
                } else {
                    log_warning("could not insert id for %s ", partitionKey.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
            }

            if (!autoIncrementColumn.empty() && autoColPos < 0 && (partitionKey != autoIncrementColumn)) {
                // need to get unique ids for auto increment columns
                uint64_t id;
                if (!dbPart->getNextUniqueId(table, &id)) {
                    log_warning("could not get next unique id for %s", autoIncrementColumn.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
                insertid = id;
                if (modifySqlForInsert(autoIncrementColumn, id)) {
                    // for nonparitioned table INSERT, use the default master db
                    if (partitionKey.empty())
                        return RET_USE_DEFAULT_DATABASE;

                    if (keyPos == -1)
                        return RET_DB_LOOKUP_SUCCESS;
                } else {
                    log_warning("could not insert id for %s ", autoIncrementColumn.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
            }

            // for nonparitioned table INSERT, use the default master db
            if (partitionKey.empty()) {
                std::string db;
                getDbMapping(table, "", 0, db, 1, insertid);
                if (!db.empty())
                    dbs.insert(db);
                return RET_USE_ALL_PARTITIONS;
            }

            pos += keyPos;

            int valPos;

            if (!findToken(pos, getTokensLen(), TK_SQL_VALUES, &valPos)) {
                printTokens("VALUES is not found: ");
                return RET_ERROR_UNPARSABLE;
            }

            if (getTokenId(valPos + 1) != TK_OBRACE) {
                printTokens("expecting '(' after VALUES: ");
                return RET_ERROR_UNPARSABLE;
            }

            pos = valPos + 2 + keyPos;
            if (pos < getTokensLen()) {//dqm
                //if (pos < getTokensLen() && getTokenId(pos) == TK_INTEGER) {
                uint64_t id = tokenToUint64(pos);
                std::string db;
                getDbMapping(table, partitionKey, id, db, 1, insertid);
                if (!db.empty())
                    dbs.insert(db);

                if (dbs.empty()) {
                    printTokens("could not find db mapping: ");
                    return RET_ERROR_UNPARSABLE;
                }

                return RET_DB_LOOKUP_SUCCESS;
            } else {
                log_warning("could not recognize value for %s:", partitionKey.c_str());
                printTokens();
                return RET_ERROR_UNPARSABLE;
            }

            break;
        }
        
        case TK_SQL_REPLACE:
        { // support format: replace  ... <table> (...) VALUES (....)

            int pos;
            uint64_t insertid = 0;
            if (!findToken(1, getTokensLen(), TK_LITERAL, &pos)) {
                printTokens("could not find table name: ");
                return RET_ERROR_UNPARSABLE;
            }

            std::string table = getTokenStr(pos);

            std::string partitionKey;
            getPartitionKey(table, partitionKey);

            if (getTokenId(++pos) != TK_OBRACE) {
                printTokens("unrecognized INSERT: ");
                return RET_ERROR_UNPARSABLE;
            }

            pos++;

            std::string autoIncrementColumn;
            dbPart->getAutoIncrementColumn(table, autoIncrementColumn);

            int keyPos = -1;
            int autoColPos = -1;
            for (int i = pos; i < getTokensLen(); i++) {
                if ((getTokenId(i) == TK_CBRACE) ||
                        (autoColPos >= 0 && keyPos >= 0))
                    break;
                if (getTokenId(i) == TK_LITERAL &&
                        tokComp(i, partitionKey) == 0) {
                    keyPos = i - pos;
                    continue;
                }
                if (getTokenId(i) == TK_LITERAL &&
                        tokComp(i, autoIncrementColumn) == 0) {
                    autoColPos = i - pos;
                }
            }

            if ((!partitionKey.empty()) && keyPos == -1 && partitionKey != autoIncrementColumn) {
                log_warning("could not find the partition key %s:", partitionKey.c_str());
                printTokens();
                return RET_ERROR_UNPARSABLE;
            }

            if ((!partitionKey.empty()) && keyPos == -1) {
                // special handling for the case in which partition key type is auto increment.
                // need to get the id first and then modify the INSERT
                uint64_t id;
                if (!dbPart->getNextUniqueId(table, &id)) {
                    log_warning("could not get next unique id for %s", partitionKey.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
                insertid = id;
                std::string db;
                getDbMapping(table, partitionKey, id, db, 1, id);
                if (!db.empty())
                    dbs.insert(db);
                else {
                    printTokens("could not find db for id %d: ");
                    return RET_DB_LOOKUP_ERROR;
                }

                if (modifySqlForInsert(partitionKey, id)) {
                    if (partitionKey == autoIncrementColumn || autoIncrementColumn.empty())
                        return RET_DB_LOOKUP_SUCCESS;
                } else {
                    log_warning("could not insert id for %s ", partitionKey.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
            }

            if (!autoIncrementColumn.empty() && autoColPos < 0 && (partitionKey != autoIncrementColumn)) {
                // need to get unique ids for auto increment columns
                uint64_t id;
                if (!dbPart->getNextUniqueId(table, &id)) {
                    log_warning("could not get next unique id for %s", autoIncrementColumn.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
                insertid = id;
                if (modifySqlForInsert(autoIncrementColumn, id)) {
                    // for nonparitioned table INSERT, use the default master db
                    if (partitionKey.empty())
                        return RET_USE_DEFAULT_DATABASE;

                    if (keyPos == -1)
                        return RET_DB_LOOKUP_SUCCESS;
                } else {
                    log_warning("could not insert id for %s ", autoIncrementColumn.c_str());
                    printTokens();
                    return RET_DB_LOOKUP_ERROR;
                }
            }

            // for nonparitioned table INSERT, use the default master db
            if (partitionKey.empty()) {
                std::string db;
                getDbMapping(table, "", 0, db, 1, insertid);
                if (!db.empty())
                    dbs.insert(db);
                return RET_USE_ALL_PARTITIONS;
            }

            pos += keyPos;

            int valPos;

            if (!findToken(pos, getTokensLen(), TK_SQL_VALUES, &valPos)) {
                printTokens("VALUES is not found: ");
                return RET_ERROR_UNPARSABLE;
            }

            if (getTokenId(valPos + 1) != TK_OBRACE) {
                printTokens("expecting '(' after VALUES: ");
                return RET_ERROR_UNPARSABLE;
            }

            pos = valPos + 2 + keyPos;
            if (pos < getTokensLen()) {//dqm
                //if (pos < getTokensLen() && getTokenId(pos) == TK_INTEGER) {
                uint64_t id = tokenToUint64(pos);
                std::string db;
                getDbMapping(table, partitionKey, id, db, 1, insertid);
                if (!db.empty())
                    dbs.insert(db);

                if (dbs.empty()) {
                    printTokens("could not find db mapping: ");
                    return RET_ERROR_UNPARSABLE;
                }

                return RET_DB_LOOKUP_SUCCESS;
            } else {
                log_warning("could not recognize value for %s:", partitionKey.c_str());
                printTokens();
                return RET_ERROR_UNPARSABLE;
            }

            break;
        }

        case TK_SQL_ALTER:
        {
            std::string tableName;
            if (getTokensLen() >= 3 && getTokenId(1) == TK_SQL_TABLE) {
                tableName = getTokenStr(2);
            } else if (getTokensLen() >= 4 && getTokenId(1) == TK_SQL_IGNORE &&
                    getTokenId(2) == TK_SQL_TABLE) {
                tableName = getTokenStr(3);
            } else
                break;
            if (dbPart->isPartitionedTable(tableName))
                return RET_USE_ALL_PARTITIONS;
            else
                return RET_USE_DEFAULT_DATABASE;
        }

        case TK_SQL_CALL:
        {
            return RET_USE_ALL_PARTITIONS;
        }

        case TK_SQL_SHOW:
        {
            if (getTokensLen() == 4 && getTokenId(2) == TK_SQL_FROM &&
                    strcasecmp(getTokenStr(1).c_str(), "fields") == 0) {

                if (dbPart->isPartitionedTable(getTokenStr(3))) {
                    return RET_USE_ANY_PARTITION;
                }
                return RET_USE_DEFAULT_DATABASE;
            }

            if (getTokensLen() == 2 &&
                    strcasecmp(getTokenStr(1).c_str(), "tables") == 0) {

                //special handling for show tables;
                //
                std::string sql = "select table_name ";
                sql.append(" from kind_setting order by table_name");
                g_string_truncate(inputSql, NET_HEADER_SIZE + 1);
                g_string_append_len(inputSql, sql.data(), sql.size());

                network_mysqld_proto_set_header_len((unsigned char *) (inputSql->str),
                        inputSql->len - NET_HEADER_SIZE);

                return RET_USE_DEFAULT_DATABASE;
            } else
                return RET_USE_DEFAULT_DATABASE;

            break;
        }

        case TK_SQL_DELETE:
        {
            int fromPos;
            if (!findToken(1, getTokensLen(), TK_SQL_FROM, &fromPos)) {
                printTokens("could not find FROM in DELETE: ");
                return RET_ERROR_UNPARSABLE;
            };

            if (fromPos >= getTokensLen() - 1) {
                printTokens("could not find table name in DELETE: ");
                return RET_ERROR_UNPARSABLE;
            }

            std::string table = getTokenStr(fromPos + 1);
            // for nonpartitioned tables, update the default master db
            if (!(dbPart->isPartitionedTable(table))) {
                std::string db;
                getDbMapping(table, "", 0, db, 1, 0);
                if (!db.empty())
                    dbs.insert(db);
                return RET_USE_ALL_PARTITIONS;
            }

            int whereStart, whereEnd;
            if (!getSqlWhere(fromPos + 1, &whereStart, &whereEnd)) {
                printTokens("no WHERE found: ");
                return RET_ERROR_UNPARSABLE;
            }

            std::string partitionKey;
            getPartitionKey(table, partitionKey);

            g_assert(!partitionKey.empty());

            std::vector<uint64_t> keyValues;
            if (!findPartitionKeyValue(whereStart, whereEnd, table, "",
                    partitionKey, keyValues)) {
                printTokens("unrecognized ranges: ");
                return RET_ERROR_UNPARSABLE;
            }

            // find the db partition for all the IDs
            for (size_t k = 0; k < keyValues.size(); k++) {
                std::string db;
                getDbMapping(table, partitionKey, keyValues[k], db, 1, 0);
                if (!db.empty())
                    dbs.insert(db);
            }

            if (dbs.empty())
                return RET_USE_ALL_PARTITIONS;

            return RET_DB_LOOKUP_SUCCESS;
        }
        case TK_SQL_DESC:
        case TK_SQL_DESCRIBE:
        {
            if (getTokensLen() >= 2) {
                std::string tableName = getTokenStr(1);
                if (dbPart->isPartitionedTable(tableName))
                    return RET_USE_ANY_PARTITION;
                else
                    return RET_USE_DEFAULT_DATABASE;
            }

            return RET_ERROR_UNPARSABLE;
        }
        case TK_SQL_SET:
        {
            if ((getTokensLen() >= 4) &&
                    (getTokenId(1) == TK_SQL_AUTOCOMMIT) &&
                    (getTokenStr(3).compare("0") == 0)) {
                (*txLevel)++;
            }
            return RET_USE_ALL_DATABASES;
        }
        case TK_SQL_START:
        case TK_SQL_BEGIN:
        {
            (*txLevel)++;
            return RET_USE_ALL_DATABASES;
        }
        case TK_SQL_COMMIT:
        case TK_SQL_ROLLBACK:
        {
            (*txLevel)--;
            return RET_USE_ALL_DATABASES;
        }
        default:
        {
            break;
        }
    }

    printTokens("unrecognized query, using default master db: ");

    return RET_USE_DEFAULT_DATABASE;
}
