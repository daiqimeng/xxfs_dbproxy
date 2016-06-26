
#ifndef __MYSQL_WRAPPER_H__

#define  __MYSQL_WRAPPER_H__

#include <mysql.h>
#include <errmsg.h>
#include <mysql_com.h>
#include <stdint.h>

void mysql_scramble(char *to, const char *message, const char *password);
void mysql_make_scramble(char *to, const char *password);
my_bool mysql_is_valid(const char *client, const char *scramble, const uint8_t *hash_stage2);
void mysql_create_random_string(char *to, uint16_t length);



#include <pthread.h>
#include <string>
#include <vector>

/**
 * stores the info needed to connect to a database
 */
struct DbInfo {
    DbInfo(uint64_t id,const std::string &hostName, int pt,  const std::string &dbName,
           const std::string &usr, const std::string &pw,uint64_t masterid) :
        id(id),host(hostName), port(pt), db(dbName), user(usr), password(pw),masterid(masterid)
    {}
    DbInfo()
    {}
    uint64_t id;
    std::string host;
    int port;
    std::string db;
    std::string user;
    std::string password;
    uint64_t masterid;
};

/**
 * thread safe mysql wrapper class for most often used APIs.
 */
class MySql {
    public:
        MySql(const DbInfo &dbInfo) : db(dbInfo) { init(); }
        ~MySql()
        {
            if (connected)
                disconnect();
        }

        /**
         * connect to a database
         * @return true on success, print errors on failure
         */
        bool connect();

        /** execute a sql query, retries some times on failure
         *  @return true on success, the vector contains the query results if there is any
         */
        bool query(const char *sql, std::vector<std::string> *resVec);

        void disconnect() { mysql_close(&mysql); connected = false; }

    private:
        void init()
        {
            mysql_init(&mysql);
            pthread_mutex_init(&mutex, NULL);
            connected = false;

            conf.maxTries = 3;
            conf.tryInterval = 5;  // default 5 seconds
        }

        MYSQL mysql;

        /**
         * using a mutex, we could do thread safe mysql queries
         */
        typedef pthread_mutex_t Mutex;
        Mutex mutex;

        DbInfo db;
        bool connected;

        struct {

            /**
             * max tries on failure, default is 3
             */
            int maxTries;


            /**
             * sleep time before tring again on failure, default is 5 seconds.
             */
            int tryInterval;
        } conf;
};

#endif  // #ifndef __MYSQL_WRAPPER_H__
