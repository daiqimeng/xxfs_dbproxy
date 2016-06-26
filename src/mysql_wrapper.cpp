
#include "mysql_wrapper.h"
#include "messages.h"


bool MySql::connect()
{
    connected = mysql_real_connect(&mysql, db.host.c_str(), db.user.c_str(),
            db.password.c_str(), db.db.c_str(), 0, NULL, 0)  != NULL;

    if (!connected) {
        log_error("%s.%d: Error in connecting to %s:%s: %s.\n",
                  __FILE__, __LINE__, db.host.c_str(),
                  db.db.c_str(), mysql_error(&mysql));
    }
    return connected;
}

bool MySql::query(const char *sql, std::vector<std::string> *resVec)
{
    if (resVec)
        resVec->clear();

    MYSQL_RES *res = NULL;

    {
        struct AutoLock {
            AutoLock(Mutex *mx) : mutex(mx) { pthread_mutex_lock(mutex); }
            ~AutoLock() { pthread_mutex_unlock(mutex); }
            Mutex *mutex;
        } lock(&mutex);

        for (int nTries = 1; nTries >= 0; nTries --) {
            if (mysql_query(&mysql, sql) == 0)
                break;
            unsigned int err = mysql_errno(&mysql);

            if ((err == CR_SERVER_GONE_ERROR || err == CR_SERVER_LOST) &&
                (nTries > 0)) {
                // reconnectting ...
                //
                disconnect();
                connect();
            } else {
                log_error("%s.%d: Error for sql query \"%s\": err=%d, %s\n",
                          __FILE__, __LINE__, sql, err, mysql_error(&mysql));
                return false;
            }
        }

        if (resVec) {
            res = mysql_store_result(&mysql);
            unsigned int err = mysql_errno(&mysql);

            if (err) {
                log_error("%s.%d: Error for sql query \"%s\": err=%d, %s\n",
                          __FILE__, __LINE__, sql, err, mysql_error(&mysql));
                return false;
            }

        } else
            return true;
    }


    if (res == NULL)
        return true;

    MYSQL_ROW row;
    while((row = mysql_fetch_row(res))) {
        unsigned long *lengths = mysql_fetch_lengths(res);
        for (size_t i = 0 ; i < mysql_num_fields(res); i++) {
            if (lengths[i] > 0)
                resVec->push_back(std::string(row[i], lengths[i]));
             else
                resVec->push_back(std::string("", lengths[i]));
        }
    }

    mysql_free_result(res);
    return true;
}


void mysql_scramble(char *to, const char *message, const char *password)
{
	scramble(to, message, password);
}

void mysql_make_scramble(char *to, const char *password)
{
    char buf[256];

	make_scrambled_password(buf, password);

	get_salt_from_password((uint8_t*)to, buf);
}

my_bool mysql_is_valid(const char *client, const char *scramble, const uint8_t *hash_stage2)
{
	return check_scramble((const unsigned char*)client, scramble, hash_stage2);
}

void mysql_create_random_string(char *to, uint16_t length)
{
	struct rand_struct rand_st;
	randominit(&rand_st, time(NULL), time(NULL)*(long)to);
	create_random_string(to, length, &rand_st);
}

