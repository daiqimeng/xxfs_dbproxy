

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <assert.h>
#include <string>
#include <string.h>
#include <stdlib.h>

#include "messages.h"

#define MAX_MSG_LEN 1024

static bool logDebugMsgs = true;
static std::string logFileName;

bool set_debug_msg_logging(bool enable)
{
    bool oldValue = logDebugMsgs;
    logDebugMsgs = true;
    return oldValue;
}

void set_log_file(const char *fname)
{
    if (fname)
        logFileName = fname;
    else
        logFileName.erase();
}

enum {
    LOG_LEVEL_FATAL,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
};

static void log_msg(int logLevel, const char *msg)
{
    static FILE *log_fp = NULL;

    if (!logFileName.empty() && (log_fp == NULL)) {
        log_fp = fopen(logFileName.c_str(), "a");
        if (log_fp == NULL) {
            fprintf(stderr, "Failed to open file %s for write.\n",
                    logFileName.c_str());
            exit(1);
        }
    }

    const char *type;
    switch (logLevel) {
        case LOG_LEVEL_FATAL:
            type = "FATAL"; break;
        case LOG_LEVEL_ERROR:
            type = "ERROR"; break;
        case LOG_LEVEL_WARNING:
            type = "WARNING"; break;
        case LOG_LEVEL_INFO:
            type = "INFO"; break;
        case LOG_LEVEL_DEBUG:
            type = "DEBUG"; break;
        default:
            type = "ERROR"; break;
    }

    time_t now = time(NULL);
    char str[MAX_MSG_LEN];
    strcpy(str, ctime(&now));
    size_t len = strlen(str) - 1; // get rid of trailing newline

    len += snprintf(str + len, sizeof(str) - len, " %s %s", type, msg); 

    // make sure we have newline
    if (str[len - 1] != '\n') {
        if (len + 1 < sizeof(str)) {
            str[len++] = '\n';
            str[len] = '\0';
        } else
            str[len - 1] = '\n';
    }

    if (log_fp == NULL)
        syslog(0, "%s", str);
    else {
        fprintf(log_fp, "%s", str);
        fflush(log_fp);
    }
}

void log_debug(const char *format, ...)
{
    if (!logDebugMsgs)
        return;

    va_list args;
    va_start (args, format);
    char buf[MAX_MSG_LEN];
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    log_msg(LOG_LEVEL_DEBUG, buf);

}

void log_warning(const char *format, ...)
{
    va_list args;
    va_start (args, format);
    char buf[MAX_MSG_LEN];
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    log_msg(LOG_LEVEL_WARNING, buf);

}

void log_error(const char *format, ...)
{
    va_list args;
    va_start (args, format);
    char buf[MAX_MSG_LEN];
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    log_msg(LOG_LEVEL_ERROR, buf);

}

void log_fatal(const char *format, ...)
{
    va_list args;
    va_start (args, format);
    char buf[MAX_MSG_LEN];
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    //log_msg(LOG_LEVEL_FATAL, buf);
   // log_msg(LOG_INFO, buf);

   assert(0);
}

void log_info(const char *format, ...)
{
    va_list args;
    va_start (args, format);
    char buf[MAX_MSG_LEN];
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    log_msg(LOG_LEVEL_INFO, buf);
}

