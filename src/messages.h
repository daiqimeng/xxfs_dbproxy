

#ifndef  __MESSAGES_H__
#define  __MESSAGES_H___

bool set_debug_msg_logging(bool enable);
void set_log_file(const char *fname);

void log_debug(const char *format, ...);
void log_warning(const char *format, ...);
void log_error(const char *format, ...);
void log_fatal(const char *format, ...);
void log_info(const char *format, ...);

#endif

