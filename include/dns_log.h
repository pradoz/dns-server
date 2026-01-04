#ifndef DNS_LOG_H
#define DNS_LOG_H


#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>


typedef enum {
  DNS_LOG_TRACE = 0,
  DNS_LOG_DEBUG,
  DNS_LOG_INFO,
  DNS_LOG_WARN,
  DNS_LOG_ERROR,
  DNS_LOG_FATAL,
  DNS_LOG_OFF,
} dns_log_level_t;

typedef struct {
  dns_log_level_t level;
  FILE *output;
  FILE *error_output;

  bool include_timestamp;
  bool include_file_line;
  bool include_level;
  bool color_enabled;

  pthread_mutex_t mutex;
  bool initialized;
} dns_logger_t;


dns_logger_t *dns_log_get_logger(void);
void dns_log_init(void);
void dns_log_shutdown(void);

void dns_log_set_level(dns_log_level_t level);
dns_log_level_t  dns_log_get_level(void);

void dns_log_set_output(FILE *output);
void dns_log_set_error_output(FILE *output);

void dns_log_set_timestamp(bool enabled);
void dns_log_set_file_line(bool enabled);
void dns_log_set_color(bool enabled);

dns_log_level_t dns_log_level_from_string(const char *str);
const char *dns_log_level_to_string(dns_log_level_t level);
void dns_log_write(dns_log_level_t level, const char *file, int line,
                   const char *func, const char *fmt, ...);
void dns_log_writev(dns_log_level_t level, const char *file, int line,
                    const char *func, const char *fmt, va_list args);

bool dns_log_is_enabled(dns_log_level_t level);


#define DNS_LOG_TRACE(...) \
  dns_log_write(DNS_LOG_TRACE, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define DNS_LOG_DEBUG(...) \
  dns_log_write(DNS_LOG_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define DNS_LOG_INFO(...) \
  dns_log_write(DNS_LOG_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define DNS_LOG_WARN(...) \
  dns_log_write(DNS_LOG_WARN, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define DNS_LOG_ERROR(...) \
  dns_log_write(DNS_LOG_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define DNS_LOG_FATAL(...) \
  dns_log_write(DNS_LOG_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__)


// conditional logging to avoid argument evaluation if level disabled
#define DNS_LOG_TRACE_IF(cond, ...) \
  do { if ((cond) && dns_log_is_enabled(DNS_LOG_TRACE)) DNS_LOG_TRACE(__VA_ARGS__); } while(0)

#define DNS_LOG_DEBUG_IF(cond, ...) \
  do { if ((cond) && dns_log_is_enabled(DNS_LOG_DEBUG)) DNS_LOG_DEBUG(__VA_ARGS__); } while(0)

// log with dns_error_t
#define DNS_LOG_ERROR_ERR(err, msg) \
  do { \
    if (err && (err)->code != DNS_ERR_NONE) { \
      DNS_LOG_ERROR("%s: %s (code=%d, %s:%d)", msg, (err)->message, \
                    (err)->code, (err)->file ? (err)->file : "unknown", (err)->line); \
    } \
  } while(0)

// hexdump to debugg packets
void dns_log_hexdump(dns_log_level_t level, const char *prefix,
                     const void *data, size_t len);

#define DNS_LOG_HEXDUMP(level, prefix, data, len) \
  do { if (dns_log_is_enabled(level)) dns_log_hexdump(level, prefix, data, len); } while(0)


#endif // !DNS_LOG_H
