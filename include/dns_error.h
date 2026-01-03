#ifndef DNS_ERROR_H
#define DNS_ERROR_H


#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>


typedef enum {
  DNS_ERR_NONE = 0,
  DNS_ERR_INVALID_PACKET,
  DNS_ERR_BUFFER_TOO_SMALL,
  DNS_ERR_MALFORMED_NAME,
  DNS_ERR_INVALID_QUESTION,
  DNS_ERR_MEMORY_ALLOCATION,
  DNS_ERR_COMPRESSION_LOOP,
  DNS_ERR_LABEL_TOO_LONG,
  DNS_ERR_NAME_TOO_LONG,
  DNS_ERR_CNAME_LOOP,
  DNS_ERR_CNAME_CHAIN_TOO_LONG,
  DNS_ERR_UNSUPPORTED_OPCODE,
  DNS_ERR_UNSUPPORTED_TYPE,
  DNS_ERR_INVALID_ARG,
  DNS_ERR_NOT_FOUND,
  DNS_ERR_WOULD_BLOCK,
  DNS_ERR_TIMEOUT,
  DNS_ERR_IO,
} dns_error_code_t;

typedef enum {
  DNS_RESULT_SUCCESS = 0,
  DNS_RESULT_ERROR = -1,
  DNS_RESULT_NOT_FOUND = -2,
  DNS_RESULT_INCOMPLETE = -3
} dns_result_t;

typedef struct {
  dns_error_code_t code;
  char message[256];
  const char *file;
  int line;
} dns_error_t;


#define DNS_ERROR_INIT { \
  .code = DNS_ERR_NONE, \
  .message = {0}, \
  .file = NULL, \
  .line = 0, \
}

static inline void dns_error_init(dns_error_t *err) {
  if (!err) return;
  err->code = DNS_ERR_NONE;
  err->message[0] = '\0';
  err->file = NULL;
  err->line = 0;
}

static inline bool dns_error_ok(const dns_error_t *err) {
  return !err || err->code == DNS_ERR_NONE;
}

static inline bool dns_error_failed(const dns_error_t *err) {
  return !dns_error_ok(err);
}


const char *dns_error_string(dns_error_code_t code);
uint8_t dns_error_to_rcode(dns_error_code_t code);

#define DNS_ERROR_SET(err, error_code, msg) \
  do { \
    if (err) { \
      (err)->code = (error_code); \
      snprintf((err)->message, sizeof((err)->message), "%s", (msg)); \
      (err)->file = __FILE__; \
      (err)->line = __LINE__; \
    } \
  } while(0)

#define DNS_ERROR_SETF(err, error_code, fmt, ...) \
  do { \
    if (err) { \
      (err)->code = (error_code); \
      snprintf((err)->message, sizeof((err)->message), fmt, __VA_ARGS__); \
      (err)->file = __FILE__; \
      (err)->line = __LINE__; \
    } \
  } while(0)

#define DNS_ERROR_CLEAR(err) \
  do { \
    if (err) { \
      (err)->code = DNS_ERR_NONE; \
      (err)->message[0] = '\0'; \
      (err)->file = NULL; \
      (err)->line = 0; \
    } \
  } while(0)

#define DNS_ERROR_PROPAGATE(dest, src) \
  do { \
    if ((src) && (src)->code != DNS_ERR_NONE && (dest)) { \
      *(dest) = *(src); \
    } \
  } while(0)


#endif // DNS_ERROR_H
