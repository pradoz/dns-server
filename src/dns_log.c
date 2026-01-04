#include "dns_log.h"
#include <ctype.h>
#include <pthread.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>


static dns_logger_t g_logger = {
  .level = DNS_LOG_INFO,
  .output = NULL,
  .error_output = NULL,
  .include_timestamp = true,
  .include_file_line = true,
  .include_level = true,
  .color_enabled = false,
};

static const char *color_reset = "\x1b[0m";
static const char *level_colors[] = {
  [DNS_LOG_TRACE] = "\x1b[90m",  // dark gray
  [DNS_LOG_DEBUG] = "\x1b[36m",  // cyan
  [DNS_LOG_INFO]  = "\x1b[32m",  // green
  [DNS_LOG_WARN]  = "\x1b[33m",  // yellow
  [DNS_LOG_ERROR] = "\x1b[31m",  // red
  [DNS_LOG_FATAL] = "\x1b[35m",  // magenta
};

static const char *level_names[] = {
  [DNS_LOG_TRACE] = "TRACE",
  [DNS_LOG_DEBUG] = "DEBUG",
  [DNS_LOG_INFO] = "INFO",
  [DNS_LOG_WARN] = "WARN",
  [DNS_LOG_ERROR] = "ERROR",
  [DNS_LOG_FATAL] = "FATAL",
};


dns_logger_t *dns_log_get_logger(void) {
  return &g_logger;
}

void dns_log_init(void) {
  if (g_logger.initialized) return;

  pthread_mutex_init(&g_logger.mutex, NULL);
  g_logger.level = DNS_LOG_INFO;
  g_logger.output = stdout;
  g_logger.error_output = stderr;

  g_logger.include_timestamp = true;
  g_logger.include_file_line = true;
  g_logger.include_level = true;

  // auto-detect color support
  g_logger.color_enabled = isatty(fileno(stdout)) && isatty(fileno(stderr));
  g_logger.initialized = true;
}

void dns_log_shutdown(void) {
  if (!g_logger.initialized) return;

  pthread_mutex_lock(&g_logger.mutex);

  // flush
  if (g_logger.output) fflush(g_logger.output);
  if (g_logger.error_output) fflush(g_logger.error_output);


  pthread_mutex_unlock(&g_logger.mutex);
  pthread_mutex_destroy(&g_logger.mutex);
}

void dns_log_set_level(dns_log_level_t level) {
  if (level <= DNS_LOG_OFF) g_logger.level = level;
}

dns_log_level_t dns_log_get_level(void) {
  return g_logger.level;
}

void dns_log_set_output(FILE *output) {
  g_logger.output = output ? output : stdout;
}

void dns_log_set_error_output(FILE *output) {
  g_logger.error_output = output ? output : stderr;
}

void dns_log_set_timestamp(bool enabled) {
  g_logger.include_timestamp = enabled;
}

void dns_log_set_file_line(bool enabled) {
  g_logger.include_file_line = enabled;
}

void dns_log_set_color(bool enabled) {
  g_logger.color_enabled = enabled;
}

dns_log_level_t dns_log_level_from_string(const char *str) {
  if (!str) return DNS_LOG_INFO;

  if (strcasecmp(str, "trace") == 0) return DNS_LOG_TRACE;
  if (strcasecmp(str, "debug") == 0) return DNS_LOG_DEBUG;
  if (strcasecmp(str, "info") == 0) return DNS_LOG_INFO;
  if (strcasecmp(str, "warn") == 0 || strcasecmp(str, "warning") == 0) return DNS_LOG_WARN;
  if (strcasecmp(str, "error") == 0) return DNS_LOG_ERROR;
  if (strcasecmp(str, "fatal") == 0) return DNS_LOG_FATAL;
  if (strcasecmp(str, "off") == 0 || strcasecmp(str, "none") == 0) return DNS_LOG_OFF;

  return DNS_LOG_INFO;
}

const char *dns_log_level_to_string(dns_log_level_t level) {
  if (level >= DNS_LOG_TRACE && level <= DNS_LOG_FATAL) {
    return level_names[level];
  }
  return "UNKNOWN";
}

void dns_log_write(dns_log_level_t level, const char *file, int line,
                   const char *func, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  dns_log_writev(level, file, line, func, fmt, args);
  va_end(args);
}

void dns_log_writev(dns_log_level_t level, const char *file, int line,
                    const char *func, const char *fmt, va_list args) {
  if (!dns_log_is_enabled(level)) return;

  // lazily initialize
  if (!g_logger.initialized) dns_log_init();

  FILE *out = (level >= DNS_LOG_ERROR) ? g_logger.error_output : g_logger.output;
  if (!out) return;

  pthread_mutex_lock(&g_logger.mutex);

  if (g_logger.include_timestamp) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(out, "%s ", time_buf);
  }

  if (g_logger.include_level) {
    if (g_logger.color_enabled && level < DNS_LOG_OFF) {
      fprintf(out, "%s%-5s%s ", level_colors[level], level_names[level], color_reset);
    } else {
      fprintf(out, "%-5s ", level_names[level]);
    }
  }

  if (g_logger.include_file_line && file) {
    const char *fname = strrchr(file, '/');
    fname = fname ? fname + 1 : file;
    fprintf(out, "[%s:%d] ", fname, line);
  }

  if (func && level <= DNS_LOG_DEBUG) fprintf(out, "%s(): ", func);

  vfprintf(out, fmt, args);
  fprintf(out, "\n");

  // flush on error/fatal
  if (level >= DNS_LOG_ERROR) fflush(out);

  pthread_mutex_unlock(&g_logger.mutex);
}

void dns_log_hexdump(dns_log_level_t level, const char *prefix,
                     const void *data, size_t len) {
  if (!dns_log_is_enabled(level) || !data || len == 0) return;

  const unsigned char *bytes = (const unsigned char*) data;

  const unsigned int line_bufsz = 80;
  const unsigned int ascii_bufsz = 16;
  char line[line_bufsz];
  char ascii[ascii_bufsz + 1];

  for (size_t i = 0; i < len; i += 16) {
    int pos = snprintf(line + pos, sizeof(line) - pos, "%s %04zx: ", prefix ? prefix : "", i);;

    for (size_t j = 0; j < 16; ++j) {
      if (i + j < len) {
        pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", bytes[i + j]);
        ascii[j] = isprint(bytes[i + j]) ? bytes[i + j] : '.';
      } else {
        pos += snprintf(line + pos, sizeof(line) - pos, "   ");
        ascii[j] = ' ';
      }
    }
    ascii[ascii_bufsz] = '\0';

    snprintf(line + pos, sizeof(line) - pos, " |%s|", ascii);
    dns_log_write(level, NULL, 0, NULL, "%s", line);
  }
}

bool dns_log_is_enabled(dns_log_level_t level) {
  return level >= g_logger.level && level < DNS_LOG_OFF;
}
