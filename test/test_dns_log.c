#include "munit.h"
#include "dns_log.h"

#include <string.h>
#include <unistd.h>


static MunitResult test_init(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_log_init();
  dns_logger_t *logger = dns_log_get_logger();

  munit_assert_not_null(logger);
  munit_assert_not_null(&logger->mutex);
  munit_assert_true(logger->initialized);
  munit_assert_int(logger->level, ==, DNS_LOG_INFO);

  dns_log_shutdown();
  return MUNIT_OK;
}

static MunitResult test_level_from_string(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  munit_assert_int(dns_log_level_from_string("trace"), ==, DNS_LOG_TRACE);
  munit_assert_int(dns_log_level_from_string("TRACE"), ==, DNS_LOG_TRACE);
  munit_assert_int(dns_log_level_from_string("debug"), ==, DNS_LOG_DEBUG);
  munit_assert_int(dns_log_level_from_string("info"), ==, DNS_LOG_INFO);
  munit_assert_int(dns_log_level_from_string("warn"), ==, DNS_LOG_WARN);
  munit_assert_int(dns_log_level_from_string("warning"), ==, DNS_LOG_WARN);
  munit_assert_int(dns_log_level_from_string("error"), ==, DNS_LOG_ERROR);
  munit_assert_int(dns_log_level_from_string("fatal"), ==, DNS_LOG_FATAL);
  munit_assert_int(dns_log_level_from_string("off"), ==, DNS_LOG_OFF);

  // default to INFO
  munit_assert_int(dns_log_level_from_string("banana"), ==, DNS_LOG_INFO);
  munit_assert_int(dns_log_level_from_string(NULL), ==, DNS_LOG_INFO);

  return MUNIT_OK;
}

static MunitResult test_level_to_string(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  munit_assert_string_equal(dns_log_level_to_string(DNS_LOG_TRACE), "TRACE");
  munit_assert_string_equal(dns_log_level_to_string(DNS_LOG_DEBUG), "DEBUG");
  munit_assert_string_equal(dns_log_level_to_string(DNS_LOG_INFO), "INFO");
  munit_assert_string_equal(dns_log_level_to_string(DNS_LOG_WARN), "WARN");
  munit_assert_string_equal(dns_log_level_to_string(DNS_LOG_ERROR), "ERROR");
  munit_assert_string_equal(dns_log_level_to_string(DNS_LOG_FATAL), "FATAL");
  munit_assert_string_equal(dns_log_level_to_string(42069), "UNKNOWN");

  return MUNIT_OK;
}

static MunitResult test_is_enabled(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_log_init();
  dns_log_set_level(DNS_LOG_WARN);

  // disabled below warn
  munit_assert_false(dns_log_is_enabled(DNS_LOG_TRACE));
  munit_assert_false(dns_log_is_enabled(DNS_LOG_DEBUG));
  munit_assert_false(dns_log_is_enabled(DNS_LOG_INFO));

  // enabled above warn
  munit_assert_true(dns_log_is_enabled(DNS_LOG_WARN));
  munit_assert_true(dns_log_is_enabled(DNS_LOG_ERROR));
  munit_assert_true(dns_log_is_enabled(DNS_LOG_FATAL));

  // turn it off
  dns_log_set_level(DNS_LOG_OFF);
  munit_assert_false(dns_log_is_enabled(DNS_LOG_FATAL));

  dns_log_shutdown();
  return MUNIT_OK;
}

static MunitResult test_output_to_file(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_log_init();

  char fname[] = "/tmp/dns_log_test_XXXXXX";
  int fd = mkstemp(fname);
  munit_assert_int(fd, >=, 0);

  FILE *file = fdopen(fd, "w+");
  munit_assert_not_null(file);

  dns_log_set_output(file);
  dns_log_set_level(DNS_LOG_INFO);
  dns_log_set_timestamp(false);
  dns_log_set_color(false);
  dns_log_set_file_line(false);

  DNS_LOG_INFO("foo bar %d", 42);
  fflush(file);
  rewind(file);

  char buf[256];
  char *result = fgets(buf, sizeof(buf), file);
  munit_assert_not_null(result);
  munit_assert_string_equal(buf, "INFO  foo bar 42\n");

  fclose(file);
  unlink(fname);

  dns_log_set_output(stdout); // flush to stdout on shutdown (file is closed)
  dns_log_shutdown();
  return MUNIT_OK;
}

static MunitResult test_hexdump(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_log_init();

  char temp_filename[] = "/tmp/dns_hexdump_test_XXXXXX";
  int fd = mkstemp(temp_filename);
  FILE *log_file = fdopen(fd, "w+");

  dns_log_set_output(log_file);
  dns_log_set_level(DNS_LOG_DEBUG);
  dns_log_set_timestamp(false);
  dns_log_set_file_line(false);
  dns_log_set_color(false);

  uint8_t test_data[] = {0x00, 0x01, 0x02, 0x03, 0x41, 0x42, 0x43, 0x44};
  dns_log_hexdump(DNS_LOG_DEBUG, "TEST", test_data, sizeof(test_data));

  fflush(log_file);
  rewind(log_file);

  char buffer[256];
  char *result = fgets(buffer, sizeof(buffer), log_file);
  munit_assert_not_null(result);
  munit_assert_ptr_not_null(strstr(buffer, "00 01 02 03"));

  fclose(log_file);
  unlink(temp_filename);

  dns_log_set_output(stdout); // flush to stdout on shutdown (file is closed)
  dns_log_shutdown();
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/init", test_init, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/level_from_string", test_level_from_string, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/level_to_string", test_level_to_string, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/is_enabled", test_is_enabled, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/output_to_file", test_output_to_file, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/hexdump", test_hexdump, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/log", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
