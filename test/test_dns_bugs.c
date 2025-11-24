#include "munit.h"
#include "dns_server.h"
#include "dns_recursive.h"
#include "dns_parser.h"
#include "dns_zone_file.h"
#include <string.h>


static MunitResult test_server_config_memory_leak(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_server_config_t *config = dns_server_config_create();
  munit_assert_not_null(config);

  config->enable_recursion = false;

  // this should not leak memory even if trie creation fails
  dns_server_t *server = dns_server_create_with_config(config);

  // server creation might fail, but should not leak
  if (server) {
    dns_server_free(server);
  }

  dns_server_config_free(config);
  return MUNIT_OK;
}

static MunitResult test_upstream_server_name_format(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_upstream_list_t servers = {0};

  int result = dns_recursive_add_upstream_server(&servers, "8.8.8.8", 53);
  munit_assert_int(result, ==, 0);

  // name should not contain trailing newline
  const char *name = servers.servers[0].name;
  size_t len = strlen(name);
  munit_assert_char(name[len - 1], !=, '\n');
  munit_assert_string_equal(name, "8.8.8.8:53");

  return MUNIT_OK;
}

static MunitResult test_zone_parser_buffer_overflow(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // create zone file with very long token
  char long_name[MAX_ZONE_TOKEN_LENGTH + 100];
  memset(long_name, 'a', sizeof(long_name) - 1);
  long_name[sizeof(long_name) - 1] = '\0';

  char zone_content[MAX_ZONE_LINE_LENGTH * 2];
  snprintf(zone_content, sizeof(zone_content), "%s.example.com. 300 IN A 192.168.1.1\n", long_name);

  // this should not crash or overflow
  FILE *temp = tmpfile();
  fprintf(temp, "%s", zone_content);
  rewind(temp);

  zone_parser_t parser = {
    .file = temp,
    .line_number = 0,
    .position = 0,
    .at_eof = false,
    .curr_ttl = 3600
  };
  dns_safe_strncpy(parser.curr_origin, "example.com", sizeof(parser.curr_origin));

  dns_rr_t *rr = NULL;
  char owner_name[MAX_DOMAIN_NAME + 1];

  // should handle gracefully without overflow
  int result = zone_parse_record(&parser, &rr, owner_name);
  munit_assert_int(result, ==, -1);

  // might fail, but should not crash
  if (rr) dns_rr_free(rr);
  fclose(temp);

  return MUNIT_OK;
}

static MunitResult test_strncpy_null_termination(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  char dest[10];
  const char *src = "verylongstring";

  // legacy/buggy way
  strncpy(dest, src, sizeof(dest) - 1); // dest might not be null-terminated

  // safe way
  dns_safe_strncpy(dest, src, sizeof(dest));
  munit_assert_char(dest[sizeof(dest) - 1], ==, '\0');

  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/memory_leak", test_server_config_memory_leak, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/format_string", test_upstream_server_name_format, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/buffer_overflow", test_zone_parser_buffer_overflow, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/null_termination", test_strncpy_null_termination, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/bugs", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
