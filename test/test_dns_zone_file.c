#include "munit.h"
#include "dns_zone_file.h"
#include "dns_trie.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


static char *create_test_file(const char *content) {
  static char temp_fname[] = "/tmp/test_XXXXXX";
  int fd = mkstemp(temp_fname);
  if (fd == -1) return NULL;

  FILE *f = fdopen(fd, "w");
  if (!f) {
    close(fd);
    return NULL;
  }

  fprintf(f, "%s", content);
  fclose(f);

  return temp_fname;
}

static void cleanup_test_file(const char *fname) {
  if (fname) {
    unlink(fname);
  }
}

static MunitResult test_parser_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  const char *content =
    "; Simple test zone\n"
    "example.com.  IN  SOA  ns1.example.com. admin.example.com. 1 3600 600 86400 300\n"
    "example.com.  IN  NS   ns1.example.com.\n"
    "www           IN  A    192.168.1.1\n";

  char *fname = create_test_file(content);
  munit_assert_not_null(fname);

  zone_parser_t *parser = zone_parser_create(fname, "example.com");
  munit_assert_not_null(parser);

  zone_parser_free(parser);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_load_simple(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  const char *zone_content =
    "www.example.com.  300  IN  A    192.168.1.1\n"
    "mail.example.com. 300  IN  A    192.168.1.2\n"
    "ftp.example.com.  300  IN  A    192.168.1.3\n";

  char *fname = create_test_file(zone_content);
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  munit_assert_int(load_result, ==, 0);
  munit_assert_int(result.errors_encountered, ==, 0);
  munit_assert_int(result.records_loaded, ==, 3);
  munit_assert_int(result.record_stats.a_records, ==, 3);

  // verify records were loaded
  dns_rrset_t *www = dns_trie_lookup(trie, "www.example.com", DNS_TYPE_A);
  munit_assert_not_null(www);
  munit_assert_int(www->records->rdata.a.address, ==, inet_addr("192.168.1.1"));

  dns_rrset_t *mail = dns_trie_lookup(trie, "mail.example.com", DNS_TYPE_A);
  munit_assert_not_null(mail);

  dns_rrset_t *ftp = dns_trie_lookup(trie, "ftp.example.com", DNS_TYPE_A);
  munit_assert_not_null(ftp);

  dns_trie_free(trie);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_load_with_comments(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  const char *zone_content =
    "; This is a comment\n"
    "www.example.com.  300  IN  A    192.168.1.1  ; End of line comment\n"
    "; Another comment\n"
    "mail.example.com. 300  IN  A    192.168.1.2\n";

  char *fname = create_test_file(zone_content);
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  munit_assert_int(load_result, ==, 0);
  munit_assert_int(result.records_loaded, ==, 2);

  dns_trie_free(trie);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_string_to_type_conversion(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  munit_assert_int(zone_string_to_type("A"), ==, DNS_TYPE_A);
  munit_assert_int(zone_string_to_type("NS"), ==, DNS_TYPE_NS);
  munit_assert_int(zone_string_to_type("CNAME"), ==, DNS_TYPE_CNAME);
  munit_assert_int(zone_string_to_type("SOA"), ==, DNS_TYPE_SOA);
  munit_assert_int(zone_string_to_type("AAAA"), ==, DNS_TYPE_AAAA);
  munit_assert_int(zone_string_to_type("UNKNOWN"), ==, 0);

  return MUNIT_OK;
}

static MunitResult test_backward_compatibility(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // test that manual record insertion still works alongside zone loading
  dns_trie_t *trie = dns_trie_create();

  // add record manually (old way)
  dns_rr_t *manual_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  manual_record->rdata.a.address = inet_addr("10.0.0.1");
  munit_assert_true(dns_trie_insert_rr(trie, "manual.example.com", manual_record));

  // load zone file (new way)
  const char *zone_content = "auto.example.com. 300 IN A 10.0.0.2\n";
  char *fname = create_test_file(zone_content);
  zone_load_result_t result;
  zone_load_file(trie, fname, "example.com", &result);

  // verify both records exist
  dns_rrset_t *manual = dns_trie_lookup(trie, "manual.example.com", DNS_TYPE_A);
  munit_assert_not_null(manual);
  munit_assert_int(manual->records->rdata.a.address, ==, inet_addr("10.0.0.1"));

  dns_rrset_t *auto_rec = dns_trie_lookup(trie, "auto.example.com", DNS_TYPE_A);
  munit_assert_not_null(auto_rec);
  munit_assert_int(auto_rec->records->rdata.a.address, ==, inet_addr("10.0.0.2"));

  dns_trie_free(trie);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_soa_parsing(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  const char *zone_content =
    "$TTL 3600\n"
    "$ORIGIN example.com.\n"
    "@  IN  SOA  ns1.example.com. admin.example.com. 2024010101 3600 600 86400 300\n";

  char *fname = create_test_file(zone_content);
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  munit_assert_int(load_result, ==, 0);
  munit_assert_int(result.records_loaded, ==, 1);
  munit_assert_int(result.record_stats.soa_records, ==, 1);

  dns_rrset_t *soa_rrset = dns_trie_lookup(trie, "example.com", DNS_TYPE_SOA);
  munit_assert_not_null(soa_rrset);
  munit_assert_string_equal(soa_rrset->records->rdata.soa.mname, "ns1.example.com.");
  munit_assert_string_equal(soa_rrset->records->rdata.soa.rname, "admin.example.com.");
  munit_assert_int(soa_rrset->records->rdata.soa.serial, ==, 2024010101);

  dns_trie_free(trie);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_directives(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  const char *zone_content =
    "$ORIGIN example.com.\n"
    "$TTL 7200\n"
    "www  IN  A    192.168.1.1\n"
    "mail IN  A    192.168.1.2\n";

  char *fname = create_test_file(zone_content);
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  munit_assert_int(load_result, ==, 0);
  munit_assert_int(result.records_loaded, ==, 2);

  // verify TTL was applied from directive
  dns_rrset_t *www = dns_trie_lookup(trie, "www.example.com", DNS_TYPE_A);
  munit_assert_not_null(www);
  munit_assert_int(www->records->ttl, ==, 7200);

  dns_trie_free(trie);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_mx_records(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  const char *zone_content =
    "example.com. 300 IN MX 10 mail.example.com.\n"
    "example.com. 300 IN MX 20 backup.example.com.\n";

  char *fname = create_test_file(zone_content);
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  munit_assert_int(load_result, ==, 0);
  munit_assert_int(result.records_loaded, ==, 2);
  munit_assert_int(result.record_stats.mx_records, ==, 2);

  dns_rrset_t *mx_rrset = dns_trie_lookup(trie, "example.com", DNS_TYPE_MX);
  munit_assert_not_null(mx_rrset);
  munit_assert_int(mx_rrset->count, ==, 2);

  dns_trie_free(trie);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_relative_names(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  const char *zone_content =
    "$ORIGIN example.com.\n"
    "@     IN  NS   ns1\n"          // @ = example.com, ns1 = ns1.example.com
    "www   IN  A    192.168.1.1\n"  // www = www.example.com
    "      IN  AAAA 2001:db8::1\n"; // empty = www.example.com (last name)

  char *fname = create_test_file(zone_content);
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  munit_assert_int(load_result, ==, 0);
  munit_assert_int(result.records_loaded, ==, 3);

  // @ resolved to zone name
  dns_rrset_t *ns_rrset = dns_trie_lookup(trie, "example.com", DNS_TYPE_NS);
  munit_assert_not_null(ns_rrset);

  // relative name resolution
  dns_rrset_t *www_a = dns_trie_lookup(trie, "www.example.com", DNS_TYPE_A);
  munit_assert_not_null(www_a);

  // empty name used last name
  dns_rrset_t *www_aaaa = dns_trie_lookup(trie, "www.example.com", DNS_TYPE_AAAA);
  munit_assert_not_null(www_aaaa);

  dns_trie_free(trie);
  cleanup_test_file(fname);

  return MUNIT_OK;
}

static MunitResult test_blank_lines_and_whitespace(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  const char *zone_content =
    "\n"
    "   \n" // blank with spaces
    "www.example.com. 300 IN A 192.168.1.1\n"
    "\t\n" // blank with tab
    "mail.example.com. 300 IN A 192.168.1.2\n"
    "\n\n";

  char *fname = create_test_file(zone_content);
  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  munit_assert_int(load_result, ==, 0);
  munit_assert_int(result.records_loaded, ==, 2);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitResult test_ttl_inheritance(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  const char *zone_content =
    "$TTL 7200\n"
    "www.example.com. IN A 192.168.1.1\n"  // should inherit 7200
    "mail.example.com. 1800 IN A 192.168.1.2\n";  // explicit 1800

  char *fname = create_test_file(zone_content);
  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  zone_load_file(trie, fname, "example.com", &result);

  dns_rrset_t *www = dns_trie_lookup(trie, "www.example.com", DNS_TYPE_A);
  munit_assert_int(www->records->ttl, ==, 7200);

  dns_rrset_t *mail = dns_trie_lookup(trie, "mail.example.com", DNS_TYPE_A);
  munit_assert_int(mail->records->ttl, ==, 1800);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitResult test_empty_file(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  char *fname = create_test_file("");
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);
  munit_assert_int(load_result, ==, -1);  // no records loaded
  munit_assert_int(result.records_loaded, ==, 0);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitResult test_only_comments(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  const char *content =
    "; foo\n"
    "; bar\n"
    "   ; baz\n";

  char *fname = create_test_file(content);
  munit_assert_not_null(fname);

  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);
  munit_assert_int(load_result, ==, -1);
  munit_assert_int(result.records_loaded, ==, 0);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitResult test_invalid_ip(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  const char *content = "test.example.com. 300 IN A 999.999.999.999\n";

  char *fname = create_test_file(content);
  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  zone_load_file(trie, fname, "example.com", &result);

  // invalid IP - should fail
  munit_assert_int(result.errors_encountered, >, 0);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitResult test_missing_rdata(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  const char *content = "test.example.com. 300 IN A\n";  // missing IP

  char *fname = create_test_file(content);
  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  zone_load_file(trie, fname, "example.com", &result);

  // should fail
  munit_assert_int(result.records_loaded, ==, 0);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitResult test_unknown_type(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  const char *content = "test.example.com. 300 IN UNKNOWNTYPE somedata\n";

  char *fname = create_test_file(content);
  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  zone_load_file(trie, fname, "example.com", &result);

  // should skip (unknown type)
  munit_assert_int(result.records_loaded, ==, 0);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitResult test_multiline_soa(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  // SOA spanning multiple lines
  const char *content =
    "$ORIGIN example.com.\n"
    "@ IN SOA ns1.example.com. admin.example.com. (\n"
    "    2024010101 ; serial\n"
    "    7200       ; refresh\n"
    "    3600       ; retry\n"
    "    604800     ; expire\n"
    "    86400      ; minimum\n"
    ")\n";

  char *fname = create_test_file(content);
  dns_trie_t *trie = dns_trie_create();
  zone_load_result_t result;

  int load_result = zone_load_file(trie, fname, "example.com", &result);

  // NOTE: current implementation may not support fully
  munit_assert_int(load_result, ==, 0);

  dns_trie_free(trie);
  cleanup_test_file(fname);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/parser_create", test_parser_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/load_simple", test_load_simple, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/load_with_comments", test_load_with_comments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/string_to_type", test_string_to_type_conversion, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/backward_compatibility", test_backward_compatibility, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/soa_parsing", test_soa_parsing, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/directives", test_directives, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/mx_records", test_mx_records, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/relative_names", test_relative_names, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/blank_lines_and_whitespace", test_blank_lines_and_whitespace, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/ttl_inheritance", test_ttl_inheritance, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/empty_file", test_empty_file, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/only_comments", test_only_comments, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/invalid_ip", test_invalid_ip, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/missing_rdata", test_missing_rdata, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/unknown_type", test_unknown_type, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/multiline_soa", test_multiline_soa, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/zone_file", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
