#include "dns_trie.h"
#include "munit.h"
#include <arpa/inet.h>

static MunitResult test_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();
  munit_assert_not_null(trie);
  munit_assert_not_null(trie->root);
  munit_assert_true(dns_trie_is_empty(trie));

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_insert_and_lookup(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // lookup non-existent
  dns_rrset_t *missing = dns_trie_lookup(trie, "notfound.com", DNS_TYPE_A);
  munit_assert_null(missing);

  // insert A record
  munit_assert_true(dns_trie_insert_a(trie, "example.com", "1.2.3.4", 300));

  // lookup
  dns_rrset_t *rrset = dns_trie_lookup(trie, "example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset);
  munit_assert_int(rrset->type, ==, DNS_TYPE_A);
  munit_assert_int(rrset->count, ==, 1);
  munit_assert_uint32(rrset->records->rdata.a.address, ==, inet_addr("1.2.3.4"));

  munit_assert_false(dns_trie_is_empty(trie));

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_insert_multiple_types(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  munit_assert_true(dns_trie_insert_a(trie, "example.com", "192.168.1.1", 300));
  munit_assert_true(dns_trie_insert_aaaa(trie, "example.com", "2001:db8::1", 300));
  munit_assert_true(dns_trie_insert_ns(trie, "example.com", "ns1.example.com", 3600));
  munit_assert_true(dns_trie_insert_mx(trie, "example.com", 10, "mail.example.com", 3600));

  // all types
  munit_assert_not_null(dns_trie_lookup(trie, "example.com", DNS_TYPE_A));
  munit_assert_not_null(dns_trie_lookup(trie, "example.com", DNS_TYPE_AAAA));
  munit_assert_not_null(dns_trie_lookup(trie, "example.com", DNS_TYPE_NS));
  munit_assert_not_null(dns_trie_lookup(trie, "example.com", DNS_TYPE_MX));

  // non-existent type
  munit_assert_null(dns_trie_lookup(trie, "example.com", DNS_TYPE_TXT));

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_cname(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // insert CNAME record
  bool result = dns_trie_insert_cname(trie, "www.example.com", "example.com", 300);
  munit_assert_true(result);

  // lookup CNAME
  uint32_t ttl;
  dns_cname_t *cname = dns_trie_lookup_cname(trie, "www.example.com", &ttl);
  munit_assert_not_null(cname);
  munit_assert_int(strcmp(cname->cname, "example.com"), ==, 0);
  munit_assert_int(ttl, ==, 300);

  // inserting A record at CNAME location should fail
  munit_assert_false(dns_trie_insert_a(trie, "www.example.com", "1.2.3.4", 300));

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_zone(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // create SOA
  dns_soa_t *soa = calloc(1, sizeof(dns_soa_t));
  dns_safe_strncpy(soa->mname, "ns1.example.com", sizeof(soa->mname));
  dns_safe_strncpy(soa->rname, "admin.example.com", sizeof(soa->rname));
  soa->serial = 2024010101;
  soa->refresh = 7200;
  soa->retry = 3600;
  soa->expire = 604800;
  soa->minimum = 86400;

  // create NS records
  dns_rrset_t *ns_rrset = dns_rrset_create(DNS_TYPE_NS, 3600);
  dns_rr_t *ns = dns_rr_create_ns("ns1.example.com", 3600);
  dns_rrset_add(ns_rrset, ns);

  // insert zone
  bool result = dns_trie_insert_zone(trie, "example.com", soa, ns_rrset);
  munit_assert_true(result);

  // find zone
  dns_zone_t *zone = dns_trie_find_zone(trie, "www.example.com");
  munit_assert_not_null(zone);
  munit_assert_not_null(zone->soa);
  munit_assert_string_equal(zone->zone_name, "example.com");
  munit_assert_true(zone->authoritative);

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_subdomain_lookup(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // insert records at different levels
  munit_assert_true(dns_trie_insert_a(trie, "example.com", "1.2.3.4", 300));
  munit_assert_true(dns_trie_insert_a(trie, "sub.example.com", "5.6.7.8", 300));
  munit_assert_true(dns_trie_insert_a(trie, "deep.sub.example.com", "9.10.11.12", 300));

  // lookup each level
  dns_rrset_t *rrset1 = dns_trie_lookup(trie, "example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset1);
  munit_assert_uint32(rrset1->records->rdata.a.address, ==, inet_addr("1.2.3.4"));

  dns_rrset_t *rrset2 = dns_trie_lookup(trie, "sub.example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset2);
  munit_assert_uint32(rrset2->records->rdata.a.address, ==, inet_addr("5.6.7.8"));

  dns_rrset_t *rrset3 = dns_trie_lookup(trie, "deep.sub.example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset3);
  munit_assert_uint32(rrset3->records->rdata.a.address, ==, inet_addr("9.10.11.12"));

  // non-existent subdomain
  munit_assert_null(dns_trie_lookup(trie, "other.example.com", DNS_TYPE_A));

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_utils_invalid_input(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // NULL trie
  munit_assert_false(dns_trie_insert_a(NULL, "test.com", "1.2.3.4", 300));

  // NULL domain
  munit_assert_false(dns_trie_insert_a(trie, NULL, "1.2.3.4", 300));

  // NULL/invalid IP
  munit_assert_false(dns_trie_insert_a(trie, "test.com", NULL, 300));
  munit_assert_false(dns_trie_insert_a(trie, "test.com", "invalid", 300));
  munit_assert_false(dns_trie_insert_aaaa(trie, "test.com", "invalid", 300));

  // NULL nsdname/exchange
  munit_assert_false(dns_trie_insert_ns(trie, "test.com", NULL, 300));
  munit_assert_false(dns_trie_insert_mx(trie, "test.com", 10, NULL, 300));

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_record_count(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();
  munit_assert_size(dns_trie_get_record_count(trie), ==, 0);

  dns_trie_insert_a(trie, "a.example.com", "1.1.1.1", 300);
  munit_assert_size(dns_trie_get_record_count(trie), ==, 1);

  dns_trie_insert_a(trie, "b.example.com", "2.2.2.2", 300);
  munit_assert_size(dns_trie_get_record_count(trie), ==, 2);

  dns_trie_insert_aaaa(trie, "a.example.com", "2001:db8::1", 300);
  munit_assert_size(dns_trie_get_record_count(trie), ==, 3);

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/create", test_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/insert_and_lookup", test_insert_and_lookup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/insert_multiple_types", test_insert_multiple_types, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/cname", test_cname, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/zone", test_zone, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/subdomain_lookup", test_subdomain_lookup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/utils_invalid", test_utils_invalid_input, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/record_count", test_record_count, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/trie", tests, NULL, 1,
                                 MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
