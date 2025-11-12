#include "dns_trie.h"
#include "munit.h"

static MunitResult test_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();
  munit_assert_not_null(trie);
  munit_assert_not_null(trie->root);

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
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = 0x01020304; // 1.2.3.4

  bool result = dns_trie_insert_rr(trie, "example.com", a_record);
  munit_assert_true(result);

  // lookup
  dns_rrset_t *rrset = dns_trie_lookup(trie, "example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset);
  munit_assert_int(rrset->type, ==, DNS_TYPE_A);
  munit_assert_int(rrset->count, ==, 1);
  munit_assert_uint32(rrset->records->rdata.a.address, ==, 0x01020304);

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
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = 0x01020304;
  result = dns_trie_insert_rr(trie, "www.example.com", a_record);
  munit_assert_false(result);

  dns_rr_free(a_record);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_zone(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // create SOA
  dns_soa_t *soa = calloc(1, sizeof(dns_soa_t));
  strcpy(soa->mname, "ns1.example.com");
  strcpy(soa->rname, "admin.example.com");
  soa->serial = 2024010101;

  // create NS records
  dns_rrset_t *ns_rrset = dns_rrset_create(DNS_TYPE_NS, 3600);
  dns_rr_t *ns = dns_rr_create(DNS_TYPE_NS, DNS_CLASS_IN, 3600);
  strcpy(ns->rdata.ns.nsdname, "ns1.example.com");
  dns_rrset_add(ns_rrset, ns);

  // insert zone
  bool result = dns_trie_insert_zone(trie, "example.com", soa, ns_rrset);
  munit_assert_true(result);

  // find zone
  dns_zone_t *zone = dns_trie_find_zone(trie, "www.example.com");
  munit_assert_not_null(zone);
  munit_assert_not_null(zone->soa);
  munit_assert_int(strcmp(zone->zone_name, "example.com"), ==, 0);

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_subdomain_lookup(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // insert records at different levels
  dns_rr_t *a1 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a1->rdata.a.address = 0x01020304;
  munit_assert_true(dns_trie_insert_rr(trie, "example.com", a1));

  dns_rr_t *a2 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a2->rdata.a.address = 0x05060708;
  munit_assert_true(dns_trie_insert_rr(trie, "sub.example.com", a2));

  dns_rr_t *a3 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a3->rdata.a.address = 0x090A0B0C;
  munit_assert_true(dns_trie_insert_rr(trie, "deep.sub.example.com", a3));

  // lookup each level
  dns_rrset_t *rrset1 = dns_trie_lookup(trie, "example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset1);
  munit_assert_uint32(rrset1->records->rdata.a.address, ==, 0x01020304);

  dns_rrset_t *rrset2 = dns_trie_lookup(trie, "sub.example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset2);
  munit_assert_uint32(rrset2->records->rdata.a.address, ==, 0x05060708);

  dns_rrset_t *rrset3 = dns_trie_lookup(trie, "deep.sub.example.com", DNS_TYPE_A);
  munit_assert_not_null(rrset3);
  munit_assert_uint32(rrset3->records->rdata.a.address, ==, 0x090A0B0C);

  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitTest tests[] = {
    {"/create", test_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/insert_and_lookup", test_insert_and_lookup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/cname", test_cname, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/zone", test_zone, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {"/subdomain_lookup", test_subdomain_lookup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}};

static const MunitSuite suite = {"/trie", tests, NULL, 1,
                                 MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
