#include "munit.h"
#include "dns_cache.h"
#include <string.h>
#include <arpa/inet.h>


static MunitResult test_cache_create(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(100);
  munit_assert_not_null(cache);
  munit_assert_size(cache->max_entries, ==, 100);
  munit_assert_size(cache->current_entries, ==, 0);
  munit_assert_int(cache->min_ttl, ==, 0);
  munit_assert_int(cache->max_ttl, ==, 86400);
  munit_assert_true(cache->enable_negative_cache);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_cache_insert_positive(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);

  // create a test record
  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  record->rdata.a.address = inet_addr("192.168.1.1");

  int result = dns_cache_insert(cache,
                                "example.com",
                                DNS_TYPE_A,
                                DNS_CLASS_IN,
                                record,
                                1,
                                300);

  munit_assert_int(result, ==, 0);
  munit_assert_size(cache->current_entries, ==, 1);
  munit_assert_int(cache->stats.insertions, ==, 1);

  dns_rr_free(record);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_cache_insert_negative(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);

  int result = dns_cache_insert_negative(cache,
                                         "notfound.com",
                                         DNS_TYPE_A,
                                         DNS_CLASS_IN,
                                         DNS_CACHE_TYPE_NXDOMAIN,
                                         DNS_RCODE_NXDOMAIN,
                                         300);

  munit_assert_int(result, ==, 0);
  munit_assert_size(cache->current_entries, ==, 1);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_cache_eviction(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(3);  // start with 3 entries

  // insert 4 entries, should evict the first
  for (int i = 0; i < 4; i++) {
    dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
    record->rdata.a.address = inet_addr("192.168.1.1");

    char qname[64];
    snprintf(qname, sizeof(qname), "example%d.com", i);

    dns_cache_insert(cache, qname, DNS_TYPE_A, DNS_CLASS_IN, record, 1, 300);
    dns_rr_free(record);
  }

  munit_assert_size(cache->current_entries, ==, 3);
  munit_assert_int(cache->stats.evictions, ==, 1);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_ttl_clamping(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  dns_cache_set_ttl_limits(cache, 60, 3600);  // 1 min to 1 hour

  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  record->rdata.a.address = inet_addr("192.168.1.1");

  // TTL too low (30 seconds)
  dns_cache_insert(cache, "test.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 30);

  // TTL should be clamped to min_ttl (60)
  // TODO: verify this when lookup is implemented

  dns_rr_free(record);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_cache_stats(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);

  const dns_cache_stats_t *stats = dns_cache_get_stats(cache);
  munit_assert_not_null(stats);
  munit_assert_int(stats->insertions, ==, 0);

  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  record->rdata.a.address = inet_addr("192.168.1.1");
  dns_cache_insert(cache, "test.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 300);

  munit_assert_int(stats->insertions, ==, 1);
  // TODO: more stat cases

  dns_rr_free(record);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/create", test_cache_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/insert_positive", test_cache_insert_positive, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/insert_negative", test_cache_insert_negative, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/eviction", test_cache_eviction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/ttl_clamping", test_ttl_clamping, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/stats", test_cache_stats, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/cache", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
