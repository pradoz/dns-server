#include "munit.h"
#include "dns_cache.h"
#include <arpa/inet.h>
#include <unistd.h>


static MunitResult test_create(const MunitParameter params[], void *data) {
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

static MunitResult test_toggle_negative(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(100);
  munit_assert_not_null(cache);
  munit_assert_true(cache->enable_negative_cache); // enabled by default

  dns_cache_set_negative_cache_enabled(cache, false);
  munit_assert_false(cache->enable_negative_cache);

  dns_cache_set_negative_cache_enabled(cache, true);
  munit_assert_true(cache->enable_negative_cache);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_insert_positive(const MunitParameter params[], void *data) {
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

static MunitResult test_insert_negative(const MunitParameter params[], void *data) {
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

static MunitResult test_eviction(const MunitParameter params[], void *data) {
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

  // tTL too low (30 seconds)
  dns_cache_insert(cache, "test.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 30);

  // tTL should be clamped to min_ttl (60)
  // tODO: verify this when lookup is implemented

  dns_rr_free(record);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_stats(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);

  const dns_cache_stats_t *stats = dns_cache_get_stats(cache);
  munit_assert_not_null(stats);
  munit_assert_int(stats->insertions, ==, 0);

  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  record->rdata.a.address = inet_addr("192.168.1.1");
  dns_cache_insert(cache, "test.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 300);

  munit_assert_int(stats->insertions, ==, 1);
  // tODO: more stat cases

  dns_rr_free(record);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_lookup_hit(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // insert
  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(record);
  record->rdata.a.address = inet_addr("192.168.1.1");

  int result = dns_cache_insert(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 300);
  munit_assert_int(result, ==, 0);
  dns_rr_free(record);

  // lookup
  dns_cache_result_t *lookup = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);

  munit_assert_not_null(lookup);
  munit_assert_true(lookup->found);
  munit_assert_int(lookup->type, ==, DNS_CACHE_TYPE_POSITIVE);
  munit_assert_int(lookup->record_count, ==, 1);
  munit_assert_not_null(lookup->records);
  munit_assert_uint32(lookup->remaining_ttl, >, 0);
  munit_assert_uint32(lookup->remaining_ttl, <=, 300);

  // check IP address
  munit_assert_int(lookup->records->type, ==, DNS_TYPE_A);
  munit_assert_uint32(lookup->records->rdata.a.address, ==, inet_addr("192.168.1.1"));

  // stats
  const dns_cache_stats_t *stats = dns_cache_get_stats(cache);
  munit_assert_int(stats->queries, ==, 1);
  munit_assert_int(stats->hits, ==, 1);
  munit_assert_int(stats->misses, ==, 0);
  munit_assert_int(stats->positive_hits, ==, 1);

  dns_cache_result_free(lookup);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_lookup_miss(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // lookup non-existent record
  dns_cache_result_t *result = dns_cache_lookup(cache, "notfound.com", DNS_TYPE_A, DNS_CLASS_IN);

  munit_assert_null(result);

  const dns_cache_stats_t *stats = dns_cache_get_stats(cache);
  munit_assert_int(stats->queries, ==, 1);
  munit_assert_int(stats->misses, ==, 1);
  munit_assert_int(stats->hits, ==, 0);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_negative_lookup(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // insert negative entry
  int result = dns_cache_insert_negative(cache, "notfound.com", DNS_TYPE_A, DNS_CLASS_IN,
                                         DNS_CACHE_TYPE_NXDOMAIN, DNS_RCODE_NXDOMAIN, 300);
  munit_assert_int(result, ==, 0);

  // lookup should return negative result
  dns_cache_result_t *lookup = dns_cache_lookup(cache, "notfound.com", DNS_TYPE_A, DNS_CLASS_IN);

  munit_assert_not_null(lookup);
  munit_assert_true(lookup->found);
  munit_assert_int(lookup->type, ==, DNS_CACHE_TYPE_NXDOMAIN);
  munit_assert_int(lookup->rcode, ==, DNS_RCODE_NXDOMAIN);
  munit_assert_null(lookup->records);
  munit_assert_int(lookup->record_count, ==, 0);

  // stats
  const dns_cache_stats_t *stats = dns_cache_get_stats(cache);
  munit_assert_int(stats->negative_hits, ==, 1);
  munit_assert_int(stats->nxdomain_hits, ==, 1);

  dns_cache_result_free(lookup);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_expiration(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // insert record with 1 second TTL
  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 1);
  munit_assert_not_null(record);
  record->rdata.a.address = inet_addr("192.168.1.1");

  int result = dns_cache_insert(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 1);
  munit_assert_int(result, ==, 0);
  dns_rr_free(record);

  // should be in cache
  dns_cache_result_t *result1 = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  munit_assert_not_null(result1);
  dns_cache_result_free(result1);

  // wait for record to expire
  sleep(2);

  // record should expire
  dns_cache_result_t *result2 = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  munit_assert_null(result2);

  const dns_cache_stats_t *stats = dns_cache_get_stats(cache);
  munit_assert_int(stats->expired, ==, 1);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_remove_expired(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // insert multiple records with 1 second TTL
  for (int i = 0; i < 3; i++) {
    dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 1);
    munit_assert_not_null(record);
    record->rdata.a.address = inet_addr("192.168.1.1");

    char qname[64];
    snprintf(qname, sizeof(qname), "example%d.com", i);

    int result = dns_cache_insert(cache, qname, DNS_TYPE_A, DNS_CLASS_IN, record, 1, 1);
    munit_assert_int(result, ==, 0);
    dns_rr_free(record);
  }

  munit_assert_size(cache->current_entries, ==, 3);

  // wait for records to expire
  sleep(2);

  // remove expired entries
  int removed = dns_cache_remove_expired(cache);
  munit_assert_int(removed, ==, 3);
  munit_assert_size(cache->current_entries, ==, 0);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_remove_entry(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // insert a record
  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(record);
  record->rdata.a.address = inet_addr("192.168.1.1");

  int result = dns_cache_insert(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 300);
  munit_assert_int(result, ==, 0);
  dns_rr_free(record);

  munit_assert_size(cache->current_entries, ==, 1);

  // remove the record
  result = dns_cache_remove_entry(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  munit_assert_int(result, ==, 0);
  munit_assert_size(cache->current_entries, ==, 0);

  // try to remove again, should fail
  result = dns_cache_remove_entry(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  munit_assert_int(result, ==, -1);

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_case_insensitive(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // insert with lowercase
  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(record);
  record->rdata.a.address = inet_addr("192.168.1.1");

  int result = dns_cache_insert(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 300);
  munit_assert_int(result, ==, 0);
  dns_rr_free(record);

  // lookup with uppercase, should work
  dns_cache_result_t *lookup = dns_cache_lookup(cache, "EXAMPLE.COM", DNS_TYPE_A, DNS_CLASS_IN);
  munit_assert_not_null(lookup);
  munit_assert_true(lookup->found);

  dns_cache_result_free(lookup);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_hit_rate(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // insert record
  dns_rr_t *record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(record);
  record->rdata.a.address = inet_addr("192.168.1.1");

  int result = dns_cache_insert(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN, record, 1, 300);
  munit_assert_int(result, ==, 0);
  dns_rr_free(record);

  // 3 hits
  dns_cache_result_t *r1 = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  dns_cache_result_free(r1);
  dns_cache_result_t *r2 = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  dns_cache_result_free(r2);
  dns_cache_result_t *r3 = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  dns_cache_result_free(r3);

  // 2 misses
  dns_cache_lookup(cache, "notfound1.com", DNS_TYPE_A, DNS_CLASS_IN);
  dns_cache_lookup(cache, "notfound2.com", DNS_TYPE_A, DNS_CLASS_IN);

  float hit_rate = dns_cache_hit_rate(cache);
  munit_assert_float(hit_rate, ==, 60.0f);  // 3/(3+2) = 3/5 = 60%

  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_multiple_records(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_cache_t *cache = dns_cache_create(10);
  munit_assert_not_null(cache);

  // create multiple records
  dns_rr_t *record1 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(record1);
  record1->rdata.a.address = inet_addr("192.168.1.1");

  dns_rr_t *record2 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(record2);
  record2->rdata.a.address = inet_addr("192.168.1.2");

  // link record1->record2
  record1->next = record2;

  // insert linked records
  int result = dns_cache_insert(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN, record1, 2, 300);
  munit_assert_int(result, ==, 0);

  dns_rr_free(record1);  // free linked records

  // lookup
  dns_cache_result_t *lookup = dns_cache_lookup(cache, "example.com", DNS_TYPE_A, DNS_CLASS_IN);
  munit_assert_not_null(lookup);
  munit_assert_int(lookup->record_count, ==, 2);

  // check linked records exist
  munit_assert_not_null(lookup->records);
  munit_assert_not_null(lookup->records->next);
  munit_assert_null(lookup->records->next->next);

  dns_cache_result_free(lookup);
  dns_cache_free(cache);
  return MUNIT_OK;
}

static MunitResult test_resolver_with_cache_create(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_resolver_t *resolver = dns_resolver_create();
  munit_assert_not_null(resolver);
  munit_assert_not_null(resolver->trie);
  munit_assert_not_null(resolver->cache);
  munit_assert_true(resolver->cache_enabled);
  munit_assert_uint64(resolver->queries, ==, 0);
  munit_assert_uint64(resolver->cache_hits, ==, 0);
  munit_assert_uint64(resolver->cache_misses, ==, 0);

  dns_resolver_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_cache_hit_on_second_query(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_resolver_t *resolver = dns_resolver_create();
  munit_assert_not_null(resolver);

  // add test record to trie
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(a_record);
  a_record->rdata.a.address = inet_addr("192.168.1.1");
  munit_assert_true(dns_trie_insert_rr(resolver->trie, "test.com", a_record));

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "test.com");

  // first query - should miss cache
  dns_resolution_result_t *result1 = dns_resolution_result_create();
  dns_error_t err1;
  dns_error_init(&err1);

  int ret = dns_resolver_query_with_cache(resolver, &question, result1, &err1);
  munit_assert_int(ret, ==, 0);
  munit_assert_uint64(resolver->cache_misses, ==, 1);
  munit_assert_uint64(resolver->cache_hits, ==, 0);
  munit_assert_int(result1->answer_count, ==, 1);

  dns_resolution_result_free(result1);

  // second query - should hit cache
  dns_resolution_result_t *result2 = dns_resolution_result_create();
  dns_error_t err2;
  dns_error_init(&err2);

  ret = dns_resolver_query_with_cache(resolver, &question, result2, &err2);
  munit_assert_int(ret, ==, 0);
  munit_assert_uint64(resolver->cache_misses, ==, 1);
  munit_assert_uint64(resolver->cache_hits, ==, 1);
  munit_assert_int(result2->answer_count, ==, 1);

  dns_resolution_result_free(result2);
  dns_resolver_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_negative_caching(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_resolver_t *resolver = dns_resolver_create();
  munit_assert_not_null(resolver);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "notfound.com");

  // first query - cache miss, NXDOMAIN
  dns_resolution_result_t *result1 = dns_resolution_result_create();
  dns_error_t err1;
  dns_error_init(&err1);

  int ret = dns_resolver_query_with_cache(resolver, &question, result1, &err1);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(result1->rcode, ==, DNS_RCODE_NXDOMAIN);
  munit_assert_uint64(resolver->cache_misses, ==, 1);

  dns_resolution_result_free(result1);

  // second query - should hit negative cache
  dns_resolution_result_t *result2 = dns_resolution_result_create();
  dns_error_t err2;
  dns_error_init(&err2);

  ret = dns_resolver_query_with_cache(resolver, &question, result2, &err2);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(result2->rcode, ==, DNS_RCODE_NXDOMAIN);
  munit_assert_uint64(resolver->cache_hits, ==, 1);

  dns_resolution_result_free(result2);
  dns_resolver_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_cache_disabled(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_resolver_t *resolver = dns_resolver_create();
  munit_assert_not_null(resolver);

  // disable cache
  dns_resolver_set_cache_enabled(resolver, false);
  munit_assert_false(resolver->cache_enabled);

  // add test record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = inet_addr("192.168.1.1");
  dns_trie_insert_rr(resolver->trie, "test.com", a_record);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "test.com");

  // two queries - both should miss cache (disabled)
  dns_resolution_result_t *result1 = dns_resolution_result_create();
  dns_error_t err1;
  dns_error_init(&err1);
  dns_resolver_query_with_cache(resolver, &question, result1, &err1);
  dns_resolution_result_free(result1);

  dns_resolution_result_t *result2 = dns_resolution_result_create();
  dns_error_t err2;
  dns_error_init(&err2);
  dns_resolver_query_with_cache(resolver, &question, result2, &err2);
  dns_resolution_result_free(result2);

  munit_assert_uint64(resolver->cache_hits, ==, 0);
  munit_assert_uint64(resolver->cache_misses, ==, 0);

  dns_resolver_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_cache_expiration(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_resolver_t *resolver = dns_resolver_create();
  munit_assert_not_null(resolver);

  // add record with 1 second TTL
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 1);
  a_record->rdata.a.address = inet_addr("192.168.1.1");
  dns_trie_insert_rr(resolver->trie, "test.com", a_record);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "test.com");

  // first query - cache miss
  dns_resolution_result_t *result1 = dns_resolution_result_create();
  dns_error_t err1;
  dns_error_init(&err1);
  dns_resolver_query_with_cache(resolver, &question, result1, &err1);
  dns_resolution_result_free(result1);

  munit_assert_uint64(resolver->cache_misses, ==, 1);

  // immediate second query - cache hit
  dns_resolution_result_t *result2 = dns_resolution_result_create();
  dns_error_t err2;
  dns_error_init(&err2);
  dns_resolver_query_with_cache(resolver, &question, result2, &err2);
  dns_resolution_result_free(result2);

  munit_assert_uint64(resolver->cache_hits, ==, 1);

  // wait for expiration
  sleep(2);

  // third query - cache miss (expired)
  dns_resolution_result_t *result3 = dns_resolution_result_create();
  dns_error_t err3;
  dns_error_init(&err3);
  dns_resolver_query_with_cache(resolver, &question, result3, &err3);
  dns_resolution_result_free(result3);

  munit_assert_uint64(resolver->cache_misses, ==, 2);

  dns_resolver_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_backward_compatibility(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  // old way still works
  dns_trie_t *trie = dns_trie_create();
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = inet_addr("192.168.1.1");
  dns_trie_insert_rr(trie, "test.com", a_record);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "test.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(result->answer_count, ==, 1);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}


static MunitTest tests[] = {
  {"/operations/create", test_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/operations/toggle_negative", test_toggle_negative, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/operations/insert_positive", test_insert_positive, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/operations/insert_negative", test_insert_negative, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/operations/eviction", test_eviction, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/operations/ttl_clamping", test_ttl_clamping, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/operations/stats", test_stats, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/hit", test_lookup_hit, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/miss", test_lookup_miss, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/negative_lookup", test_negative_lookup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/expiration", test_expiration, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/remove_expired", test_remove_expired, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/remove_entry", test_remove_entry, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/case_insensitive", test_case_insensitive, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/hit_rate", test_hit_rate, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/lookup/multiple_records", test_multiple_records, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolver/create", test_resolver_with_cache_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolver/cache_hit", test_cache_hit_on_second_query, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolver/negative_caching", test_negative_caching, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolver/cache_disabled", test_cache_disabled, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolver/cache_expiration", test_cache_expiration, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolver/backward_compat", test_backward_compatibility, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/cache", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
