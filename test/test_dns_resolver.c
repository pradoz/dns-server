#include "munit.h"
#include "dns_resolver.h"
#include "dns_error.h"
#include <string.h>
#include <arpa/inet.h>

static MunitResult test_result_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_resolution_result_t *result = dns_resolution_result_create();
  munit_assert_not_null(result);
  munit_assert_null(result->answer_list);
  munit_assert_null(result->authority_list);
  munit_assert_null(result->additional_list);
  munit_assert_int(result->answer_count, ==, 0);
  munit_assert_int(result->authority_count, ==, 0);
  munit_assert_int(result->additional_count, ==, 0);
  munit_assert_int(result->rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_false(result->authoritative);

  dns_resolution_result_free(result);
  return MUNIT_OK;
}

static MunitResult test_simple_a_record(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // add A record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = htonl(0x01020304);
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
  munit_assert_int(err.code, ==, DNS_ERR_NONE);
  munit_assert_int(result->rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(result->answer_count, ==, 1);
  munit_assert_not_null(result->answer_list);
  munit_assert_uint32(result->answer_list->rdata.a.address, ==, htonl(0x01020304));

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_nxdomain(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "nonexistent.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(result->rcode, ==, DNS_RCODE_NXDOMAIN);
  munit_assert_int(result->answer_count, ==, 0);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_nxdomain_with_soa(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // create zone with SOA
  dns_soa_t *soa = calloc(1, sizeof(dns_soa_t));
  strcpy(soa->mname, "ns1.test.com");
  strcpy(soa->rname, "admin.test.com");
  soa->serial = 1;
  soa->refresh = 3600;
  soa->retry = 600;
  soa->expire = 86400;
  soa->minimum = 300;

  dns_rrset_t *ns_rrset = dns_rrset_create(DNS_TYPE_NS, 3600);
  dns_rr_t *ns = dns_rr_create(DNS_TYPE_NS, DNS_CLASS_IN, 3600);
  strcpy(ns->rdata.ns.nsdname, "ns1.test.com");
  dns_rrset_add(ns_rrset, ns);

  dns_trie_insert_zone(trie, "test.com", soa, ns_rrset);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "nonexistent.test.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(result->rcode, ==, DNS_RCODE_NXDOMAIN);
  munit_assert_int(result->answer_count, ==, 0);
  munit_assert_int(result->authority_count, ==, 1);
  munit_assert_true(result->authoritative);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_cname_simple(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // add target A record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = htonl(0x01020304);
  dns_trie_insert_rr(trie, "target.com", a_record);

  // add CNAME
  dns_trie_insert_cname(trie, "alias.com", "target.com", 300);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "alias.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(err.code, ==, DNS_ERR_NONE);
  munit_assert_int(result->rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(result->answer_count, ==, 2); // CNAME + A

  // first should be CNAME
  munit_assert_not_null(result->answer_list);
  munit_assert_int(result->answer_list->type, ==, DNS_TYPE_CNAME);
  munit_assert_string_equal(result->answer_list->rdata.cname.cname, "target.com");

  // second should be A record
  munit_assert_not_null(result->answer_list->next);
  munit_assert_int(result->answer_list->next->type, ==, DNS_TYPE_A);
  munit_assert_uint32(result->answer_list->next->rdata.a.address, ==, htonl(0x01020304));

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_cname_chain(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // add target A record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = htonl(0x01020304);
  dns_trie_insert_rr(trie, "final.com", a_record);

  // build CNAME chain: alias1 -> alias2 -> alias3 -> final
  dns_trie_insert_cname(trie, "alias1.com", "alias2.com", 300);
  dns_trie_insert_cname(trie, "alias2.com", "alias3.com", 300);
  dns_trie_insert_cname(trie, "alias3.com", "final.com", 300);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "alias1.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(err.code, ==, DNS_ERR_NONE);
  munit_assert_int(result->rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(result->answer_count, ==, 4); // 3 CNAMEs + 1 A

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_cname_loop(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // create CNAME loop: alias1 -> alias2 -> alias1
  dns_trie_insert_cname(trie, "alias1.com", "alias2.com", 300);
  dns_trie_insert_cname(trie, "alias2.com", "alias1.com", 300);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "alias1.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, -1);
  munit_assert_int(err.code, ==, DNS_ERR_CNAME_LOOP);
  munit_assert_int(result->rcode, ==, DNS_RCODE_SERVFAIL);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_cname_too_long(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // create CNAME chain longer than max
  char name1[MAX_DOMAIN_NAME];
  char name2[MAX_DOMAIN_NAME];

  for (int i = 0; i < DNS_MAX_CNAME_CHAIN + 5; i++) {
    snprintf(name1, sizeof(name1), "alias%d.com", i);
    snprintf(name2, sizeof(name2), "alias%d.com", i + 1);
    dns_trie_insert_cname(trie, name1, name2, 300);
  }

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "alias0.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, -1);
  munit_assert_int(err.code, ==, DNS_ERR_CNAME_CHAIN_TOO_LONG);
  munit_assert_int(result->rcode, ==, DNS_RCODE_SERVFAIL);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_nodata(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // add only A record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = htonl(0x01020304);
  dns_trie_insert_rr(trie, "test.com", a_record);

  // query for AAAA (domain exists but not this type)
  dns_question_t question = {
    .qtype = DNS_TYPE_AAAA,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "test.com");

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err;
  dns_error_init(&err);

  int ret = dns_resolve_query_full(trie, &question, result, &err);
  munit_assert_int(ret, ==, 0);
  munit_assert_int(result->rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(result->answer_count, ==, 0);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_error_codes(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // test error code to string conversion
  munit_assert_string_equal(dns_error_string(DNS_ERR_NONE), "No error");
  munit_assert_string_equal(dns_error_string(DNS_ERR_CNAME_LOOP), "CNAME loop detected");

  // test error code to RCODE conversion
  munit_assert_int(dns_error_to_rcode(DNS_ERR_NONE), ==, DNS_RCODE_NOERROR);
  munit_assert_int(dns_error_to_rcode(DNS_ERR_INVALID_PACKET), ==, DNS_RCODE_FORMERROR);
  munit_assert_int(dns_error_to_rcode(DNS_ERR_UNSUPPORTED_OPCODE), ==, DNS_RCODE_NOTIMP);
  munit_assert_int(dns_error_to_rcode(DNS_ERR_MEMORY_ALLOCATION), ==, DNS_RCODE_SERVFAIL);

  return MUNIT_OK;
}

static MunitResult test_wildcard_not_implemented(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  // wildcard not yet implemented, just verify we do not crash
  dns_trie_t *trie = dns_trie_create();

  dns_trie_insert_a(trie, "*.example.com", "192.168.1.1", 300);

  dns_question_t q = { .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN };
  dns_safe_strncpy(q.qname, "anything.example.com", sizeof(q.qname));

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err = DNS_ERROR_INIT;

  dns_resolve_query_full(trie, &q, result, &err);

  // return NXDOMAIN for now without wildcard expansion
  munit_assert_int(result->rcode, ==, DNS_RCODE_NXDOMAIN);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_empty_qname(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_trie_t *trie = dns_trie_create();

  dns_question_t q = { .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN };
  q.qname[0] = '\0';  // empty name

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err = DNS_ERROR_INIT;

  int ret = dns_resolve_query_full(trie, &q, result, &err);
  munit_assert_int(ret, ==, 0);  // should not crash

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_invalid_class(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_trie_t *trie = dns_trie_create();
  dns_trie_insert_a(trie, "test.com", "192.168.1.1", 300);

  dns_question_t q = { .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_CH };  // CHAOS class
  dns_safe_strncpy(q.qname, "test.com", sizeof(q.qname));

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err = DNS_ERROR_INIT;

  int ret = dns_resolve_query_full(trie, &q, result, &err);
  munit_assert_int(ret, ==, -1);
  munit_assert_int(result->rcode, ==, DNS_RCODE_FORMERROR);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_cname_to_nonexistent(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_trie_t *trie = dns_trie_create();

  // CNAME pointing to non-existent target
  dns_trie_insert_cname(trie, "alias.com", "nonexistent.com", 300);

  dns_question_t q = { .qtype = DNS_TYPE_A, .qclass = DNS_CLASS_IN };
  dns_safe_strncpy(q.qname, "alias.com", sizeof(q.qname));

  dns_resolution_result_t *result = dns_resolution_result_create();
  dns_error_t err = DNS_ERROR_INIT;

  int ret = dns_resolve_query_full(trie, &q, result, &err);
  munit_assert_int(ret, ==, 0);

  // should return CNAME in answer, but no final A record
  // RFC: NOERROR with just the CNAME
  munit_assert_int(result->rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(result->answer_count, ==, 1);
  munit_assert_int(result->answer_list->type, ==, DNS_TYPE_CNAME);

  dns_resolution_result_free(result);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/create_resolution_result", test_result_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/simple_a_record", test_simple_a_record, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/nxdomain", test_nxdomain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/nxdomain_with_soa", test_nxdomain_with_soa, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/cname_simple", test_cname_simple, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/cname_chain", test_cname_chain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/cname_loop", test_cname_loop, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/cname_too_long", test_cname_too_long, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/nodata", test_nodata, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/error_codes", test_error_codes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/wildcard_not_implemented", test_wildcard_not_implemented, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/empty_qname", test_empty_qname, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/invalid_class", test_invalid_class, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/cname_to_nonexistent", test_cname_to_nonexistent, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/resolver", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
