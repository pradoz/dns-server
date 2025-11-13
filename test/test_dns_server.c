#include "munit.h"
#include "dns_server.h"
#include "dns_error.h"
#include <string.h>
#include <arpa/inet.h>

static MunitResult test_server_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_server_t *server = dns_server_create(5353);
  munit_assert_not_null(server);
  munit_assert_int(server->port, ==, 5353);
  munit_assert_not_null(server->trie);
  munit_assert_false(server->running);
  munit_assert_int(server->socket_fd, ==, -1);
  munit_assert_int(server->queries_received, ==, 0);
  munit_assert_int(server->queries_processed, ==, 0);
  munit_assert_int(server->queries_failed, ==, 0);

  dns_server_free(server);
  return MUNIT_OK;
}

static MunitResult test_response_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_response_t *response = dns_response_create(512);
  munit_assert_not_null(response);
  munit_assert_not_null(response->buffer);
  munit_assert_size(response->capacity, ==, 512);
  munit_assert_size(response->length, ==, 0);

  dns_response_free(response);
  return MUNIT_OK;
}

static MunitResult test_process_query_simple(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_server_t *server = dns_server_create(5353);

  // add test record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = htonl(0x7F000001);
  dns_trie_insert_rr(server->trie, "test.local", a_record);

  // build query packet
  uint8_t query_buffer[512];
  size_t offset = 0;

  dns_header_t query_header = {
    .id = 0x1234,
    .qr = DNS_QR_QUERY,
    .opcode = DNS_OPCODE_QUERY,
    .rd = 1,
    .qdcount = 1,
    .ancount = 0,
    .nscount = 0,
    .arcount = 0
  };
  dns_encode_header(query_buffer, sizeof(query_buffer), &query_header);
  offset = 12;

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "test.local");
  dns_encode_question(query_buffer, sizeof(query_buffer), &offset, &question);

  // create request
  dns_request_t request = {
    .buffer = query_buffer,
    .length = offset
  };

  // process query
  dns_response_t *response = dns_response_create(512);
  dns_error_t err;
  dns_error_init(&err);

  int result = dns_process_query(server, &request, response, &err);

  munit_assert_int(result, ==, 0);
  munit_assert_int(err.code, ==, DNS_ERR_NONE);
  munit_assert_size(response->length, >, 12);

  // parse response header
  dns_header_t response_header;
  dns_parse_header(response->buffer, response->length, &response_header);

  munit_assert_int(response_header.id, ==, query_header.id);
  munit_assert_int(response_header.qr, ==, DNS_QR_RESPONSE);
  munit_assert_int(response_header.rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(response_header.qdcount, ==, 1);
  munit_assert_int(response_header.ancount, ==, 1);

  dns_response_free(response);
  dns_server_free(server);
  return MUNIT_OK;
}

static MunitResult test_process_query_with_cname(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_server_t *server = dns_server_create(5353);

  // add target A record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = htonl(0x01020304);
  dns_trie_insert_rr(server->trie, "target.local", a_record);

  // add CNAME
  dns_trie_insert_cname(server->trie, "alias.local", "target.local", 300);

  // build query for alias
  uint8_t query_buffer[512];
  size_t offset = 0;

  dns_header_t query_header = {
    .id = 0x5678,
    .qr = DNS_QR_QUERY,
    .opcode = DNS_OPCODE_QUERY,
    .rd = 1,
    .qdcount = 1
  };
  dns_encode_header(query_buffer, sizeof(query_buffer), &query_header);
  offset = 12;

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "alias.local");
  dns_encode_question(query_buffer, sizeof(query_buffer), &offset, &question);

  dns_request_t request = {
    .buffer = query_buffer,
    .length = offset
  };

  dns_response_t *response = dns_response_create(512);
  dns_error_t err;
  dns_error_init(&err);

  int result = dns_process_query(server, &request, response, &err);

  munit_assert_int(result, ==, 0);
  munit_assert_int(err.code, ==, DNS_ERR_NONE);

  dns_header_t response_header;
  dns_parse_header(response->buffer, response->length, &response_header);

  munit_assert_int(response_header.rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(response_header.ancount, ==, 2); // CNAME + A

  dns_response_free(response);
  dns_server_free(server);
  return MUNIT_OK;
}

static MunitResult test_process_query_nxdomain(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_server_t *server = dns_server_create(5353);

  // add zone with SOA
  dns_soa_t *soa = calloc(1, sizeof(dns_soa_t));
  strcpy(soa->mname, "ns1.local");
  strcpy(soa->rname, "admin.local");
  soa->serial = 1;
  soa->minimum = 300;

  dns_rrset_t *ns_rrset = dns_rrset_create(DNS_TYPE_NS, 3600);
  dns_rr_t *ns = dns_rr_create(DNS_TYPE_NS, DNS_CLASS_IN, 3600);
  strcpy(ns->rdata.ns.nsdname, "ns1.local");
  dns_rrset_add(ns_rrset, ns);

  dns_trie_insert_zone(server->trie, "local", soa, ns_rrset);

  // query for non-existent domain
  uint8_t query_buffer[512];
  size_t offset = 0;

  dns_header_t query_header = {
    .id = 0x9ABC,
    .qr = DNS_QR_QUERY,
    .opcode = DNS_OPCODE_QUERY,
    .rd = 1,
    .qdcount = 1
  };
  dns_encode_header(query_buffer, sizeof(query_buffer), &query_header);
  offset = 12;

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "nonexistent.local");
  dns_encode_question(query_buffer, sizeof(query_buffer), &offset, &question);

  dns_request_t request = {
    .buffer = query_buffer,
    .length = offset
  };

  dns_response_t *response = dns_response_create(512);
  dns_error_t err;
  dns_error_init(&err);

  int result = dns_process_query(server, &request, response, &err);

  munit_assert_int(result, ==, 0);

  dns_header_t response_header;
  dns_parse_header(response->buffer, response->length, &response_header);

  munit_assert_int(response_header.rcode, ==, DNS_RCODE_NXDOMAIN);
  munit_assert_int(response_header.ancount, ==, 0);
  munit_assert_int(response_header.nscount, ==, 1); // SOA in authority
  munit_assert_int(response_header.aa, ==, 1); // authoritative

  dns_response_free(response);
  dns_server_free(server);
  return MUNIT_OK;
}

static MunitResult test_process_query_formerr(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_server_t *server = dns_server_create(5353);

  // create malformed query (too short)
  uint8_t query_buffer[8] = {0};

  dns_request_t request = {
    .buffer = query_buffer,
    .length = 8
  };

  dns_response_t *response = dns_response_create(512);
  dns_error_t err;
  dns_error_init(&err);

  int result = dns_process_query(server, &request, response, &err);

  munit_assert_int(result, ==, -1);
  munit_assert_int(err.code, ==, DNS_ERR_INVALID_PACKET);

  dns_response_free(response);
  dns_server_free(server);
  return MUNIT_OK;
}

static MunitResult test_process_query_notimp(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_server_t *server = dns_server_create(5353);

  // build query with unsupported opcode
  uint8_t query_buffer[512];

  dns_header_t query_header = {
    .id = 0xDEF0,
    .qr = DNS_QR_QUERY,
    .opcode = DNS_OPCODE_STATUS, // unsupported
    .rd = 1,
    .qdcount = 0
  };
  dns_encode_header(query_buffer, sizeof(query_buffer), &query_header);

  dns_request_t request = {
    .buffer = query_buffer,
    .length = 12
  };

  dns_response_t *response = dns_response_create(512);
  dns_error_t err;
  dns_error_init(&err);

  int result = dns_process_query(server, &request, response, &err);

  munit_assert_int(result, ==, 0);

  dns_header_t response_header;
  dns_parse_header(response->buffer, response->length, &response_header);

  munit_assert_int(response_header.rcode, ==, DNS_RCODE_NOTIMP);

  dns_response_free(response);
  dns_server_free(server);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/create", test_server_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/response/create", test_response_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/process_query/simple", test_process_query_simple, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/process_query/with_cname", test_process_query_with_cname, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/process_query/nxdomain", test_process_query_nxdomain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/process_query/formerr", test_process_query_formerr, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/process_query/notimp", test_process_query_notimp, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/server", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
