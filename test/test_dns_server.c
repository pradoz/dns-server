#include "munit.h"
#include "dns_server.h"
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

static MunitResult test_resolve_query_nxdomain(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "nonexistent.com");

  dns_message_t *response_msg = dns_message_create();
  response_msg->header.qdcount = 1;

  int result = dns_resolve_query(trie, &question, response_msg);
  munit_assert_int(result, ==, 0);
  munit_assert_int(response_msg->header.rcode, ==, DNS_RCODE_NXDOMAIN);
  munit_assert_int(response_msg->header.ancount, ==, 0);

  dns_message_free(response_msg);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_resolve_query_found(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // insert A record
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = htonl(0x01020304);
  dns_trie_insert_rr(trie, "example.com", a_record);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "example.com");

  dns_message_t *response_msg = dns_message_create();

  int result = dns_resolve_query(trie, &question, response_msg);
  munit_assert_int(result, ==, 0);
  munit_assert_int(response_msg->header.rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(response_msg->header.ancount, ==, 1);
  munit_assert_not_null(response_msg->answers);
  // Now access as array: answers[0] instead of answers->
  munit_assert_uint32(response_msg->answers[0]->rdata.a.address, ==, htonl(0x01020304));

  dns_message_free(response_msg);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_resolve_query_cname(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // insert CNAME
  dns_trie_insert_cname(trie, "www.example.com", "example.com", 300);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "www.example.com");

  dns_message_t *response_msg = dns_message_create();

  int result = dns_resolve_query(trie, &question, response_msg);
  munit_assert_int(result, ==, 0);
  munit_assert_int(response_msg->header.rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(response_msg->header.ancount, ==, 1);
  munit_assert_not_null(response_msg->answers);
  // Now access as array: answers[0] instead of answers->
  munit_assert_int(response_msg->answers[0]->type, ==, DNS_TYPE_CNAME);
  munit_assert_string_equal(response_msg->answers[0]->rdata.cname.cname, "example.com");

  dns_message_free(response_msg);
  dns_trie_free(trie);
  return MUNIT_OK;
}

static MunitResult test_resolve_query_multiple_records(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_trie_t *trie = dns_trie_create();

  // insert multiple A records
  dns_rr_t *a1 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a1->rdata.a.address = htonl(0x01020304);
  dns_trie_insert_rr(trie, "multi.example.com", a1);

  dns_rr_t *a2 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a2->rdata.a.address = htonl(0x05060708);
  dns_trie_insert_rr(trie, "multi.example.com", a2);

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "multi.example.com");

  dns_message_t *response_msg = dns_message_create();

  int result = dns_resolve_query(trie, &question, response_msg);
  munit_assert_int(result, ==, 0);
  munit_assert_int(response_msg->header.rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(response_msg->header.ancount, ==, 2);
  munit_assert_not_null(response_msg->answers);

  // Now access as array
  munit_assert_not_null(response_msg->answers[0]);
  munit_assert_not_null(response_msg->answers[1]);

  // Verify both IP addresses are present (order may vary due to linked list to array conversion)
  uint32_t ip1 = response_msg->answers[0]->rdata.a.address;
  uint32_t ip2 = response_msg->answers[1]->rdata.a.address;

  bool has_first_ip = (ip1 == htonl(0x01020304) || ip2 == htonl(0x01020304));
  bool has_second_ip = (ip1 == htonl(0x05060708) || ip2 == htonl(0x05060708));

  munit_assert_true(has_first_ip);
  munit_assert_true(has_second_ip);

  dns_message_free(response_msg);
  dns_trie_free(trie);
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
  int result = dns_process_query(server, &request, response);

  munit_assert_int(result, ==, 0);
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

static MunitTest tests[] = {
  {"/server_create", test_server_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/response_create", test_response_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolve_query_nxdomain", test_resolve_query_nxdomain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolve_query_found", test_resolve_query_found, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolve_query_cname", test_resolve_query_cname, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/resolve_query_multiple_records", test_resolve_query_multiple_records, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/process_query_simple", test_process_query_simple, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/server", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
