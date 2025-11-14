#include "munit.h"
#include "dns_server.h"
#include "dns_recursive.h"
#include <string.h>
#include <arpa/inet.h>


static MunitResult test_recursive_resolver_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_recursive_resolver_t *resolver = dns_recursive_create();
  munit_assert_not_null(resolver);
  munit_assert_int(resolver->socket_fd, ==, -1);
  munit_assert_int(resolver->next_query_id, ==, 1);
  munit_assert_int(resolver->recursive_queries, ==, 0);

  dns_recursive_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_root_hints_loading(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_recursive_resolver_t *resolver = dns_recursive_create();
  munit_assert_not_null(resolver);

  int result = dns_recursive_load_root_hints(resolver);
  munit_assert_int(result, ==, 0);

  // verify some root servers were loaded
  munit_assert_string_equal(resolver->root_servers[0].name, "a.root-servers.net");
  munit_assert_true(resolver->root_servers[0].has_ipv4);
  munit_assert_int(resolver->root_servers[0].ipv4.sin_family, ==, AF_INET);
  munit_assert_int(ntohs(resolver->root_servers[0].ipv4.sin_port), ==, 53);

  dns_recursive_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_upstream_server_addition(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_upstream_list_t servers = {0};

  int result = dns_recursive_add_upstream_server(&servers, "8.8.8.8", 53);
  munit_assert_int(result, ==, 0);
  munit_assert_int(servers.server_count, ==, 1);

  result = dns_recursive_add_upstream_server(&servers, "1.1.1.1", 53);
  munit_assert_int(result, ==, 0);
  munit_assert_int(servers.server_count, ==, 2);

  // test round-robin selection
  dns_nameserver_t *server1 = dns_recursive_select_server(&servers);
  munit_assert_not_null(server1);

  dns_nameserver_t *server2 = dns_recursive_select_server(&servers);
  munit_assert_not_null(server2);
  munit_assert_ptr_not_equal(server1, server2);

  // third selection should wrap around to first server
  dns_nameserver_t *server3 = dns_recursive_select_server(&servers);
  munit_assert_ptr_equal(server1, server3);

  return MUNIT_OK;
}

static MunitResult test_socket_initialization(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_recursive_resolver_t *resolver = dns_recursive_create();
  munit_assert_not_null(resolver);

  int result = dns_recursive_init_socket(resolver);
  munit_assert_int(result, ==, 0);
  munit_assert_int(resolver->socket_fd, >=, 0);

  dns_recursive_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_query_id_generation(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_recursive_resolver_t *resolver = dns_recursive_create();
  munit_assert_not_null(resolver);

  uint16_t id1 = resolver->next_query_id++;
  uint16_t id2 = resolver->next_query_id++;
  uint16_t id3 = resolver->next_query_id++;

  munit_assert_int(id1, ==, 1);
  munit_assert_int(id2, ==, 2);
  munit_assert_int(id3, ==, 3);
  munit_assert_int(id1, !=, id2);
  munit_assert_int(id2, !=, id3);

  dns_recursive_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_query_tracking(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_recursive_resolver_t *resolver = dns_recursive_create();
  munit_assert_not_null(resolver);

  // initially, all queries should be inactive
  for (int i = 0; i < 256; i++) {
    munit_assert_int(resolver->active_queries[i].query_id, ==, 0);
  }

  // simulate tracking a query
  uint16_t query_id = 42;
  dns_recursive_query_t *query = &resolver->active_queries[query_id & 0xFF];
  query->query_id = query_id;
  strcpy(query->qname, "example.com");
  query->qtype = DNS_TYPE_A;
  query->qclass = DNS_CLASS_IN;
  query->recursion_depth = 0;

  munit_assert_int(query->query_id, ==, 42);
  munit_assert_string_equal(query->qname, "example.com");
  munit_assert_int(query->qtype, ==, DNS_TYPE_A);

  // mark as inactive
  query->query_id = 0;
  munit_assert_int(query->query_id, ==, 0);

  dns_recursive_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_backward_compatibility(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // ensure that adding recursive resolver doesn't break existing functionality
  dns_server_t *server = dns_server_create(5353);
  munit_assert_not_null(server);
  munit_assert_not_null(server->trie);
  munit_assert_not_null(server->recursive_resolver);

  // test that manual record insertion still works
  dns_rr_t *test_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  test_record->rdata.a.address = inet_addr("192.168.1.1");
  munit_assert_true(dns_trie_insert_rr(server->trie, "test.local", test_record));

  // verify record exists
  dns_rrset_t *rrset = dns_trie_lookup(server->trie, "test.local", DNS_TYPE_A);
  munit_assert_not_null(rrset);
  munit_assert_int(rrset->records->rdata.a.address, ==, inet_addr("192.168.1.1"));

  dns_server_free(server);
  return MUNIT_OK;
}

static MunitResult test_response_forwarding(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_recursive_resolver_t *resolver = dns_recursive_create();
  munit_assert_not_null(resolver);

  // mock query
  uint16_t query_id = 42;
  dns_recursive_query_t *query = &resolver->active_queries[query_id & 0xFF];
  query->query_id = query_id;
  strcpy(query->qname, "example.com");
  query->qtype = DNS_TYPE_A;
  query->qclass = DNS_CLASS_IN;
  query->original_id = 1234;
  query->start_time = time(NULL);

  // error response should be sent provided an invalid socket
  resolver->main_server_socket = -1;
  int result = dns_recursive_send_error_response(resolver, query, DNS_RCODE_SERVFAIL);
  munit_assert_int(result, ==, -1);

  dns_recursive_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_authority_parsing(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // Create a mock DNS response with authority section
  uint8_t mock_response[] = {
    // header: ID=1, QR=1, OPCODE=0, AA=0, TC=0, RD=1, RA=1, RCODE=0
    0x00, 0x01, 0x81, 0x80,
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x00, // ANCOUNT = 0
    0x00, 0x01, // NSCOUNT = 1
    0x00, 0x00, // ARCOUNT = 0

    // question: example.com A IN
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, // type A
    0x00, 0x01, // class IN

    // authority: com. NS a.gtld-servers.net.
    0x03, 'c', 'o', 'm', 0x00, // name: com.
    0x00, 0x02, // type NS
    0x00, 0x01, // class IN
    0x00, 0x00, 0x0E, 0x10, // TTL
    0x00, 0x14, // rdlength = 20
    // rdata: a.gtld-servers.net.
    0x01, 'a', 0x0C, 'g', 't', 'l', 'd', '-', 's', 'e', 'r', 'v', 'e', 'r', 's',
    0x03, 'n', 'e', 't', 0x00
  };

  dns_upstream_list_t servers = {0};

  int result = dns_extract_nameservers_from_authority(mock_response, sizeof(mock_response), &servers);

  // should extract or provide fallback servers with no A records in additional section
  munit_assert_int(result, >, 0);
  munit_assert_int(servers.server_count, >=, 2);

  return MUNIT_OK;
}

static MunitResult test_query_timeout_cleanup(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_recursive_resolver_t *resolver = dns_recursive_create();
  munit_assert_not_null(resolver);

  // expired query
  uint16_t query_id = 100;
  dns_recursive_query_t *query = &resolver->active_queries[query_id & 0xFF];
  query->query_id = query_id;
  strcpy(query->qname, "expired.example.com");
  query->start_time = time(NULL) - (DNS_RECURSIVE_TIMEOUT_SEC + 10); // expired

  // fresh query
  uint16_t query_id2 = 101;
  dns_recursive_query_t *query2 = &resolver->active_queries[query_id2 & 0xFF];
  query2->query_id = query_id2;
  strcpy(query2->qname, "fresh.example.com");
  query2->start_time = time(NULL);

  resolver->main_server_socket = -1;

  int cleaned = dns_recursive_cleanup_expired_queries(resolver);
  munit_assert_int(cleaned, ==, 1);

  // expired query should be marked inactive
  munit_assert_int(query->query_id, ==, 0);

  // fresh query should still be active
  munit_assert_int(query2->query_id, ==, query_id2);

  dns_recursive_free(resolver);
  return MUNIT_OK;
}

static MunitResult test_full_integration(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // recursive resolver integrated with main server
  dns_server_t *server = dns_server_create(5353);
  munit_assert_not_null(server);
  munit_assert_not_null(server->recursive_resolver);
  munit_assert_true(server->enable_recursion);

  // recursive resolver can reference main socket
  int test_socket = 999;
  int result = dns_recursive_set_main_socket(server->recursive_resolver, test_socket);
  munit_assert_int(result, ==, 0);
  munit_assert_int(server->recursive_resolver->main_server_socket, ==, test_socket);

  dns_server_free(server);
  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/create", test_recursive_resolver_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/root_hints", test_root_hints_loading, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/upstream_servers", test_upstream_server_addition, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/socket_init", test_socket_initialization, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/query_id_generation", test_query_id_generation, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/query_tracking", test_query_tracking, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/backward_compatibility", test_backward_compatibility, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/response_forwarding", test_response_forwarding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/authority_parsing", test_authority_parsing, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/timeout_cleanup", test_query_timeout_cleanup, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/full_integration", test_full_integration, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/recursive", tests, NULL, 1, MUNIT_TEST_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
