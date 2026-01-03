#include "munit.h"
#include "dns_records.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>


static MunitResult test_rr_create(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rr_t *rr = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  munit_assert_not_null(rr);
  munit_assert_null(rr->next);
  munit_assert_int(rr->type, ==, DNS_TYPE_A);
  munit_assert_int(rr->class, ==, DNS_CLASS_IN);
  munit_assert_int(rr->ttl, ==, 300);

  dns_rr_free(rr);

  return MUNIT_OK;
}

static MunitResult test_rr_create_a(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // network byte order address
  dns_rr_t *rr = dns_rr_create_a(htonl(0x7F000001), 300);
  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_A);
  munit_assert_uint32(rr->rdata.a.address, ==, htonl(0x7F000001));

  dns_rr_free(rr);
  return MUNIT_OK;
}

static MunitResult test_rr_create_a_str(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // valid IP
  dns_rr_t *rr = dns_rr_create_a_str("192.168.1.1", 300);
  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_A);
  munit_assert_uint32(rr->rdata.a.address, ==, inet_addr("192.168.1.1"));
  dns_rr_free(rr);

  // invalid IP
  dns_rr_t *rr_invalid = dns_rr_create_a_str("not.an.ip", 300);
  munit_assert_null(rr_invalid);

  // NULL
  dns_rr_t *rr_null = dns_rr_create_a_str(NULL, 300);
  munit_assert_null(rr_null);

  return MUNIT_OK;
}

static MunitResult test_rr_create_aaaa_str(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rr_t *rr = dns_rr_create_aaaa_str("2001:db8::1", 300);
  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_AAAA);

  // valid address
  struct in6_addr expected;
  inet_pton(AF_INET6, "2001:db8::1", &expected);
  munit_assert_memory_equal(16, rr->rdata.aaaa.address, expected.s6_addr);

  dns_rr_free(rr);

  // invalid address
  dns_rr_t *rr_invalid = dns_rr_create_aaaa_str("not::valid::ipv6", 300);
  munit_assert_null(rr_invalid);

  // NULL
  dns_rr_t *rr_null = dns_rr_create_aaaa_str(NULL, 300);
  munit_assert_null(rr_null);

  return MUNIT_OK;
}

static MunitResult test_rr_create_ns(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rr_t *rr = dns_rr_create_ns("ns1.example.com", 3600);
  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_NS);
  munit_assert_string_equal(rr->rdata.ns.nsdname, "ns1.example.com");

  dns_rr_free(rr);

  // NULL
  dns_rr_t *rr_null = dns_rr_create_ns(NULL, 3600);
  munit_assert_null(rr_null);

  return MUNIT_OK;
}

static MunitResult test_rr_create_cname(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rr_t *rr = dns_rr_create_cname("www.example.com", 300);
  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_CNAME);
  munit_assert_string_equal(rr->rdata.cname.cname, "www.example.com");

  dns_rr_free(rr);
  return MUNIT_OK;
}

static MunitResult test_rr_create_mx(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rr_t *rr = dns_rr_create_mx(10, "mail.example.com", 3600);
  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_MX);
  munit_assert_int(rr->rdata.mx.preference, ==, 10);
  munit_assert_string_equal(rr->rdata.mx.exchange, "mail.example.com");

  dns_rr_free(rr);
  return MUNIT_OK;
}

static MunitResult test_rr_create_txt(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rr_t *rr = dns_rr_create_txt("v=spf1 include:example.com ~all", 3600);
  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_TXT);
  munit_assert_string_equal(rr->rdata.txt.text, "v=spf1 include:example.com ~all");
  munit_assert_size(rr->rdata.txt.length, ==, strlen("v=spf1 include:example.com ~all"));

  dns_rr_free(rr);
  return MUNIT_OK;
}

static MunitResult test_rr_create_soa(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rr_t *rr = dns_rr_create_soa(
    "ns1.example.com",
    "admin.example.com",
    2024010101,
    7200,
    3600,
    604800,
    86400,
    3600
  );

  munit_assert_not_null(rr);
  munit_assert_int(rr->type, ==, DNS_TYPE_SOA);
  munit_assert_string_equal(rr->rdata.soa.mname, "ns1.example.com");
  munit_assert_string_equal(rr->rdata.soa.rname, "admin.example.com");
  munit_assert_uint32(rr->rdata.soa.serial, ==, 2024010101);
  munit_assert_uint32(rr->rdata.soa.refresh, ==, 7200);
  munit_assert_uint32(rr->rdata.soa.retry, ==, 3600);
  munit_assert_uint32(rr->rdata.soa.expire, ==, 604800);
  munit_assert_uint32(rr->rdata.soa.minimum, ==, 86400);

  dns_rr_free(rr);
  return MUNIT_OK;
}


static MunitResult test_rrset_add(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rrset_t *rrset = dns_rrset_create(DNS_TYPE_A, 300);
  munit_assert_not_null(rrset);

  // adding wrong record type should fail
  dns_rr_t *rr_aaaa = dns_rr_create_aaaa_str("2001:db8::1", 300);
  munit_assert_false(dns_rrset_add(rrset, rr_aaaa));
  dns_rr_free(rr_aaaa);
  munit_assert_int(rrset->count, ==, 0);

  // adding correct record type should succeed
  dns_rr_t *rr1 = dns_rr_create_a_str("192.168.1.1", 300);
  munit_assert_true(dns_rrset_add(rrset, rr1));
  munit_assert_int(rrset->count, ==, 1);

  dns_rr_t *rr2 = dns_rr_create_a_str("192.168.1.2", 300);
  munit_assert_true(dns_rrset_add(rrset, rr2));
  munit_assert_int(rrset->count, ==, 2);

  // adding record with different TTL should fail
  dns_rr_t *rr_ttl = dns_rr_create_a_str("192.168.1.3", 900);
  munit_assert_false(dns_rrset_add(rrset, rr_ttl));
  dns_rr_free(rr_ttl);

  dns_rrset_free(rrset);
  return MUNIT_OK;
}

static MunitResult test_domain_normalization(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

    char output[MAX_DOMAIN_NAME];

    dns_normalize_domain("EXAMPLE.COM", output);
    munit_assert_int(strcmp(output, "example.com"), ==, 0);

    dns_normalize_domain("Example.Com", output);
    munit_assert_int(strcmp(output, "example.com"), ==, 0);

    dns_normalize_domain("example.com.", output);
    munit_assert_int(strcmp(output, "example.com"), ==, 0);

    dns_normalize_domain("www.example.com.", output);
    munit_assert_int(strcmp(output, "www.example.com"), ==, 0);

    dns_normalize_domain("WWW.EXAMPLE.COM", output);
    munit_assert_int(strcmp(output, "www.example.com"), ==, 0);

  return MUNIT_OK;
}

static MunitResult test_is_subdomain(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  munit_assert_true(dns_is_subdomain("www.example.com", "example.com"));
  munit_assert_true(dns_is_subdomain("example.com", "example.com"));
  munit_assert_true(dns_is_subdomain("sub.www.example.com", "example.com"));
  munit_assert_false(dns_is_subdomain("example.com", "www.example.com"));
  munit_assert_false(dns_is_subdomain("other.com", "example.com"));

  return MUNIT_OK;
}

static MunitResult test_null_pointer_safety(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  // free with NULL should not crash
  dns_rr_free(NULL);
  dns_rrset_free(NULL);

  // helpers with NULL should return NULL
  munit_assert_null(dns_rr_create_a_str(NULL, 300));
  munit_assert_null(dns_rr_create_aaaa_str(NULL, 300));
  munit_assert_null(dns_rr_create_ns(NULL, 300));
  munit_assert_null(dns_rr_create_cname(NULL, 300));
  munit_assert_null(dns_rr_create_mx(10, NULL, 300));
  munit_assert_null(dns_rr_create_txt(NULL, 300));
  munit_assert_null(dns_rr_create_soa(NULL, "rname", 1, 1, 1, 1, 1, 300));
  munit_assert_null(dns_rr_create_soa("mname", NULL, 1, 1, 1, 1, 1, 300));

  // rrset_add with NULL
  dns_rr_t *rr = dns_rr_create_a_str("1.2.3.4", 300);
  munit_assert_false(dns_rrset_add(NULL, rr));
  dns_rr_free(rr);

  dns_rrset_t *rrset = dns_rrset_create(DNS_TYPE_A, 300);
  munit_assert_false(dns_rrset_add(rrset, NULL));
  dns_rrset_free(rrset);

  // normalize with NULL
  char output[MAX_DOMAIN_NAME];
  output[0] = 'X';
  dns_normalize_domain(NULL, output);
  munit_assert_char(output[0], ==, '\0');

  dns_normalize_domain("test.com", NULL);  // should not crash

  // subdomain with NULL
  munit_assert_false(dns_is_subdomain(NULL, "example.com"));
  munit_assert_false(dns_is_subdomain("www.example.com", NULL));
  munit_assert_false(dns_is_subdomain(NULL, NULL));

  return MUNIT_OK;
}

static MunitResult test_safe_strncpy(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  char dest[10];

  dns_safe_strncpy(dest, "hello", sizeof(dest));
  munit_assert_string_equal(dest, "hello");

  // truncated
  dns_safe_strncpy(dest, "verylongstring", sizeof(dest));
  munit_assert_size(strlen(dest), ==, 9);
  munit_assert_char(dest[9], ==, '\0');

  // NULL src
  dest[0] = 'X';
  dns_safe_strncpy(dest, NULL, sizeof(dest));
  munit_assert_char(dest[0], ==, '\0');

  // NULL dst - should not crash
  dns_safe_strncpy(NULL, "test", 10);

  // zero size - should not crash
  dns_safe_strncpy(dest, "test", 0);

  return MUNIT_OK;
}

static MunitResult test_safe_strncpy_check(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  char dest[10];

  int result = dns_safe_strncpy_check(dest, "hello", sizeof(dest));
  munit_assert_int(result, ==, 5);
  munit_assert_string_equal(dest, "hello");

  // truncated returns -1
  result = dns_safe_strncpy_check(dest, "verylongstring", sizeof(dest));
  munit_assert_int(result, ==, -1);
  munit_assert_size(strlen(dest), ==, 9);

  // empty string - should not crash
  result = dns_safe_strncpy_check(dest, "", sizeof(dest));
  munit_assert_int(result, ==, 0);
  munit_assert_string_equal(dest, "");

  return MUNIT_OK;
}


static MunitTest tests[] = {
  {"/rr_create", test_rr_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_a", test_rr_create_a, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_a_str", test_rr_create_a_str, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_aaaa_str", test_rr_create_aaaa_str, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_ns", test_rr_create_ns, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_cname", test_rr_create_cname, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_mx", test_rr_create_mx, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_txt", test_rr_create_txt, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_create_soa", test_rr_create_soa, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rrset_add", test_rrset_add, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/domain_normalization", test_domain_normalization, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/is_subdomain", test_is_subdomain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/null_pointer_safety", test_null_pointer_safety, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/safe_strncpy", test_safe_strncpy, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/safe_strncpy_check", test_safe_strncpy_check, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/records", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
