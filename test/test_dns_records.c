#include "munit.h"
#include "dns_records.h"
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

static MunitResult test_rrset_add(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_rrset_t *rrset = dns_rrset_create(DNS_TYPE_A, 300);
  munit_assert_not_null(rrset);
  munit_assert_int(rrset->type, ==, DNS_TYPE_A);
  munit_assert_int(rrset->ttl, ==, 300);
  munit_assert_int(rrset->count, ==, 0);

  // adding wrong record type should fail
  dns_rr_t *rr_aaaa = dns_rr_create(DNS_TYPE_AAAA, DNS_CLASS_IN, 300);
  rr_aaaa->rdata.a.address = 0x01010101;
  munit_assert_false(dns_rrset_add(rrset, rr_aaaa));
  munit_assert_int(rrset->count, ==, 0);

  dns_rr_t *rr1 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  rr1->rdata.a.address = 0x01020304;
  munit_assert_true(dns_rrset_add(rrset, rr1));
  munit_assert_int(rrset->count, ==, 1);

  dns_rr_t *rr2 = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  rr2->rdata.a.address = 0x05060708;
  munit_assert_true(dns_rrset_add(rrset, rr2));
  munit_assert_int(rrset->count, ==, 2);

  // adding record with different TTL should fail
  dns_rr_t *rr_ttl_wrong = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 900);
  rr_ttl_wrong->rdata.a.address = 0x02020202;
  munit_assert_false(dns_rrset_add(rrset, rr_ttl_wrong));
  munit_assert_int(rrset->count, ==, 2);


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

static MunitTest tests[] = {
  {"/rr_create", test_rr_create, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rrset_add", test_rrset_add, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/domain_normalization", test_domain_normalization, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/is_subdomain", test_is_subdomain, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/records", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
