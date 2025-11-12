#include "munit.h"
#include "dns_parser.h"
#include <string.h>
#include <arpa/inet.h>


static MunitResult test_header_encoding(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_header_t header = {
    .id = 0x1234,
    .qr = DNS_QR_QUERY,
    .opcode = DNS_OPCODE_QUERY,
    .aa = 0,
    .tc = 0,
    .rd = 1,
    .ra = 0,
    .rcode = DNS_RCODE_NOERROR,
    .qdcount = 1,
    .ancount = 0,
    .nscount = 0,
    .arcount = 0
  };

  uint8_t buffer[12];
  int result = dns_encode_header(buffer, sizeof(buffer), &header);
  munit_assert_int(result, ==, 12);

  dns_header_t decoded;
  result = dns_parse_header(buffer, sizeof(buffer), &decoded);
  munit_assert_int(result, ==, 12);

  munit_assert_int(decoded.id, ==, header.id);

  munit_assert_int(decoded.qr, ==, header.qr);
  munit_assert_int(decoded.opcode, ==, header.opcode);
  munit_assert_int(decoded.aa, ==, header.aa);
  munit_assert_int(decoded.tc, ==, header.tc);
  munit_assert_int(decoded.rd, ==, header.rd);
  munit_assert_int(decoded.ra, ==, header.ra);

  munit_assert_int(decoded.qdcount, ==, header.qdcount);
  munit_assert_int(decoded.ancount, ==, header.ancount);
  munit_assert_int(decoded.nscount, ==, header.nscount);
  munit_assert_int(decoded.arcount, ==, header.arcount);

  return MUNIT_OK;
}

static MunitResult test_name_encoding(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  uint8_t buffer[256];
  size_t offset = 0;

  // encode
  int result = dns_encode_name(buffer, sizeof(buffer), &offset, "www.example.com");
  munit_assert_int(result, ==, 0);
  munit_assert_int(offset, >, 0);

  // decode
  size_t decode_offset = 0;
  char name[MAX_DOMAIN_NAME];
  result = dns_parse_name(buffer, offset, &decode_offset, name, sizeof(name));
  munit_assert_int(result, ==, 0);
  munit_assert_int(strcmp(name, "www.example.com"), ==, 0);

  return MUNIT_OK;
}

static MunitResult test_question_encoding(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN,
  };
  strcpy(question.qname, "example.com");

  uint8_t buffer[256];
  size_t offset = 0;

  // encode
  int result = dns_encode_question(buffer, sizeof(buffer), &offset, &question);
  munit_assert_int(result, ==, 0);
  munit_assert_int(offset, >, 0);

  // decode
  size_t decode_offset = 0;
  dns_question_t decoded;
  result = dns_parse_question(buffer, offset, &decode_offset, &decoded);
  munit_assert_int(result, ==, 0);
  munit_assert_int(strcmp(decoded.qname, "example.com"), ==, 0);
  munit_assert_int(decoded.qtype, ==, DNS_TYPE_A);
  munit_assert_int(decoded.qclass, ==, DNS_CLASS_IN);

  return MUNIT_OK;
}

static MunitResult test_rr_encoding(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  uint8_t buffer[256];
  size_t offset = 0;
  int result;

  // A record
  dns_rr_t a_record = {
    .type = DNS_TYPE_A,
    .class = DNS_CLASS_IN,
    .ttl = 3600,
    .rdata.a.address = htonl(0x08080808)  // 8.8.8.8 in network byte order
  };

  // encode
  result = dns_encode_rr(buffer, sizeof(buffer), &offset, "google.com", &a_record);
  munit_assert_int(result, ==, 0);
  munit_assert_int(offset, >, 0);

  // CNAME  record
  offset = 0;
  dns_rr_t cname_record = {
    .type = DNS_TYPE_CNAME,
    .class = DNS_CLASS_IN,
    .ttl = 1800,
  };
  strcpy(cname_record.rdata.cname.cname, "www.example.com");

  result = dns_encode_rr(buffer, sizeof(buffer), &offset, "alias.example.com", &cname_record);
  munit_assert_int(result, ==, 0);
  munit_assert_int(offset, >, 0);

  // AAAA record
  offset = 0;
  dns_rr_t aaaa_record = {
    .type = DNS_TYPE_AAAA,
    .class = DNS_CLASS_IN,
    .ttl = 7200,
  };

  // IPv6 address: 2001:4860:4860::8888
  uint8_t ipv6_addr[16] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88};
  memcpy(aaaa_record.rdata.aaaa.address, ipv6_addr, 16);

  result = dns_encode_rr(buffer, sizeof(buffer), &offset, "ipv6.example.com", &aaaa_record);
  munit_assert_int(result, ==, 0);
  munit_assert_int(offset, >, 0);

  // NS record
  offset = 0;
  dns_rr_t ns_record = {
    .type = DNS_TYPE_NS,
    .class = DNS_CLASS_IN,
    .ttl = 86400,
  };
  strcpy(ns_record.rdata.ns.nsdname, "ns1.example.com");

  result = dns_encode_rr(buffer, sizeof(buffer), &offset, "example.com", &ns_record);
  munit_assert_int(result, ==, 0);
  munit_assert_int(offset, >, 0);

  // unsupported type, should fail
  offset = 0;
  dns_rr_t unsupported_record = {
    .type = 999,
    .class = DNS_CLASS_IN,
    .ttl = 3600,
  };

  result = dns_encode_rr(buffer, sizeof(buffer), &offset, "test.com", &unsupported_record);
  munit_assert_int(result, ==, -1);

  // buffer too small, should fail
  offset = 0;
  uint8_t small_buffer[5];
  result = dns_encode_rr(small_buffer, sizeof(small_buffer), &offset, "test.com", &a_record);
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_rr_encoding_manual_verify(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  uint8_t buffer[256];
  size_t offset = 0;

  dns_rr_t a_record = {
    .type = DNS_TYPE_A,
    .class = DNS_CLASS_IN,
    .ttl = 3600,
    .rdata.a.address = htonl(0x08080808)  // 8.8.8.8
  };

  int result = dns_encode_rr(buffer, sizeof(buffer), &offset, "test.com", &a_record);
  munit_assert_int(result, ==, 0);

  // manually verify the structure:
  // [4]test[3]com[0] = 10 bytes for name
  // type (2 bytes) + class (2 bytes) + ttl (4 bytes) + rdlength (2 bytes) = 10 bytes
  // rdata (4 bytes for A record) = 4 bytes
  // Total expected: 10 + 10 + 4 = 24 bytes

  munit_assert_int(offset, ==, 24);

  // verify the IP addr is at the end
  uint32_t stored_ip;
  memcpy(&stored_ip, buffer + offset - 4, 4);
  munit_assert_int(stored_ip, ==, htonl(0x08080808));

  return MUNIT_OK;
}

static MunitResult test_full_packet_query(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  uint8_t buffer[512];
  size_t offset = 0;

  // encode header
  dns_header_t header = {
    .id = 0xABCD,
    .qr = DNS_QR_QUERY,
    .opcode = DNS_OPCODE_QUERY,
    .rd = 1,
    .qdcount = 1,
    .ancount = 0,
    .nscount = 0,
    .arcount = 0
  };

  dns_encode_header(buffer, sizeof(buffer), &header);
  offset = 12;

  // encode question
  dns_question_t question = {
    .qtype = DNS_TYPE_A,
    .qclass = DNS_CLASS_IN
  };
  strcpy(question.qname, "www.example.com");

  dns_encode_question(buffer, sizeof(buffer), &offset, &question);
  size_t packet_size = offset;

  // decode header
  dns_header_t decoded_header;
  dns_parse_header(buffer, packet_size, &decoded_header);
  munit_assert_int32(decoded_header.id, ==, header.id);
  munit_assert_int(decoded_header.qdcount, ==, header.qdcount);

  // decode question
  offset = 12;
  dns_question_t decoded_question;
  dns_parse_question(buffer, packet_size, &offset, &decoded_question);
  munit_assert_int(strcmp(decoded_question.qname, question.qname), ==, 0);
  munit_assert_int(decoded_question.qtype, ==, question.qtype);
  munit_assert_int(decoded_question.qclass, ==, question.qclass);


  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/header_encoding", test_header_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/name_encoding", test_name_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/question_encoding", test_question_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_encoding", test_rr_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_encoding_manual_verify", test_rr_encoding_manual_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/full_packet_query", test_full_packet_query, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},

  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/parser", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
