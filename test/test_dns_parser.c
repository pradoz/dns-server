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

static MunitResult test_error_response_helper(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  uint8_t buffer[512];
  uint16_t query_id = 0xABCD;

  // NULL buffer
  int result = dns_build_error_response_header(NULL,
                                           sizeof(buffer),
                                           query_id,
                                           DNS_RCODE_SERVFAIL,
                                           false);
  munit_assert_int(result, ==, -1);

  // buffer too small
  uint8_t small_buffer[8];
  result = dns_build_error_response_header(small_buffer,
                                           sizeof(small_buffer),
                                           query_id,
                                           DNS_RCODE_SERVFAIL,
                                           false);
  munit_assert_int(result, ==, -1);

  // NOTIMP without question
  result = dns_build_error_response_header(buffer,
                                               sizeof(buffer),
                                               query_id,
                                               DNS_RCODE_NOTIMP,
                                               false);
  munit_assert_int(result, ==, 12);

  dns_header_t decoded;
  dns_parse_header(buffer, sizeof(buffer), &decoded);
  munit_assert_int(decoded.id, ==, query_id);
  munit_assert_int(decoded.qr, ==, DNS_QR_RESPONSE);
  munit_assert_int(decoded.rcode, ==, DNS_RCODE_NOTIMP);
  munit_assert_int(decoded.qdcount, ==, 0);
  munit_assert_int(decoded.ancount, ==, 0);

  // FORMERR with question
  result = dns_build_error_response_header(buffer,
                                           sizeof(buffer),
                                           query_id,
                                           DNS_RCODE_FORMERROR,
                                           true);
  munit_assert_int(result, ==, 12);

  dns_parse_header(buffer, sizeof(buffer), &decoded);
  munit_assert_int(decoded.rcode, ==, DNS_RCODE_FORMERROR);
  munit_assert_int(decoded.qdcount, ==, 1);

  return MUNIT_OK;
}

static MunitResult test_parse_name_boundary_conditions(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  uint8_t buffer[256];
  size_t offset;

  // maximum length domain name (253 chars + null)
  // [63 chars].[63 chars].[63 chars].[61 chars]
  offset = 0;
  int result = dns_encode_name(buffer, sizeof(buffer), &offset,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa."
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb."
    "ccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc."
    "ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
  munit_assert_int(result, ==, 0);

  // label exactly 63 characters
  offset = 0;
  result = dns_encode_name(buffer, sizeof(buffer), &offset,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com");
  munit_assert_int(result, ==, 0);

  // label too long (64 characters), should fail
  offset = 0;
  result = dns_encode_name(buffer, sizeof(buffer), &offset,
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com");
  munit_assert_int(result, ==, -1);

  // empty label, should fail
  offset = 0;
  result = dns_encode_name(buffer, sizeof(buffer), &offset, "test..com");
  munit_assert_int(result, ==, -1);

  // buffer too small, should fail
  uint8_t small_buffer[5];
  offset = 0;
  result = dns_encode_name(small_buffer, sizeof(small_buffer), &offset, "example.com");
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_response_summary(const MunitParameter params[], void *data) {
  (void)params;
  (void)data;

  uint8_t mock_response[] = {
    // header: ID=0x1234, QR=1, RCODE=0
    0x12, 0x34, 0x81, 0x80,
    0x00, 0x01, // QDCOUNT = 1
    0x00, 0x02, // ANCOUNT = 2
    0x00, 0x01, // NSCOUNT = 1
    0x00, 0x03, // ARCOUNT = 3
  };

  dns_response_summary_t summary;
  int result = dns_parse_response_summary(mock_response, sizeof(mock_response), &summary);

  munit_assert_int(result, ==, 0);
  munit_assert_int(summary.query_id, ==, 0x1234);
  munit_assert_int(summary.rcode, ==, DNS_RCODE_NOERROR);
  munit_assert_int(summary.qdcount, ==, 1);
  munit_assert_int(summary.ancount, ==, 2);
  munit_assert_int(summary.nscount, ==, 1);
  munit_assert_int(summary.arcount, ==, 3);
  munit_assert_true(summary.is_response);

  // buffer too small
  result = dns_parse_response_summary(mock_response, 8, &summary);
  munit_assert_int(result, ==, -1);

  // NULL buffer
  result = dns_parse_response_summary(NULL, sizeof(mock_response), &summary);
  munit_assert_int(result, ==, -1);

  // NULL summary
  result = dns_parse_response_summary(mock_response, sizeof(mock_response), NULL);
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_write_uint16(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t buf[10];
  size_t offset = 0;

  munit_assert_int(dns_write_uint16(buf, sizeof(buf), &offset, 0x1234), ==, 0);
  munit_assert_size(offset, ==, 2);
  munit_assert_uint8(buf[0], ==, 0x12);
  munit_assert_uint8(buf[1], ==, 0x34);

  // buffer too small
  offset = 9;
  munit_assert_int(dns_write_uint16(buf, sizeof(buf), &offset, 0x5678), ==, -1);

  return MUNIT_OK;
}

static MunitResult test_read_uint16(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t buf[] = {0x12, 0x34, 0x56, 0x78};
  size_t offset = 0;
  uint16_t value;

  munit_assert_int(dns_read_uint16(buf, sizeof(buf), &offset, &value), ==, 0);
  munit_assert_uint16(value, ==, 0x1234);
  munit_assert_size(offset, ==, 2);

  munit_assert_int(dns_read_uint16(buf, sizeof(buf), &offset, &value), ==, 0);
  munit_assert_uint16(value, ==, 0x5678);

  // buffer overflow
  munit_assert_int(dns_read_uint16(buf, sizeof(buf), &offset, &value), ==, -1);

  return MUNIT_OK;
}

static MunitResult test_write_uint32(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t buf[10];
  size_t offset = 0;

  munit_assert_int(dns_write_uint32(buf, sizeof(buf), &offset, 0x12345678), ==, 0);
  munit_assert_size(offset, ==, 4);
  munit_assert_uint8(buf[0], ==, 0x12);
  munit_assert_uint8(buf[1], ==, 0x34);
  munit_assert_uint8(buf[2], ==, 0x56);
  munit_assert_uint8(buf[3], ==, 0x78);

  // buffer too small
  offset = 7;
  munit_assert_int(dns_write_uint32(buf, sizeof(buf), &offset, 0x9ABCDEF0), ==, -1);

  return MUNIT_OK;
}

static MunitResult test_read_uint32(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t buf[] = {0x12, 0x34, 0x56, 0x78,
                   0x9A, 0xBC, 0xDE, 0xF0};
  size_t offset = 0;
  uint32_t value;

  munit_assert_int(dns_read_uint32(buf, sizeof(buf), &offset, &value), ==, 0);
  munit_assert_uint32(value, ==, 0x12345678);
  munit_assert_size(offset, ==, 4);

  munit_assert_int(dns_read_uint32(buf, sizeof(buf), &offset, &value), ==, 0);
  munit_assert_uint32(value, ==, 0x9ABCDEF0);

  // buffer overflow
  munit_assert_int(dns_read_uint32(buf, sizeof(buf), &offset, &value), ==, -1);

  return MUNIT_OK;
}

static MunitResult test_soa_rr_encoding(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t buf[512];
  size_t offset = 0;

  dns_rr_t soa_record = {
    .type = DNS_TYPE_SOA,
    .class = DNS_CLASS_IN,
    .ttl = 3600,
  };

  strcpy(soa_record.rdata.soa.mname, "ns1.example.com");
  strcpy(soa_record.rdata.soa.rname, "admin.example.com");
  soa_record.rdata.soa.serial = 2024010101;
  soa_record.rdata.soa.refresh = 7200;
  soa_record.rdata.soa.retry = 3600;
  soa_record.rdata.soa.expire = 604800;
  soa_record.rdata.soa.minimum = 86400;

  int result = dns_encode_rr(buf, sizeof(buf), &offset, "example.com", &soa_record);
  munit_assert_int(result, ==, 0);
  munit_assert_size(offset, >, 50); // SOA records are large

  return MUNIT_OK;
}

static MunitTest tests[] = {
  {"/header_encoding", test_header_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/name_encoding", test_name_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/question_encoding", test_question_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_encoding", test_rr_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/rr_encoding_manual_verify", test_rr_encoding_manual_verify, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/full_packet_query", test_full_packet_query, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/error_response_helper", test_error_response_helper, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/name_boundary", test_parse_name_boundary_conditions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/response_summary", test_response_summary, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/write_uint16", test_write_uint16, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/read_uint16", test_read_uint16, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/write_uint32", test_write_uint32, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/read_uint32", test_read_uint32, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/soa_rr_encoding", test_soa_rr_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},

  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/parser", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
