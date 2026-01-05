#include "munit.h"
#include "dns_parser.h"
#include <stdio.h>
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

  // a record
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

  // cNAME  record
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

  // aAAA record
  offset = 0;
  dns_rr_t aaaa_record = {
    .type = DNS_TYPE_AAAA,
    .class = DNS_CLASS_IN,
    .ttl = 7200,
  };

  // iPv6 address: 2001:4860:4860::8888
  uint8_t ipv6_addr[16] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88};
  memcpy(aaaa_record.rdata.aaaa.address, ipv6_addr, 16);

  result = dns_encode_rr(buffer, sizeof(buffer), &offset, "ipv6.example.com", &aaaa_record);
  munit_assert_int(result, ==, 0);
  munit_assert_int(offset, >, 0);

  // nS record
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
  // total expected: 10 + 10 + 4 = 24 bytes

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

  // nULL buffer
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

  // nOTIMP without question
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

  // fORMERR with question
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

static MunitResult test_name_boundary_conditions(const MunitParameter params[], void *data) {
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
    0x00, 0x01, // qDCOUNT = 1
    0x00, 0x02, // aNCOUNT = 2
    0x00, 0x01, // nSCOUNT = 1
    0x00, 0x03, // aRCOUNT = 3
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

  // nULL buffer
  result = dns_parse_response_summary(NULL, sizeof(mock_response), &summary);
  munit_assert_int(result, ==, -1);

  // nULL summary
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
  munit_assert_size(offset, >, 50); // sOA records are large

  return MUNIT_OK;
}

static MunitResult test_empty_packet(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  dns_header_t header;

  int result = dns_parse_header(NULL, 0, &header);
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_truncated_header(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  // only 8 bytes when 12 are required
  uint8_t truncated[] = {0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00};
  dns_header_t header;

  int result = dns_parse_header(truncated, sizeof(truncated), &header);
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_compression_pointer_loop(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  // packet with compression pointer pointing to itself
  uint8_t loop_packet[] = {
    // header
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // name with compression pointer to itself at offset 12
    0xC0, 0x0C
  };

  size_t offset = 12;
  char name[MAX_DOMAIN_NAME];

  int result = dns_parse_name(loop_packet, sizeof(loop_packet), &offset, name, sizeof(name));
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_compression_pointer_forward(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  // compression pointer pointing forward (invalid)
  uint8_t forward_ptr[] = {
    // header
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // compression pointer after the packet at offset 20 (ends at 12)
    0xC0, 0x14
  };

  size_t offset = 12;
  char name[MAX_DOMAIN_NAME];

  int result = dns_parse_name(forward_ptr, sizeof(forward_ptr), &offset, name, sizeof(name));
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_label_too_long(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t long_label[80] = {
    // header
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // label length 64 (max is 63)
    0x40
  };
  // fill with 'a's
  memset(long_label + 13, 'a', 64);
  long_label[77] = 0x00;  // end of name

  size_t offset = 12;
  char name[MAX_DOMAIN_NAME];

  int result = dns_parse_name(long_label, sizeof(long_label), &offset, name, sizeof(name));
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_name_too_long(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  // build a packet with name >255 chars (using multiple 63-char labels)
  uint8_t long_name_packet[400];
  memset(long_name_packet, 0, sizeof(long_name_packet));

  // header
  memcpy(long_name_packet, "\x12\x34\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00", 12);

  size_t pos = 12;
  // 5 labels of 63 chars each = 315 chars (too long)
  for (int i = 0; i < 5 && pos < sizeof(long_name_packet) - 70; i++) {
    long_name_packet[pos++] = 63;  // label length
    memset(long_name_packet + pos, 'a', 63);
    pos += 63;
  }
  long_name_packet[pos++] = 0;  // end of name

  size_t offset = 12;
  char name[MAX_DOMAIN_NAME];

  int result = dns_parse_name(long_name_packet, pos, &offset, name, sizeof(name));
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_encode_name_boundary(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t buffer[256];
  size_t offset;

  // exactly 63-char label
  char label_63[64];
  memset(label_63, 'a', 63);
  label_63[63] = '\0';

  char domain_63[80];
  snprintf(domain_63, sizeof(domain_63), "%s.com", label_63);

  offset = 0;
  int result = dns_encode_name(buffer, sizeof(buffer), &offset, domain_63);
  munit_assert_int(result, ==, 0);

  // 64-char label - should fail
  char label_64[65];
  memset(label_64, 'a', 64);
  label_64[64] = '\0';

  char domain_64[80];
  snprintf(domain_64, sizeof(domain_64), "%s.com", label_64);

  offset = 0;
  result = dns_encode_name(buffer, sizeof(buffer), &offset, domain_64);
  munit_assert_int(result, ==, -1);

  return MUNIT_OK;
}

static MunitResult test_encode_buffer_too_small(const MunitParameter params[], void *data) {
  (void)params; (void)data;

  uint8_t small_buffer[5];
  size_t offset = 0;

  int result = dns_encode_name(small_buffer, sizeof(small_buffer), &offset, "example.com");
  munit_assert_int(result, ==, -1);

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
  {"/name_boundary", test_name_boundary_conditions, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/response_summary", test_response_summary, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/write_uint16", test_write_uint16, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/read_uint16", test_read_uint16, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/write_uint32", test_write_uint32, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/read_uint32", test_read_uint32, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/soa_rr_encoding", test_soa_rr_encoding, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/empty_packet", test_empty_packet, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/truncated_header", test_truncated_header, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/compression_pointer_loop", test_compression_pointer_loop, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/compression_pointer_forward", test_compression_pointer_forward, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/label_too_long", test_label_too_long, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/name_too_long", test_name_too_long, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/encode_name_boundary", test_encode_name_boundary, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
  {"/encode_buffer_too_small", test_encode_buffer_too_small, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},

  {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL}
};

static const MunitSuite suite = {"/parser", tests, NULL, 1, MUNIT_SUITE_OPTION_NONE};

int main(int argc, char *argv[]) {
  return munit_suite_main(&suite, NULL, argc, argv);
}
