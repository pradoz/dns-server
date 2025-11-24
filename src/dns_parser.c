#include "dns_parser.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


static int validate_label_length(size_t len) {
  return (len > 0 && len <= MAX_LABEL_LEN) ? 0 : -1;
}

static int validate_name_length(size_t len) {
  return (len <= MAX_DOMAIN_NAME) ? 0 : -1;
}

dns_message_t *dns_message_create(void) {
  dns_message_t *msg = calloc(1, sizeof(dns_message_t));
  return msg;
}

void dns_message_free(dns_message_t *msg) {
  if (!msg) return;

  free(msg->questions);

  if (msg->answers) {
    for (int i = 0; i < msg->header.ancount; ++i) {
      dns_rr_free(msg->answers[i]);
    }
    free(msg->answers);
  }
  if (msg->authority) {
    for (int i = 0; i < msg->header.nscount; ++i) {
      dns_rr_free(msg->authority[i]);
    }
    free(msg->authority);
  }
  if (msg->additional) {
    for (int i = 0; i < msg->header.arcount; ++i) {
      dns_rr_free(msg->additional[i]);
    }
    free(msg->additional);
  }

  free(msg);
}

int dns_parse_header(const uint8_t *buf, size_t len, dns_header_t *header) {
  if (len < 12) return -1;

  uint16_t id, flags, qdcount, ancount, nscount, arcount;

  memcpy(&id,      buf + 0, 2);
  memcpy(&flags,   buf + 2, 2);
  memcpy(&qdcount, buf + 4, 2);
  memcpy(&ancount, buf + 6, 2);
  memcpy(&nscount, buf + 8, 2);
  memcpy(&arcount, buf + 10, 2);

  header->id = ntohs(id);

  flags = ntohs(flags);
  header->qr     = (flags >> 15) & 0x1;
  header->opcode = (flags >> 11) & 0xF;
  header->aa     = (flags >> 10) & 0x1;
  header->tc     = (flags >> 9)  & 0x1;
  header->rd     = (flags >> 8)  & 0x1;
  header->ra     = (flags >> 7)  & 0x1;
  header->rcode  = flags         & 0xF;

  header->qdcount = ntohs(qdcount);
  header->ancount = ntohs(ancount);
  header->nscount = ntohs(nscount);
  header->arcount = ntohs(arcount);

  return 12;
}

int dns_parse_question(const uint8_t *buf, size_t len, size_t *offset, dns_question_t *question) {
  if (dns_parse_name(buf, len, offset, question->qname, MAX_DOMAIN_NAME) < 0) {
    return -1;
  }

  if (dns_read_uint16(buf, len, offset, &question->qtype) < 0) return -1;
  if (dns_read_uint16(buf, len, offset, &question->qclass) < 0) return -1;

  return 0;
}

int dns_parse_name(const uint8_t *buf, size_t len, size_t *offset, char *name, size_t name_len) {
  size_t pos = *offset;
  size_t name_pos = 0;
  size_t jump_pos = 0;
  bool jumped = false;

  const int MAX_JUMPS = 10;
  int jumps = 0;

  while (pos < len) {
    uint8_t label_len = buf[pos];

    // check for compression pointer (0xC0 = 11000000)
    if ((label_len & 0xC0) == 0xC0) {
      // next 14 bits point to another location in the packet
      if (pos + 1 >= len) return -1;

      uint16_t pointer = ((label_len & 0x3F) << 8) | buf[pos+1];

      if (!jumped) {
        jump_pos = pos + 2;
        jumped = true;
      }

      pos = pointer;
      ++jumps;

      if (jumps > MAX_JUMPS) return -1; // protect against infinite loops
      continue;
    }

    // end of name
    if (label_len == 0) {
      if (!jumped) {
        *offset = pos + 1;
      } else {
        *offset = jump_pos;
      }

      if (name_pos > 0) {
        name[name_pos-1] = '\0'; // remove trailing dot
      } else {
        name[0] = '\0';
      }

      return 0;
    }

    // regular label
    if (label_len > 63) return -1;
    if (pos + 1 + label_len >= len) return -1;
    if (name_pos + label_len + 1 >= name_len) return -1;

    ++pos;
    memcpy(name + name_pos, buf + pos, label_len);
    name_pos += label_len;
    name[name_pos++] = '.';
    pos += label_len;
  }

  return -1;
  // TODO: decide if returning the name length is useful
  // return name_pos > 0 ? name_pos - 1 : 0;
}

int dns_encode_header(uint8_t *buf, size_t len, const dns_header_t *header) {
  if (len < 12) return  -1;

  uint16_t id, flags, qdcount, ancount, nscount, arcount;

  id = htons(header->id);

  flags = 0;
  flags |= (header->qr     & 0x1) << 15;
  flags |= (header->opcode & 0xF) << 11;
  flags |= (header->aa     & 0x1) << 10;
  flags |= (header->tc     & 0x1) << 9;
  flags |= (header->rd     & 0x1) << 8;
  flags |= (header->ra     & 0x1) << 7;
  flags |= (header->rcode  & 0xF);
  flags = htons(flags);

  qdcount = htons(header->qdcount);
  ancount = htons(header->ancount);
  nscount = htons(header->nscount);
  arcount = htons(header->arcount);

  memcpy(buf +  0, &id,      2);
  memcpy(buf +  2, &flags,   2);
  memcpy(buf +  4, &qdcount, 2);
  memcpy(buf +  6, &ancount, 2);
  memcpy(buf +  8, &nscount, 2);
  memcpy(buf + 10, &arcount, 2);

  return 12;
}

int dns_encode_question(uint8_t *buf, size_t len, size_t *offset, const dns_question_t *question) {
  if (dns_encode_name(buf, len, offset, question->qname) < 0) {
    return -1;
  }

  if (dns_write_uint16(buf, len, offset, question->qtype) < 0) return -1;
  if (dns_write_uint16(buf, len, offset, question->qclass) < 0) return -1;

  return 0;
}

int dns_encode_name(uint8_t *buf, size_t len, size_t *offset, const char *name) {
  if (!buf || !offset || !name) return -1;

  size_t pos = *offset;
  const char *label_start = name;

  // root domain
  if (name[0] == '\0') {
    if (pos >= len) return -1;
    buf[pos++] = 0;
    *offset = pos;
    return 0;
  }

  size_t total_length = 0;

  while (*label_start) {
    const char *label_end = strchr(label_start, '.');
    size_t label_len;

    if (label_end) {
      label_len = label_end - label_start;
    } else {
      label_len = strlen(label_start);
    }

    // validate before encoding
    if (validate_label_length(label_len) < 0) return -1;
    if (pos + label_len + 1 >= len) return -1;

    total_length += label_len + 1;
    if (validate_name_length(total_length) < 0) return -1;

    buf[pos++] = (uint8_t)label_len;
    memcpy(buf + pos, label_start, label_len);
    pos += label_len;

    if (label_end) {
      label_start = label_end + 1;
    } else {
      break;
    }
  }

  if (pos >= len) return -1;
  buf[pos++] = 0;

  if (validate_name_length(total_length + 1) < 0) return -1;

  *offset = pos;
  return 0;
}

int dns_encode_rr(uint8_t *buf, size_t len, size_t *offset, const char *name, const dns_rr_t *rr) {
  if (dns_encode_name(buf, len, offset, name) < 0) {
    return -1;
  }
  if (*offset + 10 > len) return -1;

  if (dns_write_uint16(buf, len, offset, rr->type) < 0) return -1;
  if (dns_write_uint16(buf, len, offset, rr->class) < 0) return -1;
  if (dns_write_uint32(buf, len, offset, rr->ttl) < 0) return -1;

  size_t rdlength_offset = *offset;
  *offset += 2;  // TODO: rdlength

  size_t rdata_start = *offset;

  // encode rdata based on type
  switch (rr->type) {
    case DNS_TYPE_A:
      if (*offset + 4 > len) return -1;
      memcpy(buf + *offset, &rr->rdata.a.address, 4);
      *offset += 4;
      break;

    case DNS_TYPE_NS: // TODO
    case DNS_TYPE_CNAME: // TODO
    case DNS_TYPE_PTR: {
      const char *domain = (rr->type == DNS_TYPE_NS)
        ? rr->rdata.ns.nsdname
        : rr->rdata.cname.cname;
      if (dns_encode_name(buf, len, offset, domain) < 0) return -1;
      break;
    }

    case DNS_TYPE_SOA: {
      // SOA record format:
      // MNAME (domain name)
      // RNAME (domain name)
      // SERIAL (4 bytes)
      // REFRESH (4 bytes)
      // RETRY (4 bytes)
      // EXPIRE (4 bytes)
      // MINIMUM (4 bytes)

      if (dns_encode_name(buf, len, offset, rr->rdata.soa.mname) < 0) return -1;
      if (dns_encode_name(buf, len, offset, rr->rdata.soa.rname) < 0) return -1;
      if (*offset + 20 > len) return -1; // 5 * 4 bytes for the numbers

      uint32_t serial = htonl(rr->rdata.soa.serial);
      uint32_t refresh = htonl(rr->rdata.soa.refresh);
      uint32_t retry = htonl(rr->rdata.soa.retry);
      uint32_t expire = htonl(rr->rdata.soa.expire);
      uint32_t minimum = htonl(rr->rdata.soa.minimum);

      memcpy(buf + *offset, &serial, 4);   *offset += 4;
      memcpy(buf + *offset, &refresh, 4);  *offset += 4;
      memcpy(buf + *offset, &retry, 4);    *offset += 4;
      memcpy(buf + *offset, &expire, 4);   *offset += 4;
      memcpy(buf + *offset, &minimum, 4);  *offset += 4;
      break;
    }

    case DNS_TYPE_AAAA:
      if (*offset + 16 > len) return -1;
      memcpy(buf + *offset, &rr->rdata.aaaa.address, 16);
      *offset += 16;
      break;

    default:
      return -1;  // unsupported type
  }

  uint16_t rdlength = htons(*offset - rdata_start);
  memcpy(buf + rdlength_offset, &rdlength, 2);

  return 0;
}

int dns_build_error_response_header(uint8_t *buf, size_t capacity,
                                    uint16_t id, uint8_t rcode,
                                    bool include_question) {
  if (!buf || capacity < 12) return -1;

  dns_header_t header = {
    .id = id,
    .qr = DNS_QR_RESPONSE,
    .opcode = DNS_OPCODE_QUERY,
    .aa = 0,
    .tc = 0,
    .rd = 1,
    .ra = 0,
    .rcode = rcode,
    .qdcount = include_question ? 1 : 0,
    .ancount = 0,
    .nscount = 0,
    .arcount = 0
  };

  return dns_encode_header(buf, capacity, &header);
}

int dns_parse_response_summary(const uint8_t *buf, size_t len,
                               dns_response_summary_t *summary) {
  if (!buf || !summary || len < 12) return -1;

  dns_header_t header;
  if (dns_parse_header(buf, len, &header) < 0) return -1;

  summary->query_id = header.id;
  summary->rcode = header.rcode;
  summary->qdcount = header.qdcount;
  summary->ancount = header.ancount;
  summary->nscount = header.nscount;
  summary->arcount = header.arcount;
  summary->is_response = (header.qr == DNS_QR_RESPONSE);

  return 0;
}

int dns_write_uint16(uint8_t *buf, size_t len, size_t *offset, uint16_t value) {
  if (!buf || !offset || *offset + 2 > len) return -1;
  uint16_t network_value = htons(value);
  memcpy(buf + *offset, &network_value, 2);
  *offset += 2;
  return 0;
}

int dns_write_uint32(uint8_t *buf, size_t len, size_t *offset, uint32_t value) {
  if (!buf || !offset || *offset + 4 > len) return -1;
  uint32_t network_value = htonl(value);
  memcpy(buf + *offset, &network_value, 4);
  *offset += 4;
  return 0;
}

int dns_read_uint16(const uint8_t *buf, size_t len, size_t *offset, uint16_t *value) {
  if (!buf || !offset || !value || *offset + 2 > len) return -1;
  uint16_t network_value;
  memcpy(&network_value, buf + *offset, 2);
  *value = ntohs(network_value);
  *offset += 2;
  return 0;
}

int dns_read_uint32(const uint8_t *buf, size_t len, size_t *offset, uint32_t *value) {
  if (!buf || !offset || !value || *offset + 4 > len) return -1;
  uint32_t network_value;
  memcpy(&network_value, buf + *offset, 4);
  *value = ntohl(network_value);
  *offset += 4;
  return 0;
}
