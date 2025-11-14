#include "dns_parser.h"
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>


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

int dns_parse_header(const uint8_t *buffer, size_t len, dns_header_t *header) {
  if (len < 12) return -1;

  uint16_t id, flags, qdcount, ancount, nscount, arcount;

  memcpy(&id,      buffer + 0, 2);
  memcpy(&flags,   buffer + 2, 2);
  memcpy(&qdcount, buffer + 4, 2);
  memcpy(&ancount, buffer + 6, 2);
  memcpy(&nscount, buffer + 8, 2);
  memcpy(&arcount, buffer + 10, 2);

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

int dns_parse_question(const uint8_t *buffer, size_t len, size_t *offset, dns_question_t *question) {
  if (dns_parse_name(buffer, len, offset, question->qname, MAX_DOMAIN_NAME) < 0) {
    return -1;
  }

  if (*offset + 4 > len) return -1;

  uint16_t qtype, qclass;

  memcpy(&qtype, buffer + *offset, 2);
  *offset += 2;
  memcpy(&qclass, buffer + *offset, 2);
  *offset += 2;

  question->qtype = ntohs(qtype);
  question->qclass = ntohs(qclass);

  return 0;
}

int dns_parse_name(const uint8_t *buffer, size_t len, size_t *offset, char *name, size_t name_len) {
  size_t pos = *offset;
  size_t name_pos = 0;
  size_t jump_pos = 0;
  bool jumped = false;

  const int MAX_JUMPS = 10;
  int jumps = 0;

  while (pos < len) {
    uint8_t label_len = buffer[pos];

    // check for compression pointer (0xC0 = 11000000)
    if ((label_len & 0xC0) == 0xC0) {
      // next 14 bits point to another location in the packet
      if (pos + 1 >= len) return -1;

      uint16_t pointer = ((label_len & 0x3F) << 8) | buffer[pos+1];

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
    memcpy(name + name_pos, buffer + pos, label_len);
    name_pos += label_len;
    name[name_pos++] = '.';
    pos += label_len;
  }

  return -1;
  // TODO: decide if returning the name length is useful
  // return name_pos > 0 ? name_pos - 1 : 0;
}

int dns_encode_header(uint8_t *buffer, size_t len, const dns_header_t *header) {
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

  memcpy(buffer +  0, &id,      2);
  memcpy(buffer +  2, &flags,   2);
  memcpy(buffer +  4, &qdcount, 2);
  memcpy(buffer +  6, &ancount, 2);
  memcpy(buffer +  8, &nscount, 2);
  memcpy(buffer + 10, &arcount, 2);

  return 12;
}

int dns_encode_question(uint8_t *buffer, size_t len, size_t *offset, const dns_question_t *question) {
  if (dns_encode_name(buffer, len, offset, question->qname) < 0) {
    return -1;
  }

  if (*offset + 4 > len) return -1;

  uint16_t qtype, qclass;

  qtype = htons(question->qtype);
  qclass = htons(question->qclass);

  memcpy(buffer + *offset, &qtype,  2);
  *offset += 2;
  memcpy(buffer + *offset, &qclass, 2);
  *offset += 2;

  return 0;
}

int dns_encode_name(uint8_t *buffer, size_t len, size_t *offset, const char *name) {
  size_t pos = *offset;
  const char *label_start = name;

  // root domain
  if (name[0] == '\0') {
    if (pos >= len) return -1;
    buffer[pos++] = 0;
    *offset = pos;
    return 0;
  }

  while (*label_start) {
    const char *label_end = strchr(label_start, '.');
    size_t label_len;

    if (label_end) {
      label_len = label_end - label_start;
    } else {
      label_len = strlen(label_start);
    }

    if (label_len > MAX_LABEL_LEN || label_len == 0) return -1;
    if (pos + label_len + 1 >= len) return -1;

    buffer[pos++] = label_len;
    memcpy(buffer + pos, label_start, label_len);
    pos += label_len;

    if (label_end) {
      label_start = label_end + 1;
    } else {
      break;
    }
  }

  if (pos >= len) return -1;

  buffer[pos++] = 0;
  *offset = pos;
  return 0;
}

int dns_encode_rr(uint8_t *buffer, size_t len, size_t *offset, const char *name, const dns_rr_t *rr) {
  if (dns_encode_name(buffer, len, offset, name) < 0) {
    return -1;
  }
  if (*offset + 10 > len) return -1;

  uint16_t type, class;
  uint32_t ttl;

  type = htons(rr->type);
  class = htons(rr->class);
  ttl = htonl(rr->ttl);

  memcpy(buffer + *offset, &type,  2);
  *offset += 2;
  memcpy(buffer + *offset, &class, 2);
  *offset += 2;
  memcpy(buffer + *offset, &ttl,   4);
  *offset += 4;

  size_t rdlength_offset = *offset;
  *offset += 2;  // TODO: rdlength

  size_t rdata_start = *offset;

  // encode rdata based on type
  switch (rr->type) {
    case DNS_TYPE_A:
      if (*offset + 4 > len) return -1;
      memcpy(buffer + *offset, &rr->rdata.a.address, 4);
      *offset += 4;
      break;

    case DNS_TYPE_NS: // TODO
    case DNS_TYPE_CNAME: // TODO
    case DNS_TYPE_PTR: {
      const char *domain = (rr->type == DNS_TYPE_NS)
        ? rr->rdata.ns.nsdname
        : rr->rdata.cname.cname;
      if (dns_encode_name(buffer, len, offset, domain) < 0) return -1;
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

      if (dns_encode_name(buffer, len, offset, rr->rdata.soa.mname) < 0) return -1;
      if (dns_encode_name(buffer, len, offset, rr->rdata.soa.rname) < 0) return -1;
      if (*offset + 20 > len) return -1; // 5 * 4 bytes for the numbers

      uint32_t serial = htonl(rr->rdata.soa.serial);
      uint32_t refresh = htonl(rr->rdata.soa.refresh);
      uint32_t retry = htonl(rr->rdata.soa.retry);
      uint32_t expire = htonl(rr->rdata.soa.expire);
      uint32_t minimum = htonl(rr->rdata.soa.minimum);

      memcpy(buffer + *offset, &serial, 4);   *offset += 4;
      memcpy(buffer + *offset, &refresh, 4);  *offset += 4;
      memcpy(buffer + *offset, &retry, 4);    *offset += 4;
      memcpy(buffer + *offset, &expire, 4);   *offset += 4;
      memcpy(buffer + *offset, &minimum, 4);  *offset += 4;
      break;
    }

    case DNS_TYPE_AAAA:
      if (*offset + 16 > len) return -1;
      memcpy(buffer + *offset, &rr->rdata.aaaa.address, 16);
      *offset += 16;
      break;

    default:
      return -1;  // unsupported type
  }

  uint16_t rdlength = htons(*offset - rdata_start);
  memcpy(buffer + rdlength_offset, &rdlength, 2);

  return 0;
}
