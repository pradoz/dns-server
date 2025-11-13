#ifndef DNS_PARSER_H
#define DNS_PARSER_H


#include "dns_records.h"
#include <stdint.h>
#include <stdbool.h>


// see dns.md for a visual break down

#define DNS_QR_QUERY    0
#define DNS_QR_RESPONSE 1

#define DNS_OPCODE_QUERY  0
#define DNS_OPCODE_IQUERY 1
#define DNS_OPCODE_STATUS 2

#define DNS_RCODE_NOERROR   0
#define DNS_RCODE_FORMERROR 1
#define DNS_RCODE_SERVFAIL  2
#define DNS_RCODE_NXDOMAIN  3
#define DNS_RCODE_NOTIMP    4
#define DNS_RCODE_REFUSED   5


// header
typedef struct {
  uint16_t id;

  // flags
  uint8_t qr;     // query/response
  uint8_t opcode; // operation code
  uint8_t aa;     // authoritative answer
  uint8_t tc;     // truncation
  uint8_t rd;     // recursion desired
  uint8_t ra;     // recursion allowed
  uint8_t rcode;  // response code

  // counts
  uint16_t qdcount; // question
  uint16_t ancount; // answer
  uint16_t nscount; // authority
  uint16_t arcount; // additional
} dns_header_t;

// question
typedef struct {
  char qname[MAX_DOMAIN_NAME];
  uint16_t qtype;
  uint16_t qclass;
} dns_question_t;

// message
typedef struct {
    dns_header_t header;
    dns_question_t *questions;
    dns_rr_t **answers;
    dns_rr_t **authority;
    dns_rr_t **additional;
} dns_message_t;


dns_message_t *dns_message_create(void);
void dns_message_free(dns_message_t *msg);

int dns_parse_header(const uint8_t *buffer, size_t len, dns_header_t *header);
int dns_parse_question(const uint8_t *buffer, size_t len, size_t *offset, dns_question_t *question);
int dns_parse_name(const uint8_t *buffer, size_t len, size_t *offset, char *name, size_t name_len);

int dns_encode_header(uint8_t *buffer, size_t len, const dns_header_t *header);
int dns_encode_question(uint8_t *buffer, size_t len, size_t *offset, const dns_question_t *question);
int dns_encode_name(uint8_t *buffer, size_t len, size_t *offset, const char *name);
int dns_encode_rr(uint8_t *buffer, size_t len, size_t *offset, const char *name, const dns_rr_t *rr);


#endif // DNS_PARSER_H
