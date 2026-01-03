#include "dns_records.h"
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>


dns_rr_t *dns_rr_create(dns_record_type_t type, dns_class_t cls, uint32_t ttl) {
  dns_rr_t *rr = calloc(1, sizeof(dns_rr_t));
  if (!rr) return NULL;

  rr->type = type;
  rr->class = cls;
  rr->ttl = ttl;
  rr->next = NULL;
  return rr;
}

void dns_rr_free(dns_rr_t *rr) {
  if (!rr) return;

  if (rr->type == DNS_TYPE_TXT && rr->rdata.txt.text) {
    free(rr->rdata.txt.text);
  }
  if (rr->next) {
    dns_rr_free(rr->next);
  }

  free(rr);
}

dns_rrset_t *dns_rrset_create(dns_record_type_t type, uint32_t ttl) {
  dns_rrset_t *rrset = calloc(1, sizeof(dns_rrset_t));
  if (!rrset) return NULL;

  rrset->type = type;
  rrset->ttl = ttl;
  rrset->records = NULL;
  rrset->count = 0;
  return rrset;
}

void dns_rrset_free(dns_rrset_t *rrset) {
  if (!rrset) return;
  dns_rr_free(rrset->records);
  free(rrset);
}

bool dns_rrset_add(dns_rrset_t *rrset, dns_rr_t *rr) {
  if (!rrset || !rr) return false;
  // check record type
  if (rrset->type != rr->type) return false;
  // check ttl consistency
  if (rrset->count > 0 && rrset->ttl != rr->ttl) return false;

  rr->next = rrset->records;
  rrset->records = rr;
  rrset->count++;

  if (rrset->count == 1) rrset->ttl = rr->ttl;
  return true;
}

dns_rr_t *dns_rr_create_a(uint32_t address, uint32_t ttl) {
  dns_rr_t *rr = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, ttl);
  if (!rr) return NULL;

  rr->rdata.a.address = address;
  return rr;
}

dns_rr_t *dns_rr_create_a_str(const char *ip_str, uint32_t ttl) {
  if (!ip_str) return NULL;
  struct in_addr addr;
  if (inet_pton(AF_INET, ip_str, &addr) != 1) return NULL;
  return dns_rr_create_a(addr.s_addr, ttl);
}

dns_rr_t *dns_rr_create_aaaa(const uint8_t address[16], uint32_t ttl) {
  dns_rr_t *rr = dns_rr_create(DNS_TYPE_AAAA, DNS_CLASS_IN, ttl);
  if (!rr) return NULL;

  memcpy(rr->rdata.aaaa.address, address, 16);
  return rr;
}

dns_rr_t *dns_rr_create_aaaa_str(const char *ip_str, uint32_t ttl) {
  if (!ip_str) return NULL;
  struct in6_addr addr;
  if (inet_pton(AF_INET6, ip_str, &addr) != 1) return NULL;
  return dns_rr_create_aaaa(addr.s6_addr, ttl);
}

dns_rr_t *dns_rr_create_ns(const char *nsdname, uint32_t ttl) {
  if (!nsdname) return NULL;

  dns_rr_t *rr = dns_rr_create(DNS_TYPE_NS, DNS_CLASS_IN, ttl);
  if (!rr) return NULL;

  dns_safe_strncpy(rr->rdata.ns.nsdname, nsdname, sizeof(rr->rdata.ns.nsdname));
  return rr;
}

dns_rr_t *dns_rr_create_cname(const char *cname, uint32_t ttl) {
  if (!cname) return NULL;

  dns_rr_t *rr = dns_rr_create(DNS_TYPE_CNAME, DNS_CLASS_IN, ttl);
  if (!rr) return NULL;

  dns_safe_strncpy(rr->rdata.cname.cname, cname, sizeof(rr->rdata.cname.cname));
  return rr;
}

dns_rr_t *dns_rr_create_mx(uint16_t preference, const char *exchange, uint32_t ttl) {
  if (!exchange) return NULL;

  dns_rr_t *rr = dns_rr_create(DNS_TYPE_MX, DNS_CLASS_IN, ttl);
  if (!rr) return NULL;

  rr->rdata.mx.preference = preference;
  dns_safe_strncpy(rr->rdata.mx.exchange, exchange, sizeof(rr->rdata.mx.exchange));
  return rr;
}

dns_rr_t *dns_rr_create_txt(const char *text, uint32_t ttl) {
  if (!text) return NULL;

  dns_rr_t *rr = dns_rr_create(DNS_TYPE_TXT, DNS_CLASS_IN, ttl);
  if (!rr) return NULL;

  size_t len = strlen(text);
  rr->rdata.txt.text = malloc(len + 1);
  if (!rr->rdata.txt.text) {
    dns_rr_free(rr);
    return NULL;
  }

  memcpy(rr->rdata.txt.text, text, len + 1);
  rr->rdata.txt.length = len;
  return rr;
}

dns_rr_t *dns_rr_create_soa(const char *mname,
                            const char *rname,
                            uint32_t serial,
                            uint32_t refresh,
                            uint32_t retry,
                            uint32_t expire,
                            uint32_t minimum,
                            uint32_t ttl) {
  if (!mname || !rname) return NULL;

  dns_rr_t *rr = dns_rr_create(DNS_TYPE_SOA, DNS_CLASS_IN, ttl);
  if (!rr) return NULL;

  dns_safe_strncpy(rr->rdata.soa.mname, mname, sizeof(rr->rdata.soa.mname));
  dns_safe_strncpy(rr->rdata.soa.rname, rname, sizeof(rr->rdata.soa.rname));
  rr->rdata.soa.serial  = serial;
  rr->rdata.soa.refresh = refresh;
  rr->rdata.soa.retry   = retry;
  rr->rdata.soa.expire  = expire;
  rr->rdata.soa.minimum = minimum;

  return rr;
}

void dns_normalize_domain(const char *input, char *output) {
  if (!input) {
    if (output) output[0] = '\0';
    return;
  }
  if (!output) return;

  size_t len = strlen(input);
  size_t right = 0;

  for (size_t left = 0; left < len && right < MAX_DOMAIN_NAME - 1; ++left) {
    output[right++] = tolower((unsigned char) input[left]);
  }

  // remove trailing dot if present
  if (right > 0 && output[right-1] == '.') --right;
  output[right] = '\0';
}

bool dns_is_subdomain(const char *domain, const char *parent) {
  if (!domain || !parent) return false;

  size_t domain_len = strlen(domain);
  size_t parent_len = strlen(parent);

  if (domain_len < parent_len) return false;
  if (strcmp(domain, parent) == 0) return true;

  // check if domain ends in .parent
  size_t offset = domain_len - parent_len;
  if (offset > 0 && domain[offset-1] == '.') return (strcmp(domain + offset, parent) == 0);

  return false;
}
