#include "dns_records.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


dns_rr_t *dns_rr_create(dns_record_type_t type, dns_class_t class, uint32_t ttl) {
  dns_rr_t *rr = calloc(1, sizeof(dns_rr_t));
  if (!rr) return NULL;

  rr->type = type;
  rr->class = class;
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

void dns_normalize_domain(const char *input, char *output) {
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
  size_t domain_len = strlen(domain);
  size_t parent_len = strlen(parent);

  if (domain_len < parent_len) return false;
  if (strcmp(domain, parent) == 0) return true;

  // check if domain ends in .parent
  size_t offset = domain_len - parent_len;
  if (offset > 0 && domain[offset-1] == '.') return (strcmp(domain + offset, parent) == 0);

  return false;
}
