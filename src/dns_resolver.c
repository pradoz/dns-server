#include "dns_resolver.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>


dns_resolution_result_t *dns_resolution_result_create(void) {
  dns_resolution_result_t *result = calloc(1, sizeof(dns_resolution_result_t));
  if (!result) return NULL;

  result->rcode = DNS_RCODE_NOERROR;
  result->authoritative = false;
  return result;
}

static void dns_rr_list_free(dns_rr_t *list) {
  while (list) {
    dns_rr_t *next = list->next;
    list->next = NULL; // prevent recursive free
    dns_rr_free(list);
    list = next;
  }
}

void dns_resolution_result_free(dns_resolution_result_t *result) {
  if (!result) return;

  dns_rr_list_free(result->answer_list);
  dns_rr_list_free(result->authority_list);
  dns_rr_list_free(result->additional_list);

  free(result);
}

static dns_rr_t *dns_rr_copy(const dns_rr_t *rr) {
  if (!rr) return NULL;

  dns_rr_t *copy = dns_rr_create(rr->type, rr->class, rr->ttl);
  if (!copy) return NULL;

  memcpy(&copy->rdata, &rr->rdata, sizeof(dns_rdata_t));

  // handle TXT case
  if (rr->type == DNS_TYPE_TXT && rr->rdata.txt.text) {
    copy->rdata.txt.text = malloc(rr->rdata.txt.length);
    if (copy->rdata.txt.text) {
      memcpy(copy->rdata.txt.text, rr->rdata.txt.text, rr->rdata.txt.length);
      copy->rdata.txt.length = rr->rdata.txt.length;
    } else {
      dns_rr_free(copy);
      return NULL;
    }
  }

  return copy;
}

static bool dns_rr_list_append(dns_rr_t **list, int *count, dns_rr_t *rr) {
  if (!list || !rr) return false;

  if (!*list) {
    *list = rr;
  } else {
    dns_rr_t *curr = *list;
    while (curr->next) {
      curr = curr->next;
    }
    curr->next = rr;
  }

  if (count) (*count)++;
  return true;
}

int dns_resolve_query_full(dns_trie_t *trie,
    const dns_question_t *question,
    dns_resolution_result_t *result,
    dns_error_t *err) {
  if (!trie || !question || !result) return -1;

  // validate question
  if (question->qtype == 0 || question->qclass != DNS_CLASS_IN) {
    DNS_ERROR_SET(err, DNS_ERR_INVALID_QUESTION, "Invalid question type or class");
    result->rcode = DNS_RCODE_FORMERROR;
    return -1;
  }

  // check if zone exists and set authoritative flag
  dns_zone_t *zone = dns_trie_find_zone(trie, question->qname);
  if (zone && zone->authoritative) result->authoritative = true;

  // try CNAME chain resolution
  dns_cname_chain_t chain;
  int cname_result = dns_resolve_cname_chain(trie,
      question->qname,
      question->qtype,
      &chain,
      result,
      err);
  if (cname_result < 0) return -1;

  if (result->answer_count > 0) {
    result->rcode = DNS_RCODE_NOERROR;
    return 0;
  }

  // no CNAME, try direct lookup
  dns_rrset_t *rrset = dns_trie_lookup(trie, question->qname, question->qtype);
  if (rrset) {
    for (dns_rr_t *rr = rrset->records; rr != NULL; rr = rr->next) {
      dns_rr_t *copy = dns_rr_copy(rr);
      if (copy) {
        dns_rr_list_append(&result->answer_list, &result->answer_count, copy);
      }
    }

    result->rcode = DNS_RCODE_NOERROR;
    return 0;
  }

  // check if domain exists with a different record type (NODATA)
  dns_rrset_t *any_rrset = NULL;
  dns_record_type_t check_types[] = {DNS_TYPE_A, DNS_TYPE_AAAA, DNS_TYPE_NS, DNS_TYPE_MX};
  for (size_t i = 0; i < sizeof(check_types) / sizeof(check_types[0]); ++i) {
    if (check_types[i] != question->qtype) {
      any_rrset = dns_trie_lookup(trie, question->qname, check_types[i]);
      if (any_rrset) {
        result->rcode = DNS_RCODE_NOERROR;
        break;
      }
    }
  }

  // if we get here, domain does not exist (NXDOMAIN)
  if (!any_rrset) result->rcode = DNS_RCODE_NXDOMAIN;

  dns_add_authority_soa(trie, question->qname, result);
  return 0;
}

static bool is_in_cname_chain(const dns_cname_chain_t *chain, const char *name) {
  for (int i = 0; i < chain->count; ++i) {
    if (strcasecmp(chain->names[i], name) == 0) {
      return true;
    }
  }
  return false;
}

// CNAME chain resolution
int dns_resolve_cname_chain(dns_trie_t *trie,
                            const char *start_name,
                            dns_record_type_t qtype,
                            dns_cname_chain_t *chain,
                            dns_resolution_result_t *result,
                            dns_error_t *err) {
  if (!trie || !start_name || !chain || !result) return -1;

  chain->count = 0;
  char curr_name[MAX_DOMAIN_NAME];
  strncpy(curr_name, start_name, MAX_DOMAIN_NAME - 1);
  curr_name[MAX_DOMAIN_NAME - 1] = '\0';
  while (chain->count < DNS_MAX_CNAME_CHAIN) {
    // check for loop
    if (is_in_cname_chain(chain, curr_name)) {
      DNS_ERROR_SET(err, DNS_ERR_CNAME_LOOP, "CNAME loop detected");
      result->rcode = DNS_RCODE_SERVFAIL;
      return -1;
    }

    // record this name in the chain
    strncpy(chain->names[chain->count], curr_name, MAX_DOMAIN_NAME - 1);
    chain->names[chain->count][MAX_DOMAIN_NAME - 1] = '\0';
    chain->count++;

    // look for CNAME at current name
    uint32_t cname_ttl;
    dns_cname_t *cname = dns_trie_lookup_cname(trie, curr_name, &cname_ttl);

    if (cname) {
      // found CNAME, add to answer section
      dns_rr_t *cname_rr = dns_rr_create(DNS_TYPE_CNAME, DNS_CLASS_IN, cname_ttl);
      if (!cname_rr) {
        DNS_ERROR_SET(err, DNS_ERR_MEMORY_ALLOCATION, "Failed to create CNAME record");
        result->rcode = DNS_RCODE_SERVFAIL;
        return -1;
      }

      strncpy(cname_rr->rdata.cname.cname, cname->cname, MAX_DOMAIN_NAME - 1);
      dns_rr_list_append(&result->answer_list, &result->answer_count, cname_rr);

      // follow the CNAME
      strncpy(curr_name, cname->cname, MAX_DOMAIN_NAME - 1);
      curr_name[MAX_DOMAIN_NAME - 1] = '\0';
      continue;
    }

    // no CNAME, look for the requested type
    dns_rrset_t *rrset = dns_trie_lookup(trie, curr_name, qtype);
    if (rrset) {
      // found target records
      for (dns_rr_t *rr = rrset->records; rr != NULL; rr = rr->next) {
        dns_rr_t *copy = dns_rr_copy(rr);
        if (copy) {
          dns_rr_list_append(&result->answer_list, &result->answer_count, copy);
        }
      }
      return 0;
    }

    // no CNAME and no target record
    if (chain->count > 1) {
      // if we followed at least one CNAME, NOERROR
      result->rcode = DNS_RCODE_NOERROR;
      return 0;
    } else {
      // if this is the original query name, NXDOMAIN
      result->rcode = DNS_RCODE_NXDOMAIN;
      return 0;
    }
  }

  // chain too long
  DNS_ERROR_SET(err, DNS_ERR_CNAME_CHAIN_TOO_LONG, "CNAME chain exceeds maximum length");
  result->rcode = DNS_RCODE_SERVFAIL;
  return -1;
}

// authority section handling
int dns_add_authority_soa(dns_trie_t *trie,
                          const char *domain,
                          dns_resolution_result_t *result) {
  if (!trie || !domain || !result) return -1;

  dns_zone_t *zone = dns_trie_find_zone(trie, domain);
  if (!zone || !zone->soa) return -1;

  dns_rr_t *soa_rr = dns_rr_create(DNS_TYPE_SOA, DNS_CLASS_IN, zone->soa->minimum);
  if (!soa_rr) return -1;

  memcpy(&soa_rr->rdata.soa, zone->soa, sizeof(dns_soa_t));
  dns_rr_list_append(&result->authority_list, &result->authority_count, soa_rr);

  if (zone->authoritative) result->authoritative = true;

  return 0;
}

