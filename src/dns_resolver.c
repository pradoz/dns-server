#include "dns_resolver.h"
#include <stdlib.h>
#include <stdint.h>
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
  dns_record_type_t check_types[] = {
    DNS_TYPE_A,
    DNS_TYPE_AAAA,
    DNS_TYPE_CNAME,
    DNS_TYPE_NS,
    DNS_TYPE_MX,
  };
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
  dns_safe_strncpy(curr_name, start_name, sizeof(curr_name));
  while (chain->count < DNS_MAX_CNAME_CHAIN) {
    // check for loop
    if (is_in_cname_chain(chain, curr_name)) {
      DNS_ERROR_SET(err, DNS_ERR_CNAME_LOOP, "CNAME loop detected");
      result->rcode = DNS_RCODE_SERVFAIL;
      return -1;
    }

    // record this name in the chain
    dns_safe_strncpy(chain->names[chain->count], curr_name, sizeof(chain->names[chain->count]));
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

      dns_safe_strncpy(cname_rr->rdata.cname.cname, cname->cname, sizeof(cname_rr->rdata.cname.cname));
      dns_rr_list_append(&result->answer_list, &result->answer_count, cname_rr);

      // follow the CNAME
      dns_safe_strncpy(curr_name, cname->cname, sizeof(curr_name));
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
  dns_safe_strncpy(result->authority_zone_name, zone->zone_name, sizeof(result->authority_zone_name));

  // add SOA to authority list
  if (dns_rr_list_append(&result->authority_list, &result->authority_count, soa_rr)) {
    if (zone->authoritative) result->authoritative = true;
    return 0;
  }

  dns_rr_free(soa_rr);
  return -1;
}

static void dns_resolver_cache_store(dns_resolver_t *resolver,
                                     const dns_question_t *question,
                                     const dns_resolution_result_t *result) {
  if (!resolver || !resolver->cache_enabled || !resolver->cache) return;
  if (!question || !result) return;

  if (result->rcode == DNS_RCODE_NOERROR && result->answer_list) {
    uint32_t min_ttl = UINT32_MAX;
    int count = 0;

    for (dns_rr_t *rr = result->answer_list; rr != NULL; rr = rr->next) {
      if (rr->ttl < min_ttl) min_ttl = rr->ttl; // min(rr->ttl, min_ttl)
      ++count;
    }

    if (min_ttl > 0 && count > 0) {
      dns_cache_insert(resolver->cache,
                       question->qname,
                       question->qtype,
                       question->qclass,
                       result->answer_list,
                       count,
                       min_ttl);
    }
  } else if (result->rcode == DNS_RCODE_NXDOMAIN) {
    // cache negative response (default 5 minutes)
    uint32_t ttl = 300;

    // get TTL from SOA if available
    if (result->authority_list && result->authority_list->type == DNS_TYPE_SOA) {
      ttl = result->authority_list->rdata.soa.minimum;
    }

    dns_cache_insert_negative(resolver->cache,
                              question->qname,
                              question->qtype,
                              question->qclass,
                              DNS_CACHE_TYPE_NXDOMAIN,
                              DNS_RCODE_NXDOMAIN,
                              ttl);
  }
}

static bool dns_resolver_cache_lookup(dns_resolver_t *resolver,
                                      const dns_question_t *question,
                                      dns_resolution_result_t *result) {
  if (!resolver || !resolver->cache_enabled || !resolver->cache) return false;
  if (!question || !result) return false;

  dns_cache_result_t *cache_result = dns_cache_lookup(resolver->cache,
                                                      question->qname,
                                                      question->qtype,
                                                      question->qclass);
  if (!cache_result) {
    resolver->cache_misses++;
    return false;
  }

  resolver->cache_hits++;

  if (cache_result->type == DNS_CACHE_TYPE_POSITIVE) {
    result->answer_list = cache_result->records;
    result->answer_count = cache_result->record_count;
    result->rcode = DNS_RCODE_NOERROR;

    cache_result->records = NULL; // prevent double-free
  } else if (cache_result->type == DNS_CACHE_TYPE_NXDOMAIN) {
    result->rcode = DNS_RCODE_NXDOMAIN;
    result->answer_count = 0;
  } else {
    result->rcode = DNS_RCODE_NOERROR;
    result->answer_count = 0;
  }

  dns_cache_result_free(cache_result);
  return true;
}

dns_resolver_t *dns_resolver_create(void) {
  dns_resolver_t *resolver = calloc(1, sizeof(dns_resolver_t));
  if (!resolver) return NULL;

  resolver->trie = dns_trie_create();
  if (!resolver->trie) {
    dns_trie_free(resolver->trie);
    free(resolver);
    return NULL;
  }

  resolver->cache = dns_cache_create(DNS_CACHE_DEFAULT_SIZE);
  if (!resolver->cache) {
    dns_cache_free(resolver->cache);
    free(resolver);
    return NULL;
  }

  resolver->cache_enabled = true;
  resolver->queries = 0;
  resolver->cache_hits = 0;
  resolver->cache_misses = 0;
  return resolver;
}

void dns_resolver_free(dns_resolver_t *resolver) {
  if (!resolver) return;

  if (resolver->trie) dns_trie_free(resolver->trie);
  if (resolver->cache) dns_cache_free(resolver->cache);
  free(resolver);
}

void dns_resolver_set_cache_enabled(dns_resolver_t *resolver, bool enabled) {
  if (!resolver) return;
  resolver->cache_enabled = enabled;
}

int dns_resolver_query_with_cache(dns_resolver_t *resolver,
                                   const dns_question_t *question,
                                   dns_resolution_result_t *result,
                                   dns_error_t *err) {
  if (!resolver || !question || !result) return -1;

  resolver->queries++;

  // try cache first
  if (dns_resolver_cache_lookup(resolver, question, result)) {
    return 0; // got a hit
  }

  // cache miss, fallback to normal resolution
  int ret = dns_resolve_query_full(resolver->trie, question, result, err);
  if (ret == 0) {
    // store result in cache
    dns_resolver_cache_store(resolver, question, result);
  }

  return ret;
}
