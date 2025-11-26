#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H


#include "dns_records.h"
#include "dns_parser.h"
#include "dns_trie.h"
#include "dns_error.h"
#include "dns_cache.h"


#define DNS_MAX_CNAME_CHAIN 16


typedef struct {
  char names[DNS_MAX_CNAME_CHAIN][MAX_DOMAIN_NAME];
  int count;
} dns_cname_chain_t;

typedef struct {
  dns_rr_t *answer_list;
  dns_rr_t *authority_list;
  dns_rr_t *additional_list;
  int answer_count;
  int authority_count;
  int additional_count;
  uint8_t rcode;
  bool authoritative;
  char authority_zone_name[MAX_DOMAIN_NAME];
} dns_resolution_result_t;

typedef struct {
  dns_trie_t *trie;
  dns_cache_t *cache;
  bool cache_enabled;

  // stats
  uint64_t queries;
  uint64_t cache_hits;
  uint64_t cache_misses;
} dns_resolver_t;


dns_resolution_result_t *dns_resolution_result_create(void);
void dns_resolution_result_free(dns_resolution_result_t *result);
int dns_resolve_query_full(dns_trie_t *trie,
        const dns_question_t *question, dns_resolution_result_t *result,
        dns_error_t *err);

// CNAME chain resolution
int dns_resolve_cname_chain(dns_trie_t *trie,
        const char *start_name,
        dns_record_type_t qtype,
        dns_cname_chain_t *chain,
        dns_resolution_result_t *result,
        dns_error_t *err);

// authority section handling
int dns_add_authority_soa(dns_trie_t *trie,
        const char *domain,
        dns_resolution_result_t *result);


// cache-aware resolver functions
dns_resolver_t *dns_resolver_create(void);
void dns_resolver_free(dns_resolver_t *resolver);
void dns_resolver_set_cache_enabled(dns_resolver_t *resolver, bool enabled);

int dns_resolver_query_with_cache(dns_resolver_t *resolver,
                                   const dns_question_t *question,
                                   dns_resolution_result_t *result,
                                   dns_error_t *err);

#endif /* DNS_RESOLVER_H */
