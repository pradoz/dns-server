#ifndef DNS_CACHE_H
#define DNS_CACHE_H


#include "dns_records.h"
#include "dns_parser.h"
#include <time.h>
#include <stdbool.h>
#include <stdio.h>


#define DNS_CACHE_DEFAULT_SIZE 1000
#define DNS_CACHE_HASH_SIZE 256


typedef struct dns_cache_entry dns_cache_entry_t;

typedef enum {
  DNS_CACHE_TYPE_POSITIVE,
  DNS_CACHE_TYPE_NXDOMAIN,
  DNS_CACHE_TYPE_NODATA,
} dns_cache_entry_type_t;

typedef struct dns_cache_entry {
  char qname[MAX_DOMAIN_NAME];
  dns_record_type_t qtype;
  dns_class_t qclass;

  dns_cache_entry_type_t entry_type;
  time_t timestamp;  // cached at time
  time_t expiration; // expired at time
  uint32_t original_ttl;

  // positive responses
  dns_rr_t *records;
  int record_count;

  // negative responses
  uint8_t rcode; // NXDOMAIN, SERVFAIL, etc.

  dns_cache_entry_t *next; // hash collision chaining
  dns_cache_entry_t *lru_prev;
  dns_cache_entry_t *lru_next;
} dns_cache_entry_t;

typedef struct {
  uint64_t queries;
  uint64_t hits;
  uint64_t misses;
  uint64_t expired;
  uint64_t evictions;
  uint64_t insertions;

  uint64_t positive_hits;
  uint64_t negative_hits;
  uint64_t nxdomain_hits;
  uint64_t nodata_hits;
} dns_cache_stats_t;

typedef struct {
  dns_cache_entry_t *hash_table[DNS_CACHE_HASH_SIZE];

  dns_cache_entry_t *lru_head;
  dns_cache_entry_t *lru_tail;

  size_t max_entries;
  size_t current_entries;

  dns_cache_stats_t stats;

  // configuration
  uint32_t min_ttl;          // minimum TTL (default: 0)
  uint32_t max_ttl;          // maximum TTL (default: 86400)
  uint32_t negative_ttl;     // TTL for negative responses (default: 300)
  bool enable_negative_cache;
} dns_cache_t;

typedef struct {
  bool found;
  dns_cache_entry_type_t type;
  dns_rr_t *records;         // caller must free these
  int record_count;
  uint32_t remaining_ttl;
  uint8_t rcode;
} dns_cache_result_t;


// lifecycle
dns_cache_t *dns_cache_create(size_t max_entries);
void dns_cache_free(dns_cache_t *cache);
void dns_cache_clear(dns_cache_t *cache);

// operations
int dns_cache_insert(dns_cache_t *cache,
                     const char *qname,
                     dns_record_type_t qtype,
                     dns_class_t qclass,
                     const dns_rr_t *records,
                     int record_count,
                     uint32_t ttl);

int dns_cache_insert_negative(dns_cache_t *cache,
                              const char *qname,
                              dns_record_type_t qtype,
                              dns_class_t qclass,
                              dns_cache_entry_type_t type,
                              uint8_t rcode,
                              uint32_t ttl);

dns_cache_result_t *dns_cache_lookup(dns_cache_t *cache,
                                     const char *qname,
                                     dns_record_type_t qtype,
                                     dns_class_t qclass);

void dns_cache_result_free(dns_cache_result_t *result);

//  maintenance
int dns_cache_remove_expired(dns_cache_t *cache);
int dns_cache_remove_entry(dns_cache_t *cache,
                           const char *qname,
                           dns_record_type_t qtype,
                           dns_class_t qclass);

// stats/monitoring
const dns_cache_stats_t *dns_cache_get_stats(const dns_cache_t *cache);
void dns_cache_reset_stats(dns_cache_t *cache);
void dns_cache_print_stats(const dns_cache_t *cache, FILE *output);
float dns_cache_hit_rate(const dns_cache_t *cache);

// configuration
void dns_cache_set_ttl_limits(dns_cache_t *cache, uint32_t min_ttl, uint32_t max_ttl);
void dns_cache_set_negative_ttl(dns_cache_t *cache, uint32_t ttl);
void dns_cache_set_negative_cache_enabled(dns_cache_t *cache, bool enabled);



#endif // !DNS_CACHE_H
