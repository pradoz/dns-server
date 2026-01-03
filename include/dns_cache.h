#ifndef DNS_CACHE_H
#define DNS_CACHE_H


#include "dns_records.h"
#include "dns_parser.h"
#include <pthread.h>
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

typedef struct {
  dns_cache_t *cache;
  int cleanup_interval_sec;
  bool running;
  pthread_t thread;
  pthread_mutex_t mutex;
  pthread_cond_t cond;
} dns_cache_maintainer_t;

typedef struct {
  size_t current_entries;
  size_t max_entries;
  float utilization_pct;
  float hit_rate_pct;

  uint64_t total_queries;
  uint64_t positive_entries;
  uint64_t negative_entries;

  time_t oldest_entry_age;
  time_t newest_entry_age;
  uint32_t avg_remaining_ttl;
} dns_cache_summary_t;


// maintenance
dns_cache_maintainer_t *dns_cache_maintainer_create(dns_cache_t *cache, int interval_sec);
void dns_cache_maintainer_free(dns_cache_maintainer_t *maintainer);
int dns_cache_maintainer_start(dns_cache_maintainer_t *maintainer);
void dns_cache_maintainer_stop(dns_cache_maintainer_t *maintainer);

// thread-safe cache operations
int dns_cache_insert_safe(dns_cache_t *cache,
                          pthread_mutex_t *mutex,
                          const char *qname,
                          dns_record_type_t qtype,
                          dns_class_t qclass,
                          const dns_rr_t *records,
                          int record_count,
                          uint32_t ttl);
dns_cache_result_t *dns_cache_lookup_safe(dns_cache_t *cache,
                          pthread_mutex_t *mutex,
                          const char *qname,
                          dns_record_type_t qtype,
                          dns_class_t qclass);


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

int dns_cache_get_summary(const dns_cache_t *cache, dns_cache_summary_t *summary);
size_t dns_cache_memory_usage(const dns_cache_t *cache);
int dns_cache_dump_entries(const dns_cache_t *cache, FILE *output, int max_entries);

// configuration
void dns_cache_set_ttl_limits(dns_cache_t *cache, uint32_t min_ttl, uint32_t max_ttl);
void dns_cache_set_negative_ttl(dns_cache_t *cache, uint32_t ttl);
void dns_cache_set_negative_cache_enabled(dns_cache_t *cache, bool enabled);



#endif // !DNS_CACHE_H
