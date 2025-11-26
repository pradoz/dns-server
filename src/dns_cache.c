#include "dns_cache.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>


// DJB2 hash function
static unsigned int dns_cache_hash(const char *qname,
                                   dns_record_type_t qtype,
                                   dns_class_t qclass) {
  unsigned int hash = 5381;

  for (const char *p = qname; *p; ++p) {
    char c = (*p >= 'A' && *p <= 'Z') ? (*p + 32) : *p;
    hash = ((hash << 5) + hash) + c;
  }

  // mix-in type and class
  hash = ((hash << 5) + hash) + qtype;
  hash = ((hash << 5) + hash) + qclass;

  return hash % DNS_CACHE_HASH_SIZE;
}

static bool dns_cache_key_match(const dns_cache_entry_t *entry,
                                const char *qname,
                                dns_record_type_t qtype,
                                dns_class_t qclass) {
  return (entry->qtype == qtype
       && entry->qclass == qclass
       && strcmp(entry->qname, qname) == 0);
}
dns_cache_t *dns_cache_create(size_t max_entries) {
  dns_cache_t *cache = calloc(1, sizeof(dns_cache_t));
  if (!cache) return NULL;

  cache->max_entries = max_entries > 0 ? max_entries : DNS_CACHE_DEFAULT_SIZE;
  cache->current_entries = 0;

  // hash table
  for (int i = 0; i < DNS_CACHE_HASH_SIZE; ++i) {
    cache->hash_table[i] = NULL;
  }

  // LRU
  cache->lru_head = NULL;
  cache->lru_tail = NULL;

  // default config
  cache->min_ttl = 0;
  cache->max_ttl = 86400; // 24 hours
  cache->negative_ttl = 300; // 5 minutes
  cache->enable_negative_cache = true;

  memset(&cache->stats, 0, sizeof(dns_cache_stats_t));

  return cache;
}

static void dns_cache_entry_free(dns_cache_entry_t *entry) {
  if (!entry) return;

  // free records if its a positive entry
  if (entry->entry_type == DNS_CACHE_TYPE_POSITIVE && entry->records) {
    dns_rr_free(entry->records);
  }
  free(entry);
}

void dns_cache_free(dns_cache_t *cache) {
  if (!cache) return;

  // free the hash table
  for (int i = 0; i < DNS_CACHE_HASH_SIZE; ++i) {
    dns_cache_entry_t *entry = cache->hash_table[i];
    while (entry) {
      dns_cache_entry_t *next = entry->next;
      dns_cache_entry_free(entry);
      entry = next;
    }
  }

  free(cache);
}

void dns_cache_clear(dns_cache_t *cache) {
  if (!cache) return;

  // free the hash table entries
  for (int i = 0; i < DNS_CACHE_HASH_SIZE; ++i) {
    dns_cache_entry_t *entry = cache->hash_table[i];
    while (entry) {
      dns_cache_entry_t *next = entry->next;
      dns_cache_entry_free(entry);
      entry = next;
    }
    cache->hash_table[i] = NULL;
  }

  // reset LRU
  cache->lru_head = NULL;
  cache->lru_tail = NULL;

  cache->current_entries = 0;
}

const dns_cache_stats_t *dns_cache_get_stats(const dns_cache_t *cache) {
  return cache ? &cache->stats : NULL;
}

void dns_cache_reset_stats(dns_cache_t *cache) {
  if (!cache) return;
  memset(&cache->stats, 0, sizeof(dns_cache_stats_t));
}

void dns_cache_print_stats(const dns_cache_t *cache, FILE *output) {
  if (!cache || !output) return;

  const dns_cache_stats_t *stats = &cache->stats;

  fprintf(output, "=== DNS Cache Statistics ===\n");
  fprintf(output, "Entries: %zu / %zu (%.1f%% full)\n",
          cache->current_entries,
          cache->max_entries,
          (cache->current_entries * 100.0) / cache->max_entries);
  fprintf(output, "\nQuery Statistics:\n");
  fprintf(output, "  Total queries: %lu\n", stats->queries);
  fprintf(output, "  Cache hits:    %lu (%.1f%%)\n",
          stats->hits,
          dns_cache_hit_rate(cache));
  fprintf(output, "  Cache misses:  %lu\n", stats->misses);
  fprintf(output, "  Expired:       %lu\n", stats->expired);
  fprintf(output, "\nHit Breakdown:\n");
  fprintf(output, "  Positive:      %lu\n", stats->positive_hits);
  fprintf(output, "  Negative:      %lu\n", stats->negative_hits);
  fprintf(output, "    NXDOMAIN:    %lu\n", stats->nxdomain_hits);
  fprintf(output, "    NODATA:      %lu\n", stats->nodata_hits);
  fprintf(output, "\nMaintenance:\n");
  fprintf(output, "  Insertions:    %lu\n", stats->insertions);
  fprintf(output, "  Evictions:     %lu\n", stats->evictions);
}

float dns_cache_hit_rate(const dns_cache_t *cache) {
  if (!cache || cache->stats.queries == 0) return 0.0f;
  return (cache->stats.hits * 100.0f) / cache->stats.queries;
}

void dns_cache_set_ttl_limits(dns_cache_t *cache, uint32_t min_ttl, uint32_t max_ttl) {
  if (!cache) return;
  cache->min_ttl = min_ttl;
  cache->max_ttl = max_ttl;
}

void dns_cache_set_negative_ttl(dns_cache_t *cache, uint32_t ttl) {
  if (!cache) return;
  cache->negative_ttl = ttl;
}

void dns_cache_set_negative_cache_enabled(dns_cache_t *cache, bool enabled) {
  if (!cache) return;
  cache->enable_negative_cache = false;
}

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
int dns_cache_remove_expired(dns_cache_t *cache);
int dns_cache_remove_entry(dns_cache_t *cache,
                           const char *qname,
                           dns_record_type_t qtype,
                           dns_class_t qclass);
