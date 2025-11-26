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
       && strcasecmp(entry->qname, qname) == 0);
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
  cache->enable_negative_cache = enabled;
}

static void dns_cache_lru_touch(dns_cache_t *cache, dns_cache_entry_t *entry) {
  if (!cache || !entry) return;

  if (cache->lru_head == entry) return; // already at head

  // remove from current position
  if (entry->lru_prev) entry->lru_prev->lru_next = entry->lru_next;
  if (entry->lru_next) entry->lru_next->lru_prev = entry->lru_prev;

  // update tail if entry is the tail
  if (cache->lru_tail == entry) cache->lru_tail = entry->lru_prev;

  // insert entry at head
  entry->lru_prev = NULL;
  entry->lru_next = cache->lru_head;

  if (cache->lru_head) cache->lru_head->lru_prev = entry;
  cache->lru_head = entry;

  // if this is the only entry, then it's also the tail
  if (!cache->lru_tail) cache->lru_tail = entry;
}

static void dns_cache_lru_add(dns_cache_t *cache, dns_cache_entry_t *entry) {
  if (!cache || !entry) return;

  // add new entry to LRU head (MRU entry)
  entry->lru_prev = NULL;
  entry->lru_next = cache->lru_head;

  if (cache->lru_head) cache->lru_head->lru_prev = entry;

  cache->lru_head = entry;

  if (!cache->lru_tail) cache->lru_tail = entry;
}

static void dns_cache_lru_remove(dns_cache_t *cache, dns_cache_entry_t *entry) {
  if (!cache || !entry) return;

  if (entry->lru_prev) {
    entry->lru_prev->lru_next = entry->lru_next;
  } else {
    cache->lru_head = entry->lru_next;
  }

  if (entry->lru_next) {
    entry->lru_next->lru_prev = entry->lru_prev;
  } else {
    cache->lru_tail = entry->lru_prev;
  }

  entry->lru_prev = NULL;
  entry->lru_next = NULL;
}

static bool dns_cache_evict_lru(dns_cache_t *cache) {
  if (!cache || !cache->lru_tail) return false;

  dns_cache_entry_t *victim = cache->lru_tail;

  // remove victim from hash table
  unsigned int hash = dns_cache_hash(victim->qname, victim->qtype, victim->qclass);
  dns_cache_entry_t **curr = &cache->hash_table[hash];

  while (*curr) {
    if (*curr == victim) {
      *curr = victim->next;
      break;
    }
    curr = &(*curr)->next;
  }

  // evict the victim
  dns_cache_lru_remove(cache, victim);
  dns_cache_entry_free(victim);

  cache->current_entries--;
  cache->stats.evictions++;

  return true;
}

static uint32_t dns_cache_clamp_ttl(const dns_cache_t *cache, uint32_t ttl) {
  if (!cache) return ttl;

  if (ttl < cache->min_ttl) return cache->min_ttl;
  if (ttl > cache->max_ttl) return cache->max_ttl;

  return ttl;
}

static bool dns_cache_entry_expired(const dns_cache_entry_t *entry) {
  if (!entry) return true;
  return time(NULL) >= entry->expiration;
}

static uint32_t dns_cache_entry_remaining_ttl(const dns_cache_entry_t *entry) {
  if (!entry) return 0;

  time_t now = time(NULL);
  if (now >= entry->expiration) return 0;

  return (uint32_t)(entry->expiration - now);
}

static dns_rr_t *dns_cache_copy_records(const dns_rr_t *records) {
  if (!records) return NULL;

  // deep copy the linked list of records
  dns_rr_t *head = NULL;
  dns_rr_t *tail = NULL;

  for (const dns_rr_t *src = records; src != NULL; src = src->next) {
    dns_rr_t *copy = dns_rr_create(src->type, src->class, src->ttl);
    if (!copy) {
      dns_rr_free(head);
      return NULL;
    }

    // copy rdata based on type
    switch (src->type) {
      case DNS_TYPE_A:
        copy->rdata.a = src->rdata.a;
        break;

      case DNS_TYPE_AAAA:
        copy->rdata.aaaa = src->rdata.aaaa;
        break;

      case DNS_TYPE_NS:
        copy->rdata.ns = src->rdata.ns;
        break;

      case DNS_TYPE_CNAME:
        copy->rdata.cname = src->rdata.cname;
        break;

      case DNS_TYPE_MX:
        copy->rdata.mx = src->rdata.mx;
        break;

      case DNS_TYPE_SOA:
        copy->rdata.soa = src->rdata.soa;
        break;

      case DNS_TYPE_TXT:
        if (src->rdata.txt.text) {
          copy->rdata.txt.text = malloc(src->rdata.txt.length);
          if (copy->rdata.txt.text) {
            memcpy(copy->rdata.txt.text, src->rdata.txt.text, src->rdata.txt.length);
            copy->rdata.txt.length = src->rdata.txt.length;
          }
        }
        break;

      default: break;
    }

    // add to list
    if (!head) {
      head = copy;
      tail = copy;
    } else {
      tail->next = copy;
      tail = copy;
    }
  }

  return head;
}

int dns_cache_insert(dns_cache_t *cache,
                     const char *qname,
                     dns_record_type_t qtype,
                     dns_class_t qclass,
                     const dns_rr_t *records,
                     int record_count,
                     uint32_t ttl) {
  if (!cache || !qname || !records || record_count <= 0) return -1;

  ttl = dns_cache_clamp_ttl(cache, ttl);
  if (ttl == 0) return 0; // do not cache zero TTL

  unsigned int hash = dns_cache_hash(qname, qtype, qclass);

  // check if entry already exist
  dns_cache_entry_t *existing = cache->hash_table[hash];
  while (existing) {
    if (dns_cache_key_match(existing, qname, qtype, qclass)) {
      // update existing entry
      if (existing->records) {
        dns_rr_free(existing->records);
      }

      existing->records = dns_cache_copy_records(records);
      if (!existing->records) return -1;

      existing->record_count = record_count;
      existing->entry_type = DNS_CACHE_TYPE_POSITIVE;
      existing->timestamp = time(NULL);
      existing->expiration = existing->timestamp + ttl;
      existing->original_ttl = ttl;

      // move to front of LRU (MRU entry)
      dns_cache_lru_touch(cache, existing);
      return 0;
    }
    existing = existing->next;
  }

  // if it does not exist, then create a new entry (check if we need to evict)
  while (cache->current_entries >= cache->max_entries) {
    if (!dns_cache_evict_lru(cache)) {
      return -1; // failed eviction
    }
  }

  // create new entry
  dns_cache_entry_t *entry = calloc(1, sizeof(dns_cache_entry_t));
  if (!entry) return -1;

  strncpy(entry->qname, qname, MAX_DOMAIN_NAME - 1);
  entry->qname[MAX_DOMAIN_NAME - 1] = '\0';
  entry->qtype = qtype;
  entry->qclass = qclass;
  entry->entry_type = DNS_CACHE_TYPE_POSITIVE;

  entry->records = dns_cache_copy_records(records);
  if (!entry->records) {
    free(entry);
    return -1;
  }

  entry->record_count = record_count;
  entry->timestamp = time(NULL);
  entry->expiration = entry->timestamp + ttl;
  entry->original_ttl = ttl;

  // insert new entry
  entry->next = cache->hash_table[hash];
  cache->hash_table[hash] = entry;

  // add to LRU list
  dns_cache_lru_add(cache, entry);

  cache->current_entries++;
  cache->stats.insertions++;
  return 0;
}

int dns_cache_insert_negative(dns_cache_t *cache,
                              const char *qname,
                              dns_record_type_t qtype,
                              dns_class_t qclass,
                              dns_cache_entry_type_t type,
                              uint8_t rcode,
                              uint32_t ttl) {
  if (!cache || !qname) return -1;
  if (!cache->enable_negative_cache) return 0;

  if (type != DNS_CACHE_TYPE_NXDOMAIN && type != DNS_CACHE_TYPE_NODATA) {
    return -1;
  }

  ttl = dns_cache_clamp_ttl(cache, ttl);
  if (ttl == 0) return 0;

  unsigned int hash = dns_cache_hash(qname, qtype, qclass);

  // check if entry already exist
  dns_cache_entry_t *existing = cache->hash_table[hash];
  while (existing) {
    if (dns_cache_key_match(existing, qname, qtype, qclass)) {
      // update existing entry
      if (existing->records) {
        dns_rr_free(existing->records);
      }

      existing->rcode = rcode;
      existing->entry_type = type;
      existing->record_count = 0;
      existing->timestamp = time(NULL);
      existing->expiration = existing->timestamp + ttl;
      existing->original_ttl = ttl;

      // move to front of LRU (MRU entry)
      dns_cache_lru_touch(cache, existing);
      return 0;
    }
    existing = existing->next;
  }

  // if it does not exist, then create a new entry (check if we need to evict)
  while (cache->current_entries >= cache->max_entries) {
    if (!dns_cache_evict_lru(cache)) {
      return -1; // failed eviction
    }
  }

  // create new entry
  dns_cache_entry_t *entry = calloc(1, sizeof(dns_cache_entry_t));
  if (!entry) return -1;

  strncpy(entry->qname, qname, MAX_DOMAIN_NAME - 1);
  entry->qname[MAX_DOMAIN_NAME - 1] = '\0';
  entry->qtype = qtype;
  entry->qclass = qclass;
  entry->entry_type = type;
  entry->rcode = rcode;
  entry->records = NULL;
  entry->record_count = 0;
  entry->timestamp = time(NULL);
  entry->expiration = entry->timestamp + ttl;
  entry->original_ttl = ttl;

  // insert new entry
  entry->next = cache->hash_table[hash];
  cache->hash_table[hash] = entry;

  // add to LRU list
  dns_cache_lru_add(cache, entry);

  cache->current_entries++;
  cache->stats.insertions++;
  return 0;
}

dns_cache_result_t *dns_cache_lookup(dns_cache_t *cache,
                                     const char *qname,
                                     dns_record_type_t qtype,
                                     dns_class_t qclass) {
  if (!cache || !qname) return NULL;

  cache->stats.queries++;

  unsigned int hash = dns_cache_hash(qname, qtype, qclass);
  dns_cache_entry_t *entry = cache->hash_table[hash];

  // search collision chain
  while (entry) {
    if (dns_cache_key_match(entry, qname, qtype, qclass)) {
      // check if expired
      if (dns_cache_entry_expired(entry)) {
        cache->stats.expired++;
        cache->stats.misses++;
        return NULL;
      }

      // prepare result
      dns_cache_result_t *result = calloc(1, sizeof(dns_cache_result_t));
      if (!result) {
        cache->stats.misses++;
        return NULL;
      }

      result->found = true;
      result->type = entry->entry_type;
      result->rcode = entry->rcode;
      result->remaining_ttl = dns_cache_entry_remaining_ttl(entry);

      // if its a positive entry, copy records
      if (entry->entry_type == DNS_CACHE_TYPE_POSITIVE && entry->records) {
        result->records = dns_cache_copy_records(entry->records);
        result->record_count = entry->record_count;

        for (dns_rr_t *rr = result->records; rr != NULL; rr = rr->next) {
          rr->ttl = result->remaining_ttl;
        }
      } else {
        result->records = NULL;
        result->record_count = 0;
      }

      // update stats
      cache->stats.hits++;
      if (entry->entry_type == DNS_CACHE_TYPE_POSITIVE) {
        cache->stats.positive_hits++;
      } else {
        cache->stats.negative_hits++;
        if (entry->entry_type == DNS_CACHE_TYPE_NXDOMAIN) {
          cache->stats.nxdomain_hits++;
        } else if (entry->entry_type == DNS_CACHE_TYPE_NODATA) {
          cache->stats.nodata_hits++;
        }
      }

      dns_cache_lru_touch(cache, entry);
      return result;
    }

    entry = entry->next;
  }

  // not found
  cache->stats.misses++;
  return NULL;
}

void dns_cache_result_free(dns_cache_result_t *result) {
  if (!result) return;
  if (result->records) dns_rr_free(result->records);
  free(result);
}

int dns_cache_remove_expired(dns_cache_t *cache) {
  if (!cache) return -1;

  int removed_count = 0;
  time_t now = time(NULL);

  for (int i = 0; i < DNS_CACHE_HASH_SIZE; ++i) {
    dns_cache_entry_t **curr = &cache->hash_table[i];
    while (*curr) {
      dns_cache_entry_t *entry = *curr;

      if (now >= entry->expiration) {
        *curr = entry->next; // remove from collision chain
        dns_cache_lru_remove(cache, entry); // remove from LRU list
        dns_cache_entry_free(entry);

        cache->current_entries--;
        ++removed_count;
      } else {
        curr = &(*curr)->next;
      }
    }
  }

  return removed_count;
}

int dns_cache_remove_entry(dns_cache_t *cache,
                           const char *qname,
                           dns_record_type_t qtype,
                           dns_class_t qclass) {
  if (!cache || !qname) return -1;

  unsigned int hash = dns_cache_hash(qname, qtype, qclass);
  dns_cache_entry_t **curr = &cache->hash_table[hash];

  while (*curr) {
    dns_cache_entry_t *entry = *curr;

    if (dns_cache_key_match(entry, qname, qtype, qclass)) {
        *curr = entry->next; // remove from collision chain
        dns_cache_lru_remove(cache, entry); // remove from LRU list
        dns_cache_entry_free(entry);
        cache->current_entries--;
        return 0;
    }

    curr = &(*curr)->next;
  }

  return -1;
}
