#ifndef DNS_TRIE_H
#define DNS_TRIE_H


#include "dns_records.h"
#include <stdbool.h>


#define RRSET_MAP_SIZE 16


typedef struct rrset_entry rrset_entry_t;
typedef struct dns_trie_node dns_trie_node_t;
typedef struct dns_trie dns_trie_t;


typedef struct {
  char zone_name[MAX_DOMAIN_NAME];
  dns_soa_t *soa;
  dns_rrset_t *ns_records;
  bool authoritative;
} dns_zone_t;

typedef struct rrset_entry {
  dns_record_type_t type;
  dns_rrset_t *rrset;
  rrset_entry_t *next;
} rrset_entry_t;

typedef struct {
  rrset_entry_t *buckets[RRSET_MAP_SIZE];
} rrset_map_t;

typedef struct dns_trie_node {
  char label[MAX_LABEL_LEN + 1];
  dns_trie_node_t **children;
  size_t children_count;
  size_t children_capacity;

  rrset_map_t *rrsets; // rrsets at this node
  dns_zone_t *zone;

  // CNAME handling; mutually exclusive with other records
  dns_cname_t *cname;
  uint32_t cname_ttl;

  bool is_delegation;
} dns_trie_node_t;

typedef struct dns_trie {
    dns_trie_node_t *root;
} dns_trie_t;


dns_trie_t *dns_trie_create(void);
void dns_trie_free(dns_trie_t *trie);

dns_trie_node_t *dns_trie_node_create(const char *label);
void dns_trie_node_free(dns_trie_node_t *node);

// insert operations
bool dns_trie_insert_rr(dns_trie_t *trie, const char *domain, dns_rr_t *rr);
bool dns_trie_insert_zone(dns_trie_t *trie, const char *zone_name, dns_soa_t *soa, dns_rrset_t *ns_records);
bool dns_trie_insert_cname(dns_trie_t *trie, const char *domain, const char *target, uint32_t ttl);

// query operations
dns_rrset_t *dns_trie_lookup(dns_trie_t *trie, const char *domain, dns_record_type_t type);
dns_cname_t *dns_trie_lookup_cname(dns_trie_t *trie, const char *domain, uint32_t *ttl);
dns_zone_t *dns_trie_find_zone(dns_trie_t *trie, const char *domain);

// utility functions
rrset_map_t *rrset_map_create(void);
void rrset_map_free(rrset_map_t *map);
bool rrset_map_insert(rrset_map_t *map, dns_record_type_t type, dns_rrset_t *rrset);
dns_rrset_t *rrset_map_lookup(rrset_map_t *map, dns_record_type_t type);
bool dns_trie_is_empty(const dns_trie_t *trie);
size_t dns_trie_get_record_count(const dns_trie_t *trie);
const char *dns_trie_get_stats(const dns_trie_t *trie, char *buf, size_t len);


#endif // DNS_TRIE_H
