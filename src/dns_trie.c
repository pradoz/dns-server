#include "dns_trie.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <strings.h>


static unsigned int hash_type(dns_record_type_t type) {
  return type % RRSET_MAP_SIZE;
}


dns_trie_t *dns_trie_create(void) {
  dns_trie_t *trie = malloc(sizeof(dns_trie_t));
  if (!trie) return NULL;

  trie->root = dns_trie_node_create("");
  if (!trie->root) {
    free(trie);
    return NULL;
  }

  return trie;
}

void dns_trie_free(dns_trie_t *trie) {
  if (!trie) return;

  dns_trie_node_free(trie->root);
  free(trie);
}

static int split_domain(const char *domain, char labels[][MAX_LABEL_LEN+1], int max_labels) {
  char normalized[MAX_DOMAIN_NAME];
  dns_normalize_domain(domain, normalized);

  int count = 0;
  const char *end = normalized + strlen(normalized);

  // find all dots and split from right to left (root [TLD] down)
  const char *dots[128];
  int dot_count = 0;
  for (const char *p = normalized; *p; ++p) {
    if (*p == '.') {
      dots[dot_count++] = p;
    }
  }

  // extract labels from right to left (root [TLD] down)
  const char *start = (dot_count > 0) ? dots[dot_count-1] + 1 : normalized;
  const char *label_end = end;

  for (int i = dot_count - 1; i >= -1 && count < max_labels; --i) {

    size_t len = label_end - start;

    if (len > 0 && len <= MAX_LABEL_LEN) {
      memcpy(labels[count], start, len);
      labels[count][len] = '\0';
      ++count;
    }

    if (i >= 0) {
      label_end = dots[i];
      start = (i > 0) ? dots[i-1] + 1 : normalized;
    }
  }

  return count;
}

static dns_trie_node_t *find_or_create_node(dns_trie_t *trie, const char *domain) {
  char labels[128][MAX_LABEL_LEN + 1];
  int label_count = split_domain(domain, labels, 128);

  dns_trie_node_t *curr = trie->root;

  for (int i = 0; i < label_count; ++i) {
    // find child with matching label
    dns_trie_node_t *child = NULL;
    for (size_t j = 0; j < curr->children_count; ++j) {
      if (strcasecmp(curr->children[j]->label, labels[i]) == 0) {
        child = curr->children[j];
        break;
      }
    }

    // create child if not found
    if (!child) {
      child = dns_trie_node_create(labels[i]);
      if (!child) return NULL;

      // add to children
      if (curr->children_count >= curr->children_capacity) {
        size_t new_capacity = (curr->children_capacity == 0)
          ? 4
          : curr->children_capacity * 2;
        dns_trie_node_t **new_children = realloc(curr->children, new_capacity * sizeof(dns_trie_node_t*));
        if (!new_children) {
          dns_trie_node_free(child);
          return NULL;
        }
        curr->children = new_children;
        curr->children_capacity = new_capacity;
      }

      curr->children[curr->children_count++] = child;
    }

    curr = child;
  }

  return curr;
}

dns_trie_node_t *dns_trie_node_create(const char *label) {
  dns_trie_node_t *node = calloc(1, sizeof(dns_trie_node_t));
  if (!node) return NULL;

  if (label) {
    strncpy(node->label, label, MAX_LABEL_LEN);
    node->label[MAX_LABEL_LEN] = '\0';
  }

  node->children = NULL;
  node->children_count = 0;
  node->children_capacity = 0;
  node->rrsets = rrset_map_create();
  node->zone = NULL;
  node->cname = NULL;
  node->is_delegation = false;;

  return node;
}

void dns_trie_node_free(dns_trie_node_t *node) {
  if (!node) return;

  // free children
  for (size_t i = 0; i < node->children_count; ++i) {
    dns_trie_node_free(node->children[i]);
  }
  free(node->children);

  // free rrsets
  rrset_map_free(node->rrsets);

  // free zone
  if (node->zone) {
    if (node->zone->soa) free(node->zone->soa);
    dns_rrset_free(node->zone->ns_records);
    free(node->zone);
  }

  // free cname
  if (node->cname) free(node->cname);

  free(node);
}

bool dns_trie_insert_rr(dns_trie_t *trie, const char *domain, dns_rr_t *rr) {
  if (!trie || !domain || !rr) return false;

  dns_trie_node_t *node = find_or_create_node(trie, domain);
  if (!node) return false;

  // check for CNAME conflict
  if (node->cname != NULL) return false;

  // check if adding CNAME when any other records exist
  if (rr->type == DNS_TYPE_CNAME && node->rrsets) {
    for (int i = 0; i < RRSET_MAP_SIZE; ++i) {
      if (node->rrsets->buckets[i] != NULL) return false;
    }
  }

  // get or create rrset for this type
  dns_rrset_t *rrset = rrset_map_lookup(node->rrsets, rr->type);
  if (!rrset) {
    rrset = dns_rrset_create(rr->type, rr->ttl);
    if (!rrset) return false;

    if (!rrset_map_insert(node->rrsets, rr->type, rrset)) {
      dns_rrset_free(rrset);
      return false;
    }
  }

  return dns_rrset_add(rrset, rr);
}

bool dns_trie_insert_zone(dns_trie_t *trie, const char *zone_name, dns_soa_t *soa, dns_rrset_t *ns_records) {
  if (!trie || !zone_name || !soa || !ns_records) return false;

  dns_trie_node_t *node = find_or_create_node(trie, zone_name);

  if (node->zone) return false; // zone already exists

  node->zone = calloc(1, sizeof(dns_zone_t));
  if (!node->zone) return false;

  strncpy(node->zone->zone_name, zone_name, MAX_DOMAIN_NAME - 1);
  node->zone->soa = soa;
  node->zone->ns_records = ns_records;
  node->zone->authoritative = true;

  return true;
}

bool dns_trie_insert_cname(dns_trie_t *trie, const char *domain, const char *target, uint32_t ttl) {
  if (!trie || !domain || !target) return false;

  dns_trie_node_t *node = find_or_create_node(trie, domain);
  if (!node) return false;

  // check if other records exist
  for (int i = 0; i < RRSET_MAP_SIZE; ++i) {
    if (node->rrsets->buckets[i] != NULL) return false;
  }

  // check if CNAME already exists
  if (node->cname) return false;

  node->cname = calloc(1, sizeof(dns_cname_t));
  if (!node->cname) return false;

  strncpy(node->cname->cname, target, MAX_DOMAIN_NAME - 1);
  node->cname_ttl = ttl;

  return true;
}

dns_rrset_t *dns_trie_lookup(dns_trie_t *trie, const char *domain, dns_record_type_t type) {
  if (!trie || !domain) return NULL;

  char labels[128][MAX_LABEL_LEN + 1];
  int label_count = split_domain(domain, labels, 128);

  dns_trie_node_t *curr = trie->root;
  for (int i = 0; i < label_count; ++i) {
    dns_trie_node_t *child = NULL;
    for (size_t j = 0; j < curr->children_count; ++j) {
      if (strcasecmp(curr->children[j]->label, labels[i]) == 0) {
        child = curr->children[j];
        break;
      }
    }

    if (!child) return NULL;
    curr = child;
  }

  return rrset_map_lookup(curr->rrsets, type);
}

dns_cname_t *dns_trie_lookup_cname(dns_trie_t *trie, const char *domain, uint32_t *ttl) {
  if (!trie || !domain) return NULL;

  char labels[128][MAX_LABEL_LEN + 1];
  int label_count = split_domain(domain, labels, 128);

  dns_trie_node_t *curr = trie->root;
  for (int i = 0; i < label_count; ++i) {
    dns_trie_node_t *child = NULL;
    for (size_t j = 0; j < curr->children_count; ++j) {
      if (strcasecmp(curr->children[j]->label, labels[i]) == 0) {
        child = curr->children[j];
        break;
      }
    }

    if (!child) return NULL;
    curr = child;
  }

  if (curr->cname && ttl) {
    *ttl = curr->cname_ttl;
  }

  return curr->cname;
}

dns_zone_t *dns_trie_find_zone(dns_trie_t *trie, const char *domain) {
  if (!trie || !domain) return NULL;

  char labels[128][MAX_LABEL_LEN + 1];
  int label_count = split_domain(domain, labels, 128);

  dns_trie_node_t *curr = trie->root;
  dns_zone_t *closest_zone = NULL;

  for (int i = 0; i < label_count; ++i) {
    if (curr->zone) closest_zone = curr->zone;

    dns_trie_node_t *child = NULL;
    for (size_t j = 0; j < curr->children_count; ++j) {
      if (strcasecmp(curr->children[j]->label, labels[i]) == 0) {
        child = curr->children[j];
        break;
      }
    }

    if (!child) break;
    curr = child;
  }

  // check final node
  if (curr->zone) closest_zone = curr->zone;

  return closest_zone;
}

rrset_map_t *rrset_map_create(void) {
  rrset_map_t *map = calloc(1, sizeof(rrset_map_t));
  return map;
}

void rrset_map_free(rrset_map_t *map) {
  if (!map) return;

  for (int i = 0; i < RRSET_MAP_SIZE; ++i) {
    rrset_entry_t *entry = map->buckets[i];
    while (entry) {
      rrset_entry_t *next = entry->next;
      dns_rrset_free(entry->rrset);
      free(entry);
      entry = next;
    }
  }
  free(map);
}

bool rrset_map_insert(rrset_map_t *map, dns_record_type_t type, dns_rrset_t *rrset) {
  if (!map || !rrset) return false;

  unsigned int bucket = hash_type(type);

  // check if type already exists
  rrset_entry_t *entry = map->buckets[bucket];
  while (entry) {
    if (entry->type == type) return false; // already exists
    entry = entry->next;
  }

  rrset_entry_t *new_entry = malloc(sizeof(rrset_entry_t));
  if (!new_entry) return false;

  new_entry->type = type;
  new_entry->rrset = rrset;
  new_entry->next = map->buckets[bucket];
  map->buckets[bucket] = new_entry;

  return true;
}

dns_rrset_t *rrset_map_lookup(rrset_map_t *map, dns_record_type_t type) {
  if (!map) return NULL;

  unsigned int bucket = hash_type(type);
  rrset_entry_t *entry = map->buckets[bucket];

  while (entry) {
    if (entry->type == type) return entry->rrset;
    entry = entry->next;
  }

  return NULL;
}
