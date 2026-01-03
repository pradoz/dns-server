#ifndef DNS_RECORDS_H
#define DNS_RECORDS_H


#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <time.h>


#define MAX_DOMAIN_NAME 255
#define MAX_LABEL_LEN 63


typedef struct dns_rr dns_rr_t;


// record types
typedef enum {
  DNS_TYPE_A = 1,
  DNS_TYPE_NS = 2,
  DNS_TYPE_CNAME = 5,
  DNS_TYPE_SOA = 6,
  DNS_TYPE_PTR = 12,
  DNS_TYPE_MX = 15,
  DNS_TYPE_TXT = 16,
  DNS_TYPE_AAAA = 28
} dns_record_type_t;

typedef enum {
  DNS_CLASS_IN = 1, // Internet
  DNS_CLASS_CS = 2, // CSNET
  DNS_CLASS_CH = 3, // CHAOS
  DNS_CLASS_HS = 4  // Hesiod
} dns_class_t;

// SOA Record
typedef struct {
  char mname[MAX_DOMAIN_NAME]; // primary name server
  char rname[MAX_DOMAIN_NAME]; // email
  uint32_t serial;
  uint32_t refresh;
  uint32_t retry;
  uint32_t expire;
  uint32_t minimum;
} dns_soa_t;

// A Record (IPv4)
typedef struct {
  uint32_t address; // byte order
} dns_a_t;

// AAAA Record (IPv6)
typedef struct {
  uint8_t address[16];
} dns_aaaa_t;

// NS Record
typedef struct {
  char nsdname[MAX_DOMAIN_NAME];
} dns_ns_t;

// CNAME Record
typedef struct {
  char cname[MAX_DOMAIN_NAME];
} dns_cname_t;

// MX Record
typedef struct {
  uint16_t preference;
  char exchange[MAX_DOMAIN_NAME];
} dns_mx_t;

// TXT Record
typedef struct {
  char *text;
  size_t length;
} dns_txt_t;

// Generic resource record data
typedef union {
  dns_soa_t soa;
  dns_a_t a;
  dns_aaaa_t aaaa;
  dns_ns_t ns;
  dns_cname_t cname;
  dns_mx_t mx;
  dns_txt_t txt;
} dns_rdata_t;

// Resource record
typedef struct dns_rr {
  dns_record_type_t type;
  dns_class_t class;
  uint32_t ttl;
  dns_rdata_t rdata;
  dns_rr_t *next; // For RRsets (resource record sets)
} dns_rr_t;

// Resource Record Set
typedef struct {
  dns_record_type_t type;
  uint32_t ttl; // all records in RRset must have same TTL
  dns_rr_t *records;
  size_t count;
} dns_rrset_t;

static inline void dns_safe_strncpy(char *dest, const char *src, size_t dest_size) {
  if (!dest || !src || dest_size == 0) return;
  strncpy(dest, src, dest_size - 1);
  dest[dest_size - 1] = '\0';
}

dns_rr_t *dns_rr_create(dns_record_type_t type, dns_class_t cls, uint32_t ttl);
void dns_rr_free(dns_rr_t *rr);
dns_rrset_t *dns_rrset_create(dns_record_type_t type, uint32_t ttl);
void dns_rrset_free(dns_rrset_t *rrset);
bool dns_rrset_add(dns_rrset_t *rrset, dns_rr_t *rr);
void dns_normalize_domain(const char *input, char *output);
bool dns_is_subdomain(const char *domain, const char *parent);


#endif // DNS_RECORDS_H
