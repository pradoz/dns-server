#ifndef DNS_ZONE_FILE_H
#define DNS_ZONE_FILE_H


#include "dns_records.h"
#include "dns_trie.h"
#include "dns_error.h"
#include <stdio.h>

#define MAX_ZONE_LINE_LENGTH 1024
#define MAX_ZONE_TOKEN_LENGTH 256


typedef enum {
  ZONE_TOKEN_NAME,
  ZONE_TOKEN_TTL,
  ZONE_TOKEN_CLASS,
  ZONE_TOKEN_TYPE,
  ZONE_TOKEN_RDATA,
  ZONE_TOKEN_COMMENT,
  ZONE_TOKEN_EOF,
  ZONE_TOKEN_ERROR,
} zone_token_type_t;

typedef enum {
  ZONE_DIRECTIVE_NONE,
  ZONE_DIRECTIVE_ORIGIN,
  ZONE_DIRECTIVE_TTL,
  ZONE_DIRECTIVE_INCLUDE,
} zone_directive_t;

typedef struct {
  zone_token_type_t type;
  char value[MAX_ZONE_TOKEN_LENGTH];
  int line_number;
  int column;
} zone_token_t;

typedef struct {
  FILE *file;
  char curr_line[MAX_ZONE_LINE_LENGTH];
  int line_number;
  int position;
  bool at_eof;

  // state
  char curr_origin[MAX_DOMAIN_NAME];
  char last_name[MAX_DOMAIN_NAME];
  uint32_t curr_ttl;

  // directive handling
  bool origin_set_by_directive;
} zone_parser_t;

typedef struct {
  char zone_name[MAX_DOMAIN_NAME];
  char filename[256];
  int records_loaded;
  int errors_encountered;
  dns_error_t last_error;

  // error tracking
  struct {
    int parse_errors;
    int unknown_types;
    int invalid_rdata;
    int directive_errors;
  } error_details;

  // stats
  struct {
    int a_records;
    int aaaa_records;
    int ns_records;
    int cname_records;
    int mx_records;
    int txt_records;
    int soa_records;
  } record_stats;
} zone_load_result_t;

// lifecycle
zone_parser_t *zone_parser_create(const char *filename, const char *origin);
void zone_parser_free(zone_parser_t *parser);

// file parsing
int zone_load_file(dns_trie_t *trie, const char *filename, const char *zone_name,
                   zone_load_result_t *result);
int zone_parse_record(zone_parser_t *parser, dns_rr_t **rr, char *owner_name);

// token parsing
int zone_get_next_token(zone_parser_t *parser, zone_token_t *token);
bool zone_parse_rdata(const char *type_str, const char *rdata_str, dns_rr_t *rr);

// directive handling
zone_directive_t zone_parse_directive(const char *line);
int zone_handle_directive(zone_parser_t *parser, const char *line);

// utility
dns_record_type_t zone_string_to_type(const char *type_str);
bool zone_is_valid_domain_char(char c);
dns_class_t zone_string_to_class(const char *class_str);

#endif // DNS_ZONE_FILE_H
