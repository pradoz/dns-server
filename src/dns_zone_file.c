#include "dns_zone_file.h"
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <strings.h>
#include <sys/socket.h>


zone_parser_t *zone_parser_create(const char *filename, const char *origin) {
  if (!filename || !origin) return NULL;

  zone_parser_t *parser = calloc(1, sizeof(zone_parser_t));
  if (!parser) return NULL;

  parser->file = fopen(filename, "r");
  if (!parser->file) {
    free(parser);
    return NULL;
  }

  parser->line_number = 0;
  parser->position = 0;
  parser->at_eof = false;

  strncpy(parser->curr_origin, origin, MAX_DOMAIN_NAME - 1);
  parser->last_name[0] = '\0';
  parser->curr_ttl = 3600; // default TTL

  return parser;
}

void zone_parser_free(zone_parser_t *parser) {
  if (!parser) return;

  if (parser->file) {
    fclose(parser->file);
  }
  free(parser);
}

dns_record_type_t zone_string_to_type(const char *type_str) {
  if (!type_str) return 0;

  if (strcasecmp(type_str, "A") == 0) return DNS_TYPE_A;
  if (strcasecmp(type_str, "NS") == 0) return DNS_TYPE_NS;
  if (strcasecmp(type_str, "CNAME") == 0) return DNS_TYPE_CNAME;
  if (strcasecmp(type_str, "SOA") == 0) return DNS_TYPE_SOA;
  if (strcasecmp(type_str, "PTR") == 0) return DNS_TYPE_PTR;
  if (strcasecmp(type_str, "MX") == 0) return DNS_TYPE_MX;
  if (strcasecmp(type_str, "TXT") == 0) return DNS_TYPE_TXT;
  if (strcasecmp(type_str, "AAAA") == 0) return DNS_TYPE_AAAA;

  return 0; // unknown type
}

dns_class_t zone_string_to_class(const char *class_str) {
  if (!class_str) return DNS_CLASS_IN; // default to IN

  if (strcasecmp(class_str, "IN") == 0) return DNS_CLASS_IN;
  if (strcasecmp(class_str, "CS") == 0) return DNS_CLASS_CS;
  if (strcasecmp(class_str, "CH") == 0) return DNS_CLASS_CH;
  if (strcasecmp(class_str, "HS") == 0) return DNS_CLASS_HS;

  return DNS_CLASS_IN;
}

bool zone_is_valid_domain_char(char c) {
  return isalnum(c) || c == '.' || c == '-' || c == '_';
}

static bool zone_read_line(zone_parser_t *parser) {
  if (!parser || !parser->file) return false;

  while (true) {
    if (!fgets(parser->curr_line, MAX_ZONE_LINE_LENGTH, parser->file)) {
      parser->at_eof = true;
      return false;
    }

    parser->line_number++;
    parser->position = 0;

    // remove trailing newline
    size_t len = strlen(parser->curr_line);
    if (len > 0 && parser->curr_line[len-1] == '\n') {
      parser->curr_line[len-1] = '\0';
    }

    // handle directives
    if (parser->curr_line[0] == '$') {
      if (zone_handle_directive(parser, parser->curr_line) == 0) {
        continue; // successfully handled directive
      }
      // if directive handling failed, treat as regular line
    }

    return true;
  }
}

static void zone_skip_whitespace(zone_parser_t *parser) {
  while (parser->curr_line[parser->position]
         && isspace(parser->curr_line[parser->position])) {
    parser->position++;
  }
}

int zone_get_next_token(zone_parser_t *parser, zone_token_t *token) {
  if (!parser || !token) return -1;

  zone_skip_whitespace(parser);

  if (parser->curr_line[parser->position] == '\0'
      || parser->curr_line[parser->position] == ';') {

    // handle comment at end of line
    if (parser->curr_line[parser->position] == ';') {
      token->type = ZONE_TOKEN_COMMENT;
      parser->position = strlen(parser->curr_line); // skip to end
      return 0;
    }

    // end of line - signal EOF (caller advances to next line)
    token->type = ZONE_TOKEN_EOF;
    return 0;
  }

  token->line_number = parser->line_number;
  token->column = parser->position;

  // parse token
  const char *start = &parser->curr_line[parser->position];
  const char *end = start;

  while (*end && !isspace(*end) && *end != ';') {
    ++end;
  }

  size_t token_len = end - start;
  if (token_len == 0) {
    token->type = ZONE_TOKEN_EOF;
    return 0;
  }

  if (token_len >= MAX_ZONE_TOKEN_LENGTH) {
    token->type = ZONE_TOKEN_ERROR;
    return -1;
  }

  strncpy(token->value, start, token_len);
  token->value[token_len] = '\0';
  parser->position = end - parser->curr_line;

  token->type = ZONE_TOKEN_NAME;
  return 0;
}

bool zone_parse_rdata(const char *type_str, const char *rdata_str, dns_rr_t *rr) {
  if (!type_str || !rdata_str || !rr) return false;

  dns_record_type_t type = zone_string_to_type(type_str);

  switch (type) {
    case DNS_TYPE_A: {
      struct in_addr addr;
      if (inet_aton(rdata_str, &addr) == 0) return false;
      rr->rdata.a.address = addr.s_addr;
      return true;
    }

    case DNS_TYPE_NS: {
      strncpy(rr->rdata.ns.nsdname, rdata_str, MAX_DOMAIN_NAME - 1);
      return true;
    }

    case DNS_TYPE_SOA: {
      // SOA format: "primary-ns email serial refresh retry expire minimum"
      // handle this in zone_parse_soa_record (need to parse multiple tokens
      return false;
    }

    case DNS_TYPE_MX: {
      // MX format: "priority hostname"
      char *space = strchr(rdata_str, ' ');
      if (!space) return false;

      *space = '\0'; // temp null terminator
      rr->rdata.mx.preference = (uint16_t) atoi(rdata_str);
      strncpy(rr->rdata.mx.exchange, space + 1, MAX_DOMAIN_NAME - 1);
      *space = ' ';
      return true;
    }

    case DNS_TYPE_TXT: {
      // simple TXT implementation - just store the string
      size_t len = strlen(rdata_str);
      rr->rdata.txt.text = malloc(len + 1);
      if (!rr->rdata.txt.text) return false;
      strcpy(rr->rdata.txt.text, rdata_str);
      rr->rdata.txt.length = len;
      return true;
    }

    case DNS_TYPE_AAAA: {
      struct in6_addr addr;
      if (inet_pton(AF_INET6, rdata_str, &addr) != 1) return false;
      memcpy(rr->rdata.aaaa.address, &addr, sizeof(struct in6_addr));
      return true;
    }

    default: return false;
  }
}

zone_directive_t zone_parse_directive(const char *line) {
  if (!line) return ZONE_DIRECTIVE_NONE;
  while (isspace(*line)) ++line; // skip whitespace

  if (strncasecmp(line, "$ORIGIN", 7) == 0) return ZONE_DIRECTIVE_ORIGIN;
  if (strncasecmp(line, "$INCLUDE", 8) == 0) return ZONE_DIRECTIVE_INCLUDE;
  if (strncasecmp(line, "$TTL", 4) == 0) return ZONE_DIRECTIVE_TTL;

  return ZONE_DIRECTIVE_NONE;
}

int zone_handle_directive(zone_parser_t *parser, const char *line) {
  if (!parser || !line) return -1;

  zone_directive_t directive = zone_parse_directive(line);

  switch (directive) {
    case ZONE_DIRECTIVE_ORIGIN: {
      // $ORIGIN example.com.
      char *origin_start = strchr(line, ' ');
      if (!origin_start) return -1;
      while (isspace(*origin_start)) ++origin_start; // skip whitespace

      strncpy(parser->curr_origin, origin_start, MAX_DOMAIN_NAME - 1);

      // remove trailing whitespace/newline/dot
      char *end = parser->curr_origin + strlen(parser->curr_origin) - 1;
      while (end > parser->curr_origin && isspace(*end)) {
        *end = '\0';
        --end;
      }

      printf("DEBUG: Set origin to '%s'\n", parser->curr_origin);
      return 0;
    }

    case ZONE_DIRECTIVE_TTL: {
      char *ttl_start = strchr(line, ' ');
      if (!ttl_start) return -1;
      while (isspace(*ttl_start)) ++ttl_start;

      parser->curr_ttl = (uint32_t)atol(ttl_start);
      return 0;
    }

    case ZONE_DIRECTIVE_INCLUDE: {
      // TODO: #INCLUDE support
      printf("DEBUG: $INCLUDE directive not supported yet\n");
      return 0;
    }

    default: return -1;
  }
}

static bool zone_parse_soa_record(zone_parser_t *parser,
                                  dns_rr_t *rr,
                                  zone_token_t *initial_tokens,
                                  int initial_count) {
  if (!parser || !rr) return false;

  // mname, rname, serial, refresh, retry, expire, minimum
  zone_token_t tokens[7];
  int token_count = 0;

  // copy any initial tokens that were already read
  for (int i = 0; i < initial_count && i < 7; i++) {
    tokens[token_count++] = initial_tokens[i];
  }

  // get remanining tokens for SOA
  while (token_count < 7) {
    if (zone_get_next_token(parser, &tokens[token_count]) < 0) {
      return false;
    }

    if (tokens[token_count].type == ZONE_TOKEN_EOF) {
      // end of line, read next line
      if (!zone_read_line(parser)) {
        return false; // EOF
      }
      continue;
    }
    if (tokens[token_count].type == ZONE_TOKEN_COMMENT) continue;
    ++token_count;
  }

  if (token_count < 7) return false;

  // parse SOA fields
  strncpy(rr->rdata.soa.mname, tokens[0].value, MAX_DOMAIN_NAME - 1);
  rr->rdata.soa.mname[MAX_DOMAIN_NAME - 1] = '\0';
  strncpy(rr->rdata.soa.rname, tokens[1].value, MAX_DOMAIN_NAME - 1);

  rr->rdata.soa.rname[MAX_DOMAIN_NAME - 1] = '\0';
  rr->rdata.soa.serial = (uint32_t) atol(tokens[2].value);
  rr->rdata.soa.refresh = (uint32_t) atol(tokens[3].value);
  rr->rdata.soa.retry = (uint32_t) atol(tokens[4].value);
  rr->rdata.soa.expire = (uint32_t) atol(tokens[5].value);
  rr->rdata.soa.minimum = (uint32_t) atol(tokens[6].value);

  return true;
}

static void zone_process_name(zone_parser_t *parser, const char *input, char *output) {
  if (!parser || !input || !output) return;

  if (strcmp(input, "@") == 0) {
    // @ --> current origin
    strcpy(output, parser->curr_origin);
  } else if (input[0] == '\0' || isspace(input[0])) {
    // empty --> use last name
    strcpy(output, parser->last_name);
  } else if (input[strlen(input) - 1] == '.') {
    // absolute name --> ends with dot
    strcpy(output, input);
    size_t len = strlen(output);
    if (len > 1) output[len-1] = '\0';
  } else {
    // relative name --> append origin
    if (strlen(parser->curr_origin) > 0) {
      snprintf(output, MAX_DOMAIN_NAME + 1, "%s.%s", input, parser->curr_origin);
    } else {
      strcpy(output, input);
    }
  }

  // update last name for future empty references
  strncpy(parser->last_name, output, MAX_DOMAIN_NAME);
  parser->last_name[MAX_DOMAIN_NAME] = '\0';
}

int zone_parse_record(zone_parser_t *parser, dns_rr_t **rr, char *owner_name) {
  if (!parser || !rr || !owner_name) return -1;

  // allow more tokens for complex records
  zone_token_t tokens[10];
  int token_count = 0;
  bool name_is_blank = false;

  if (parser->curr_line[0] != '\0' && isspace(parser->curr_line[0])) {
    name_is_blank = true;
  }

  // parser tokens for a single record
  while (token_count < 10) {
    if (zone_get_next_token(parser, &tokens[token_count]) < 0) {
      return -1;
    }

    if (tokens[token_count].type == ZONE_TOKEN_EOF) {
      if (token_count == 0) {
        // no tokens on this line, try next line
        if (!zone_read_line(parser)) {
          return 0; // EOF
        }

        // check again for blank name on new line
        if (parser->curr_line[0] != '\0' && isspace(parser->curr_line[0])) {
          name_is_blank = true;
        }

        continue; // try to read tokens from new line
      }
      break; // have tokens, end of record
    }

    // skip comments
    if (tokens[token_count].type == ZONE_TOKEN_COMMENT) continue;

    ++token_count;
  }

  if (token_count < 2) return 0; // not a complete record

  // parse tokens
  int name_idx = 0;
  int search_start = 0;
  int type_idx = -1;

  // reuse last name if name is blank
  if (name_is_blank) {
    // first token is actually TTL/CLASS/TYPE, not name
    search_start = 0;
    name_idx = -1; // signal to use last_name
  } else {
    // normal case: first token is the name
    search_start = 1;
    name_idx = 0;
  }

  // look for required type
  for (int i = search_start; i < token_count; ++i) {
    if (zone_string_to_type(tokens[i].value) != 0) {
      type_idx = i;
      break;
    }
  }
  if (type_idx == -1) return 0; // no valid type found

  // look for optional class, defaults to IN
  int class_idx = -1;
  dns_class_t record_class = DNS_CLASS_IN;
  for (int i = 1; i < type_idx; ++i) {
    dns_class_t parsed_class = zone_string_to_class(tokens[i].value);
    if (parsed_class != DNS_CLASS_IN || strcasecmp(tokens[i].value, "IN") == 0) {
      class_idx = i;
      record_class = parsed_class;
      break;
    }
  }

  // look for TTL, use default if not found
  uint32_t record_ttl = parser->curr_ttl;
  for (int i = 1; i < type_idx; i++) {
    if (i != class_idx && isdigit(tokens[i].value[0])) {
      record_ttl = (uint32_t) atol(tokens[i].value);
      break;
    }
  }

  int rdata_start_idx = type_idx + 1;
  dns_record_type_t type = zone_string_to_type(tokens[type_idx].value);

  if (rdata_start_idx >= token_count && zone_string_to_type(tokens[type_idx].value) != DNS_TYPE_SOA) {
    return 0; // no rdata
  }

  // process owner name
  if (name_idx == -1) { // blank name - use last name

    if (parser->last_name[0] == '\0') {
      return 0; // no previous name to use
    }
    strcpy(owner_name, parser->last_name);
  } else {
    zone_process_name(parser, tokens[name_idx].value, owner_name);
  }

  // create record
  *rr = dns_rr_create(type, record_class, record_ttl);
  if (!*rr) return -1;

  // handle SOA records (could span multiple lines)
  if (type == DNS_TYPE_SOA) {
    // pass any rdata tokens we already read
    int rdata_token_count = token_count - rdata_start_idx;
    zone_token_t *rdata_tokens = (rdata_token_count > 0) ? &tokens[rdata_start_idx] : NULL;

    if (!zone_parse_soa_record(parser, *rr, rdata_tokens, rdata_token_count)) {
      dns_rr_free(*rr);
      *rr = NULL;
      return -1;
    }
  } else { // build rdata from remaining tokens
    char rdata[MAX_ZONE_LINE_LENGTH] = {0};
    for (int i = rdata_start_idx; i < token_count; ++i) {
      if (i > rdata_start_idx) strcat(rdata, " ");
      strcat(rdata, tokens[i].value);
    }

    if (!zone_parse_rdata(tokens[type_idx].value, rdata, *rr)) {
      dns_rr_free(*rr);
      *rr = NULL;
      return -1;
    }
  }

  return 1; // successfully parsed 1 record
}

int zone_load_file(dns_trie_t *trie,
                   const char *filename,
                   const char *zone_name,
                   zone_load_result_t *result) {
  if (!trie || !filename || !zone_name || !result) return -1;

  memset(result, 0, sizeof(zone_load_result_t));
  strncpy(result->zone_name, zone_name, MAX_DOMAIN_NAME - 1);
  strncpy(result->filename, filename, sizeof(result->filename) - 1);
  dns_error_init(&result->last_error);

  zone_parser_t *parser = zone_parser_create(filename, zone_name);
  if (!parser) {
    DNS_ERROR_SET(&result->last_error, DNS_ERR_INVALID_PACKET, "Failed to open zone file");
    return -1;
  }

  dns_rr_t *rr;
  char owner_name[MAX_DOMAIN_NAME + 1];
  int parse_result;

  printf("Loading zone file: %s for zone: %s\n", filename, zone_name);

  while ((parse_result = zone_parse_record(parser, &rr, owner_name)) != 0) {
    if (parse_result < 0) {
      result->errors_encountered++;
      result->error_details.parse_errors++;
      continue;
    }

    if (rr) {
      if (dns_trie_insert_rr(trie, owner_name, rr)) {
        result->records_loaded++;
        // update stats
        switch (rr->type) {
          case DNS_TYPE_A: result->record_stats.a_records++; break;
          case DNS_TYPE_AAAA: result->record_stats.aaaa_records++; break;
          case DNS_TYPE_NS: result->record_stats.ns_records++; break;
          case DNS_TYPE_CNAME: result->record_stats.cname_records++; break;
          case DNS_TYPE_MX: result->record_stats.mx_records++; break;
          case DNS_TYPE_TXT: result->record_stats.txt_records++; break;
          case DNS_TYPE_SOA: result->record_stats.soa_records++; break;
          default: break;
        }

        printf("  Loaded: %s %u IN %s\n", owner_name, rr->ttl,
               (rr->type == DNS_TYPE_A) ? "A" :
               (rr->type == DNS_TYPE_AAAA) ? "AAAA" :
               (rr->type == DNS_TYPE_NS) ? "NS" :
               (rr->type == DNS_TYPE_CNAME) ? "CNAME" :
               (rr->type == DNS_TYPE_SOA) ? "SOA" :
               (rr->type == DNS_TYPE_MX) ? "MX" : "OTHER");
      } else {
        result->errors_encountered++;
        result->error_details.invalid_rdata++;
        dns_rr_free(rr);
      }
    }
  }

  zone_parser_free(parser);

  // print detailed summary
  printf("Zone loading complete: %s\n", zone_name);
  printf("  Records loaded: %d\n", result->records_loaded);
  printf("    A: %d, NS: %d, CNAME: %d, SOA: %d, MX: %d, TXT: %d, AAAA: %d\n",
         result->record_stats.a_records,
         result->record_stats.ns_records,
         result->record_stats.cname_records,
         result->record_stats.soa_records,
         result->record_stats.mx_records,
         result->record_stats.txt_records,
         result->record_stats.aaaa_records);
  printf("  Errors: %d\n", result->errors_encountered);
  if (result->errors_encountered > 0) {
    printf("    Parse errors: %d, Invalid rdata: %d\n",
           result->error_details.parse_errors,
           result->error_details.invalid_rdata);
  }

  return result->records_loaded > 0 ? 0 : -1;
}
