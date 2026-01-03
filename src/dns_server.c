#include "dns_server.h"
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>


dns_server_config_t *dns_server_config_create(void) {
  dns_server_config_t *config = calloc(1, sizeof(dns_server_config_t));
  if (!config) return NULL;

  // set defaults
  config->port = DNS_DEFAULT_PORT;
  config->enable_recursion = true;
  strcpy(config->root_hints_file, "root.hints");
  strcpy(config->zone_file, "");
  config->recursion_timeout = DNS_RECURSIVE_TIMEOUT_SEC;
  config->max_recursion_depth = DNS_MAX_RECURSION_DEPTH;
  config->upstream_count = 0;

  return config;
}

void dns_server_config_free(dns_server_config_t *config) {
  if (config) free(config);
}

int dns_server_config_load(dns_server_config_t *config, const char *config_file) {
  if (!config) return -1;

  FILE *file = fopen(config_file, "r");
  if (!file) {
    printf("Config file not found, using defaults\n");
    return 0;
  }

  char line[512];
  while (fgets(line, sizeof(line), file)) {
    // skip comments/empty lines
    if (line[0] == '#' || line[0] == '\n' || line[0] == '\0') continue;

    char key[64];
    char value[256];
    if (sscanf(line, "%s %s", key, value) == 2) {
      if (strcmp(key, "port") == 0) {
        config->port = (uint16_t) atoi(value);
      } else if (strcmp(key, "recursion") == 0) {
        config->enable_recursion = (strcmp(value, "yes") == 0 || strcmp(value, "true") == 0);
      } else if (strcmp(key, "root_hints") == 0) {
        dns_safe_strncpy(config->root_hints_file, value, sizeof(config->root_hints_file));
      } else if (strcmp(key, "zone_file") == 0) {
        dns_safe_strncpy(config->zone_file, value, sizeof(config->zone_file));
      } else if (strcmp(key, "forwarder") == 0 && config->upstream_count < 8) {
        dns_safe_strncpy(config->upstream_servers[config->upstream_count], value, sizeof(config->upstream_servers[config->upstream_count]));
        config->upstream_count++;
      }
    }
  }

  fclose(file);
  printf("Loaded configuration file from %s\n", config_file);
  return 0;
}

dns_server_t *dns_server_create_with_config(const dns_server_config_t *config) {
  if (!config) return dns_server_create(DNS_DEFAULT_PORT);

  dns_server_t *server = calloc(1, sizeof(dns_server_t));
  if (!server) goto err_alloc;

  server->socket_fd = -1;
  server->running = false;
  server->port = config->port;
  server->enable_recursion = config->enable_recursion;
  server->enable_cache = true;

  server->trie = dns_trie_create();
  if (!server->trie) goto err_trie;

  server->cache = dns_cache_create(DNS_CACHE_DEFAULT_SIZE);
  if (!server->cache) goto err_cache;

  server->cache_maintainer = dns_cache_maintainer_create(server->cache, 60);
  if (!server->cache_maintainer) goto err_maintainer;

  if (dns_cache_maintainer_start(server->cache_maintainer) < 0) goto err_maintainer_start;

  // create recursive resolver
  if (config->enable_recursion) {
    server->recursive_resolver = dns_recursive_create();
    if (server->recursive_resolver) {
      if (dns_recursive_init_socket(server->recursive_resolver) < 0) {
        printf("WARNING: Failed to initialize recursive resolver socket\n");
        server->enable_recursion = false;
      }

      // try to load root hints
      if (dns_recursive_load_root_hints_file(server->recursive_resolver,
                                             config->root_hints_file) < 0) {
        printf("WARNING: Failed to load root hints, using built-in\n");
        dns_recursive_load_root_hints(server->recursive_resolver);
      }

      // add upstream forwarders if configured
      if (config->upstream_count > 0) {
        printf("Configuring %d upstream forwarders\n", config->upstream_count);
        // TODO: implement forwarder mode
      }
    }
  }

  return server;

err_maintainer_start:
  dns_cache_maintainer_free(server->cache_maintainer);
  server->cache_maintainer = NULL;
err_maintainer:
  dns_cache_free(server->cache);
  server->cache = NULL;
err_cache:
  dns_trie_free(server->trie);
  server->trie = NULL;
err_trie:
  free(server);
err_alloc:
  return NULL;
}

dns_server_t *dns_server_create(uint16_t port) {
  dns_server_t *server = calloc(1, sizeof(dns_server_t));
  if (!server) goto err_alloc;

  server->port = port;
  server->socket_fd = -1;
  server->running = false;
  server->enable_recursion = false;
  server->enable_cache = true;

  server->trie = dns_trie_create();
  if (!server->trie) goto err_trie;

  server->cache = dns_cache_create(DNS_CACHE_DEFAULT_SIZE);
  if (!server->cache) goto err_cache;

  server->cache_maintainer = dns_cache_maintainer_create(server->cache, 60);
  if (!server->cache_maintainer) goto err_maintainer;

  if (dns_cache_maintainer_start(server->cache_maintainer) < 0) goto err_maintainer_start;

  // create and initialize recursive resolver
  server->recursive_resolver = dns_recursive_create();
  if (!server->recursive_resolver) {
    printf("WARNING: Failed to create recursive resolver\n");
  } else {
    if (dns_recursive_init_socket(server->recursive_resolver) < 0) {
      printf("WARNING: Failed to initialize recursive resolver socket\n");
    } else {
      server->enable_recursion = true;
      if (dns_recursive_load_root_hints(server->recursive_resolver) < 0) {
        printf("WARNING: Failed to load root hints\n");
        server->enable_recursion = false;
      }
    }
  }

  return server;

err_maintainer_start:
  dns_cache_maintainer_free(server->cache_maintainer);
  server->cache_maintainer = NULL;
err_maintainer:
  dns_cache_free(server->cache);
  server->cache = NULL;
err_cache:
  dns_trie_free(server->trie);
  server->trie = NULL;
err_trie:
  free(server);
err_alloc:
  return NULL;
}

void dns_server_free(dns_server_t *server) {
  if (!server) return;

  if (server->socket_fd >= 0) close(server->socket_fd);

  if (server->cache_maintainer) {
    dns_cache_maintainer_stop(server->cache_maintainer);
    dns_cache_maintainer_free(server->cache_maintainer);
  }

  if (server->recursive_resolver) dns_recursive_free(server->recursive_resolver);
  if (server->cache) dns_cache_free(server->cache);
  if (server->trie) dns_trie_free(server->trie);

  free(server);
}

int dns_server_start(dns_server_t *server) {
  if (!server) return -1;
  if (server->socket_fd >= 0) return -1; // already started

  // create UDP socket
  server->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (server->socket_fd < 0) {
    perror("socket creation failed");
    return -1;
  }

  // set socket options
  int opt = 1;
  if (setsockopt(server->socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt failed");
    close(server->socket_fd);
    server->socket_fd = -1;
    return -1;
  }

  // bind to port
  struct sockaddr_in server_addr = {0};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(server->port);

  if (bind(server->socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    perror("bind failed");
    close(server->socket_fd);
    server->socket_fd = -1;
    return -1;
  }

  server->running = true;
  printf("DNS server listening on port %d\n", server->port);
  return 0;
}

void dns_server_stop(dns_server_t *server) {
  if (!server) return;

  server->running = false;

  if (server->socket_fd >= 0) {
    close(server->socket_fd);
    server->socket_fd = -1;
  }
}

dns_response_t *dns_response_create(size_t capacity) {
  dns_response_t *response = calloc(1, sizeof(dns_response_t));
  if (!response) return NULL;

  response->buffer = malloc(capacity);
  if (!response->buffer) {
    free(response);
    return NULL;
  }

  response->capacity = capacity;
  response->length = 0;
  return response;
}

void dns_response_free(dns_response_t *response) {
  if (!response) return;
  free(response->buffer);
  free(response);
}

int dns_build_response(const dns_message_t *query,
                       const dns_resolution_result_t *resolution,
                       uint8_t *buffer, size_t capacity, size_t *length,
                       dns_error_t *err) {
  if (!query || !resolution || !buffer || !length) return -1;

  size_t offset = 0;

  // build response header
  dns_header_t response_header = {
    .id = query->header.id,
    .qr = DNS_QR_RESPONSE,
    .opcode = query->header.opcode,
    .aa = resolution->authoritative ? 1 : 0,
    .tc = 0,
    .rd = query->header.rd,
    .ra = 0, // we don't support recursion yet
    .rcode = resolution->rcode,
    .qdcount = 1,
    .ancount = resolution->answer_count,
    .nscount = resolution->authority_count,
    .arcount = resolution->additional_count
  };

  if (dns_encode_header(buffer, capacity, &response_header) < 0) {
    DNS_ERROR_SET(err, DNS_ERR_BUFFER_TOO_SMALL, "Failed to encode header");
    return -1;
  }
  offset = 12;

  // encode question section
  if (dns_encode_question(buffer, capacity, &offset, query->questions) < 0) {
    DNS_ERROR_SET(err, DNS_ERR_BUFFER_TOO_SMALL, "Failed to encode question");
    return -1;
  }

  // encode answer section
  for (dns_rr_t *rr = resolution->answer_list; rr != NULL; rr = rr->next) {
    if (dns_encode_rr(buffer, capacity, &offset, query->questions[0].qname, rr) < 0) {
      // truncate response
      response_header.tc = 1;
      response_header.ancount = 0;
      response_header.nscount = 0;
      response_header.arcount = 0;

      offset = 12;
      dns_encode_header(buffer, capacity, &response_header);
      offset = 12;
      dns_encode_question(buffer, capacity, &offset, query->questions);
      break;
    }
  }

  // encode authority section (if not truncated)
  if (!response_header.tc) {
    for (dns_rr_t *rr = resolution->authority_list; rr != NULL; rr = rr->next) {
      const char *name;
      // for SOA records in authority, use the zone name from the SOA
      if (rr->type == DNS_TYPE_SOA && resolution->authority_zone_name[0] != '\0') {
        name = resolution->authority_zone_name;
      } else {
        name = query->questions[0].qname;
      }

      if (dns_encode_rr(buffer, capacity, &offset, name, rr) < 0) {
        // truncate if authority section doesn't fit
        response_header.tc = 1;
        response_header.nscount = 0;
        response_header.arcount = 0;

        offset = 12;
        dns_encode_header(buffer, capacity, &response_header);

        // would need to re-encode everything, so just stop here
        break;
      }
    }
  }

  // encode additional section (if not truncated)
  if (!response_header.tc) {
    for (dns_rr_t *rr = resolution->additional_list; rr != NULL; rr = rr->next) {
      if (dns_encode_rr(buffer, capacity, &offset, query->questions[0].qname, rr) < 0) {
        // just skip additional records if they don't fit
        response_header.arcount = 0;
        break;
      }
    }
  }

  *length = offset;
  return 0;
}

int dns_process_query(dns_server_t *server,
                      const dns_request_t *request,
                      dns_response_t *response,
                      dns_error_t *err) {
  if (!server || !request || !response) return -1;

  dns_error_init(err);
  server->queries_received++;

  // parse request
  dns_message_t *query_msg = dns_message_create();
  if (!query_msg) {
    DNS_ERROR_SET(err, DNS_ERR_MEMORY_ALLOCATION, "Failed to allocate query message");
    server->queries_failed++;
    return -1;
  }

  // parse header
  size_t offset = 0;
  if (dns_parse_header(request->buffer, request->length, &query_msg->header) < 0) {
    DNS_ERROR_SET(err, DNS_ERR_INVALID_PACKET, "Failed to parse header");
    dns_message_free(query_msg);
    server->queries_failed++;
    return -1;
  }
  offset = 12;

  // validate: must be a query
  if (query_msg->header.qr != DNS_QR_QUERY) {
    DNS_ERROR_SET(err, DNS_ERR_INVALID_PACKET, "Not a query packet");
    dns_message_free(query_msg);
    server->queries_failed++;
    return -1;
  }

  // validate: only standard query supported for now
  if (query_msg->header.opcode != DNS_OPCODE_QUERY) {
    DNS_ERROR_SET(err, DNS_ERR_UNSUPPORTED_OPCODE, "Unsupported opcode");

    // send NOTIMP response
    if (dns_build_error_response_header(response->buffer,
                                        response->capacity,
                                        query_msg->header.id,
                                        DNS_RCODE_NOTIMP,
                                        false) < 0) {
      dns_message_free(query_msg);
      server->queries_failed++;
      return -1;
    }
    response->length = 12;

    dns_message_free(query_msg);
    server->queries_processed++;
    return 0;
  }

  // validate: must have exactly one question
  if (query_msg->header.qdcount != 1) {
    DNS_ERROR_SET(err, DNS_ERR_INVALID_QUESTION, "Must have exactly one question");

    // send FORMERR response
    if (dns_build_error_response_header(response->buffer,
                                        response->capacity,
                                        query_msg->header.id,
                                        DNS_RCODE_FORMERROR,
                                        false) < 0) {
      dns_message_free(query_msg);
      server->queries_failed++;
      return -1;
    }
    response->length = 12;

    dns_message_free(query_msg);
    server->queries_processed++;
    return 0;
  }

  // parse question
  query_msg->questions = calloc(1, sizeof(dns_question_t));
  if (!query_msg->questions) {
    DNS_ERROR_SET(err, DNS_ERR_MEMORY_ALLOCATION, "Failed to allocate question");
    dns_message_free(query_msg);
    server->queries_failed++;
    return -1;
  }

  if (dns_parse_question(request->buffer, request->length, &offset,
              &query_msg->questions[0]) < 0) {
    DNS_ERROR_SET(err, DNS_ERR_INVALID_QUESTION, "Failed to parse question");

    // send FORMERR response
    if (dns_build_error_response_header(response->buffer,
                                        response->capacity,
                                        query_msg->header.id,
                                        DNS_RCODE_FORMERROR,
                                        false) < 0) {
      dns_message_free(query_msg);
      server->queries_failed++;
      return -1;
    }
    response->length = 12;

    dns_message_free(query_msg);
    server->queries_processed++;
    return 0;
  }

  if (server->enable_cache && server->cache) {
    dns_cache_result_t *cache_result = dns_cache_lookup(
        server->cache,
        query_msg->questions[0].qname,
        query_msg->questions[0].qtype,
        query_msg->questions[0].qclass);

    if (cache_result && cache_result->found) {
      server->cache_hits++;

      dns_resolution_result_t *resolution = dns_resolution_result_create();
      if (resolution) {
        if (cache_result->type == DNS_CACHE_TYPE_POSITIVE) {
          resolution->answer_list = cache_result->records;
          resolution->answer_count = cache_result->record_count;
          resolution->rcode = DNS_RCODE_NOERROR;
          cache_result->records = NULL; // transfer ownership
        } else if (cache_result->type == DNS_CACHE_TYPE_NXDOMAIN) {
          resolution->rcode = DNS_RCODE_NXDOMAIN;
        } else {
          resolution->rcode = DNS_RCODE_NOERROR;
        }

        dns_build_response(query_msg,
                           resolution,
                           response->buffer,
                           response->capacity,
                           &response->length,
                           err);
        dns_resolution_result_free(resolution);
        dns_cache_result_free(cache_result);
        dns_message_free(query_msg);
        server->queries_processed++;
        return 0;
      }
      dns_cache_result_free(cache_result);
    } else {
      server->cache_misses++;
      if (cache_result) {
        dns_cache_result_free(cache_result);
      }
    }
  }

  // resolve query - try authoritative first
  dns_resolution_result_t *resolution = dns_resolution_result_create();
  if (!resolution) {
    DNS_ERROR_SET(err, DNS_ERR_MEMORY_ALLOCATION, "Failed to allocate resolution result");
    dns_message_free(query_msg);
    server->queries_failed++;
    return -1;
  }

  dns_error_t resolve_err;
  dns_error_init(&resolve_err);

  int auth_result = dns_resolve_query_full(server->trie,
                                           &query_msg->questions[0],
                                           resolution,
                                           &resolve_err);

  if (server->enable_cache && server->cache && auth_result == 0) {
    if (resolution->rcode == DNS_RCODE_NOERROR && resolution->answer_list) {
      uint32_t min_ttl = UINT32_MAX;
      int count = 0;

      for (dns_rr_t *rr = resolution->answer_list; rr; rr = rr->next) {
        if (rr->ttl < min_ttl) min_ttl = rr->ttl;
        ++count;
      }

      if (min_ttl > 0 && count > 0) {
        dns_cache_insert(server->cache,
                         query_msg->questions[0].qname,
                         query_msg->questions[0].qtype,
                         query_msg->questions[0].qclass,
                         resolution->answer_list,
                         count,
                         min_ttl);
      }
    } else if (resolution->rcode == DNS_RCODE_NXDOMAIN) {
      uint32_t negative_ttl = 300; // default negative TTL

      if (resolution->authority_list && resolution->authority_list->type == DNS_TYPE_SOA) {
        negative_ttl = resolution->authority_list->rdata.soa.minimum;
      }
      dns_cache_insert_negative(server->cache,
                                query_msg->questions[0].qname,
                                query_msg->questions[0].qtype,
                                query_msg->questions[0].qclass,
                                DNS_CACHE_TYPE_NXDOMAIN,
                                DNS_RCODE_NXDOMAIN,
                                negative_ttl);
    }
  }

  // check if client requested recursion
  bool try_recursion = false;
  if (server->enable_recursion && query_msg->header.rd) {
    if (auth_result < 0
        || (resolution->rcode == DNS_RCODE_NXDOMAIN && !resolution->authoritative)
        || (resolution->answer_count == 0 && !resolution->authoritative)) {
      // client requested recursion
      try_recursion = true;
    }
  }

  if (try_recursion) {
    printf("Starting recursilve resolution for %s (type %u)\n",
            query_msg->questions[0].qname,
            query_msg->questions[0].qtype);

    // start asynchronous recursive resolution
    int recursive_result = dns_recursive_resolve(server->recursive_resolver,
                                                 &query_msg->questions[0],
                                                 &request->client_addr,
                                                 request->client_addr_len,
                                                 query_msg->header.id);
    if (recursive_result == 0) {
      // start async resolution, response will be sent when it completes
      dns_message_free(query_msg);
      dns_resolution_result_free(resolution);
      server->queries_processed++;
      server->recursive_responses++;

      // don't send the response now, just mark it as empty
      response->length = 0;
      return 0;
    } else {
      printf("Failed to start recursive resolution, falling back to authoritative\n");
    }
  }

  // recursive resolution failed to start, fall back to authoritative
  server->authoritative_responses++;

  if (auth_result < 0) {
    // resolution failed, but we still send a response
    if (resolve_err.code != DNS_ERR_NONE) {
      resolution->rcode = dns_error_to_rcode(resolve_err.code);
      fprintf(stderr, "Resolution error: %s (%s:%d)\n",
              resolve_err.message,
              resolve_err.file,
              resolve_err.line);
    } else {
      resolution->rcode = DNS_RCODE_SERVFAIL;
    }
  }

  // build response
  dns_error_t build_err;
  dns_error_init(&build_err);

  if (dns_build_response(query_msg,
                         resolution,
                         response->buffer,
                         response->capacity,
                         &response->length,
                         &build_err) < 0) {


    // failed to build response, send SERVFAIL
    if (dns_build_error_response_header(response->buffer,
                                        response->capacity,
                                        query_msg->header.id,
                                        DNS_RCODE_SERVFAIL,
                                        true) >= 0) {
      offset = 12;
      dns_encode_question(response->buffer, response->capacity, &offset, query_msg->questions);
      response->length = offset;
    } else {
      // error response failed, set minimal header
      dns_build_error_response_header(response->buffer,
                                      response->capacity,
                                      query_msg->header.id,
                                      DNS_RCODE_SERVFAIL,
                                      false);
      response->length = 12;
    }

    fprintf(stderr, "Build error: %s (%s:%d)\n",
            build_err.message,
            build_err.file,
            build_err.line);
  }

  dns_message_free(query_msg);
  dns_resolution_result_free(resolution);
  server->queries_processed++;

  return 0;
}

int dns_server_handle_recursive_query(dns_server_t *server,
                                     const dns_question_t *question,
                                     const struct sockaddr_storage *client_addr,
                                     socklen_t client_addr_len,
                                     uint16_t query_id) {
  if (!server || !server->recursive_resolver || !question || !client_addr) {
    return -1;
  }

  printf("Starting recusive resolution for %s\n", question->qname);
  return dns_recursive_resolve(server->recursive_resolver,
                               question,
                               client_addr,
                               client_addr_len,
                               query_id);
}

int dns_recursive_cleanup_expired_queries(dns_recursive_resolver_t *resolver) {
  if (!resolver) return -1;

  time_t now = time(NULL);
  int cleaned = 0;

  for (int i = 0; i < 256; ++i) {
    dns_recursive_query_t *query = &resolver->active_queries[i];

    if (query->query_id != 0
        && (now - query->start_time) > DNS_RECURSIVE_TIMEOUT_SEC) {

      printf("Cleaning up expired query for %s (ID: %u)\n",
             query->qname,
             query->query_id);

      // send timeout response to client
      dns_recursive_send_error_response(resolver, query, DNS_RCODE_SERVFAIL);

      // mark as inactive
      query->query_id = 0;
      resolver->failed_queries++;
      ++cleaned;
    }
  }

  return cleaned;
}

int dns_server_run(dns_server_t *server) {
  if (!server || server->socket_fd < 0) return -1;

  uint8_t recv_buffer[DNS_BUFFER_SIZE];

  // set up socket for main server to reference recursive resolver
  if (server->recursive_resolver) {
    dns_recursive_set_main_socket(server->recursive_resolver, server->socket_fd);
  }

  while (server->running) {
    fd_set read_fds;
    int max_fd = server->socket_fd;

    FD_ZERO(&read_fds);
    FD_SET(server->socket_fd, &read_fds);

    // add recursive resolver socket if it's available
    if (server->recursive_resolver && server->recursive_resolver->socket_fd >= 0) {
      FD_SET(server->recursive_resolver->socket_fd, &read_fds);
      if (server->recursive_resolver->socket_fd > max_fd) {
        max_fd = server->recursive_resolver->socket_fd;
      }
    }

    // wait for activity on either socket
    struct timeval timeout = {1, 0}; // 1s timeout
    int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

    if (activity < 0) {
      if (errno == EINTR) continue;
      perror("select failed");
      break;
    }

    if (activity == 0) {
      // timeout, check for expired recursive queries
      dns_recursive_cleanup_expired_queries(server->recursive_resolver);
      continue;
    }

    // check for client queries on main socket
    if (FD_ISSET(server->socket_fd, &read_fds)) {
      dns_request_t request = {0};
      request.client_addr_len = sizeof(request.client_addr);

      // receive query
      ssize_t recv_len = recvfrom(server->socket_fd,
                                  recv_buffer,
                                  sizeof(recv_buffer),
                                  0,
                                  (struct sockaddr *)&request.client_addr,
                                  &request.client_addr_len);

      if (recv_len >= 12) {
        request.buffer = recv_buffer;
        request.length = recv_len;

        dns_response_t *response = dns_response_create(DNS_BUFFER_SIZE);
        if (response) {

          dns_error_t err;
          dns_error_init(&err);

          if (dns_process_query(server, &request, response, &err) == 0
              && response->length > 0) {
            // send response
            ssize_t sent = sendto(server->socket_fd,
                                  response->buffer,
                                  response->length,
                                  0,
                                  (struct sockaddr *)&request.client_addr,
                                  request.client_addr_len);
            if (sent > 0) {
              server->responses_sent++;
            }
          }

          dns_response_free(response);
        }
      }
    }

    // check for recursive resolver responses
    if (server->recursive_resolver
        && server->recursive_resolver->socket_fd >= 0
        && FD_ISSET(server->recursive_resolver->socket_fd, &read_fds)) {
      struct sockaddr_storage server_addr;
      socklen_t server_addr_len = sizeof(server_addr);

      ssize_t recv_len = recvfrom(server->recursive_resolver->socket_fd,
                                  recv_buffer,
                                  sizeof(recv_buffer),
                                  0,
                                  (struct sockaddr*) &server_addr,
                                  &server_addr_len);
      if (recv_len >= 12) {
        dns_recursive_handle_response(server->recursive_resolver,
                                      recv_buffer,
                                      recv_len,
                                      &server_addr);
      }
    }
  }

  return 0;
}
