#include "dns_server.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>

dns_server_t *dns_server_create(uint16_t port) {
  dns_server_t *server = calloc(1, sizeof(dns_server_t));
  if (!server) return NULL;

  server->port = port;
  server->socket_fd = -1;
  server->running = false;

  server->trie = dns_trie_create();
  if (!server->trie) {
    free(server);
    return NULL;
  }

  return server;
}

void dns_server_free(dns_server_t *server) {
  if (!server) return;

  if (server->socket_fd >= 0) close(server->socket_fd);

  dns_trie_free(server->trie);
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
    dns_header_t error_header = query_msg->header;
    error_header.qr = DNS_QR_RESPONSE;
    error_header.rcode = DNS_RCODE_NOTIMP;
    error_header.ancount = 0;
    error_header.nscount = 0;
    error_header.arcount = 0;

    dns_encode_header(response->buffer, response->capacity, &error_header);
    response->length = 12;

    dns_message_free(query_msg);
    server->queries_processed++;
    return 0;
  }

  // validate: must have exactly one question
  if (query_msg->header.qdcount != 1) {
    DNS_ERROR_SET(err, DNS_ERR_INVALID_QUESTION, "Must have exactly one question");

    // send FORMERR response
    dns_header_t error_header = query_msg->header;
    error_header.qr = DNS_QR_RESPONSE;
    error_header.rcode = DNS_RCODE_FORMERROR;
    error_header.qdcount = 0;
    error_header.ancount = 0;
    error_header.nscount = 0;
    error_header.arcount = 0;

    dns_encode_header(response->buffer, response->capacity, &error_header);
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
    dns_header_t error_header = query_msg->header;
    error_header.qr = DNS_QR_RESPONSE;
    error_header.rcode = DNS_RCODE_FORMERROR;
    error_header.qdcount = 0;
    error_header.ancount = 0;
    error_header.nscount = 0;
    error_header.arcount = 0;

    dns_encode_header(response->buffer, response->capacity, &error_header);
    response->length = 12;

    dns_message_free(query_msg);
    server->queries_processed++;
    return 0;
  }

  // resolve query
  dns_resolution_result_t *resolution = dns_resolution_result_create();
  if (!resolution) {
    DNS_ERROR_SET(err, DNS_ERR_MEMORY_ALLOCATION, "Failed to allocate resolution result");
    dns_message_free(query_msg);
    server->queries_failed++;
    return -1;
  }

  dns_error_t resolve_err;
  dns_error_init(&resolve_err);

  if (dns_resolve_query_full(server->trie, &query_msg->questions[0], resolution, &resolve_err) < 0) {
    // resolution failed, but we still send a response
    if (resolve_err.code != DNS_ERR_NONE) {
      resolution->rcode = dns_error_to_rcode(resolve_err.code);
      fprintf(stderr, "Resolution error: %s (%s:%d)\n",
          resolve_err.message, resolve_err.file, resolve_err.line);
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
    dns_header_t error_header = query_msg->header;
    error_header.qr = DNS_QR_RESPONSE;
    error_header.rcode = DNS_RCODE_SERVFAIL;
    error_header.ancount = 0;
    error_header.nscount = 0;
    error_header.arcount = 0;

    dns_encode_header(response->buffer, response->capacity, &error_header);
    offset = 12;
    dns_encode_question(response->buffer, response->capacity, &offset, query_msg->questions);
    response->length = offset;

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

int dns_server_run(dns_server_t *server) {
  if (!server || server->socket_fd < 0) return -1;

  uint8_t recv_buffer[DNS_BUFFER_SIZE];

  while (server->running) {
    dns_request_t request = {0};
    request.client_addr_len = sizeof(request.client_addr);

    // receive query
    ssize_t recv_len = recvfrom(server->socket_fd,
                                recv_buffer,
                                sizeof(recv_buffer),
                                0,
                                (struct sockaddr *)&request.client_addr,
                                &request.client_addr_len);

    if (recv_len < 0) {
      if (errno == EINTR) continue;
      perror("recvfrom failed");
      continue;
    }

    // too small to be valid DNS packet
    if (recv_len < 12) continue;

    request.buffer = recv_buffer;
    request.length = recv_len;

    // process query
    dns_response_t *response = dns_response_create(DNS_BUFFER_SIZE);
    if (!response) continue;

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

      if (sent < 0) {
        perror("sendto failed");
      } else {
        server->responses_sent++;
      }
    } else if (err.code != DNS_ERR_NONE) {
      fprintf(stderr, "Query processing error: %s (%s:%d)\n",
              err.message,
              err.file,
              err.line);
    }

    dns_response_free(response);
  }

  return 0;
}
