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
  if (server) return;

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

int dns_resolve_query(dns_trie_t *trie, const dns_question_t *question, dns_message_t *response_msg) {
  if (!trie || !question || !response_msg) return -1;

  // check for CNAME first
  uint32_t cname_ttl;
  dns_cname_t *cname = dns_trie_lookup_cname(trie, question->qname, &cname_ttl);

  if (cname) {
    // found CNAME, create response with CNAME record
    dns_rr_t *cname_rr = dns_rr_create(DNS_TYPE_CNAME, DNS_CLASS_IN, cname_ttl);
    if (!cname_rr) return -1;

    strncpy(cname_rr->rdata.cname.cname, cname->cname, MAX_DOMAIN_NAME - 1);

    // Allocate array for one answer
    response_msg->answers = malloc(sizeof(dns_rr_t*));
    if (!response_msg->answers) {
      dns_rr_free(cname_rr);
      return -1;
    }
    response_msg->answers[0] = cname_rr;
    response_msg->header.ancount = 1;
    response_msg->header.rcode = DNS_RCODE_NOERROR;

    // TODO: follow CNAME chain and add target records
    return 0;
  }

  // lookup requested record type
  dns_rrset_t *rrset = dns_trie_lookup(trie, question->qname, question->qtype);
  if (!rrset) {
    // check if domain exists but record type does not (NODATA vs NXDOMAIN)
    // TODO: NODATA
    response_msg->header.rcode = DNS_RCODE_NXDOMAIN;
    response_msg->header.ancount = 0;

    // TODO: add SOA record in authority section
    return 0;
  }

  // found records, count them first
  int count = 0;
  for (dns_rr_t *rr = rrset->records; rr != NULL; rr = rr->next) {
    count++;
  }

  // allocate array
  response_msg->answers = malloc(count * sizeof(dns_rr_t*));
  if (!response_msg->answers) return -1;

  // build answer array
  int i = 0;
  for (dns_rr_t *rr = rrset->records; rr != NULL; rr = rr->next) {
    // create a copy of the RR for the response
    dns_rr_t *answer_rr = dns_rr_create(rr->type, rr->class, rr->ttl);
    if (!answer_rr) {
      // cleanup already allocated answers
      for (int j = 0; j < i; j++) {
        dns_rr_free(response_msg->answers[j]);
      }
      free(response_msg->answers);
      response_msg->answers = NULL;
      return -1;
    }

    // copy rdata
    memcpy(&answer_rr->rdata, &rr->rdata, sizeof(dns_rdata_t));

    // handle TXT records case (copy text)
    if (rr->type == DNS_TYPE_TXT && rr->rdata.txt.text) {
      answer_rr->rdata.txt.text = malloc(rr->rdata.txt.length);
      if (answer_rr->rdata.txt.text) {
        memcpy(answer_rr->rdata.txt.text, rr->rdata.txt.text, rr->rdata.txt.length);
        answer_rr->rdata.txt.length = rr->rdata.txt.length;
      }
    }

    response_msg->answers[i++] = answer_rr;
  }

  response_msg->header.ancount = count;
  response_msg->header.rcode = DNS_RCODE_NOERROR;

  return 0;
}

int dns_process_query(dns_server_t *server, const dns_request_t *request, dns_response_t *response) {
  if (!server || !request || !response) return -1;

  // parse request
  dns_message_t *query_msg = dns_message_create();
  if (!query_msg) return -1;

  // parse header
  size_t offset = 0;
  if (dns_parse_header(request->buffer, request->length, &query_msg->header) < 0) {
    dns_message_free(query_msg);
    return -1;
  }
  offset = 12;

  // TODO: handle queries with >1 question
  if (query_msg->header.qr != DNS_QR_QUERY || query_msg->header.qdcount != 1) {
    dns_message_free(query_msg);
    return -1;
  }

  // parse question
  query_msg->questions = calloc(1, sizeof(dns_question_t));
  if (!query_msg->questions) {
    dns_message_free(query_msg);
    return -1;
  }

  if (dns_parse_question(request->buffer, request->length, &offset, &query_msg->questions[0]) < 0) {
    dns_message_free(query_msg);
    return -1;
  }

  // create response message
  dns_message_t *response_msg = dns_message_create();
  if (!response_msg) {
    dns_message_free(query_msg);
    return -1;
  }

  // copy header and set response flags
  response_msg->header.id = query_msg->header.id;
  response_msg->header.qr = DNS_QR_RESPONSE;
  response_msg->header.opcode = query_msg->header.opcode;
  response_msg->header.aa = 0; // TODO: set based on zone authority
  response_msg->header.tc = 0;
  response_msg->header.rd = query_msg->header.rd;
  response_msg->header.ra = 0; // TODO: support recursion yet
  response_msg->header.rcode = DNS_RCODE_NOERROR;

  // copy question section
  response_msg->questions = calloc(1, sizeof(dns_question_t));
  if (!response_msg->questions) {
    dns_message_free(query_msg);
    dns_message_free(response_msg);
    return -1;
  }
  memcpy(response_msg->questions, query_msg->questions, sizeof(dns_question_t));
  response_msg->header.qdcount = 1;

  // resolve query
  if (dns_resolve_query(server->trie, &query_msg->questions[0], response_msg) < 0) {
    response_msg->header.rcode = DNS_RCODE_SERVFAIL;
  }

  // encode response
  size_t response_offset = 0;

  // encode header
  if (dns_encode_header(response->buffer, response->capacity, &response_msg->header) < 0) {
    dns_message_free(query_msg);
    dns_message_free(response_msg);
    return -1;
  }
  response_offset = 12;

  // encode question section
  if (dns_encode_question(response->buffer, response->capacity, &response_offset, &response_msg->questions[0]) < 0) {
    dns_message_free(query_msg);
    dns_message_free(response_msg);
    return -1;
  }

  // encode answer records
  for (int i = 0; i < response_msg->header.ancount; i++) {
    if (dns_encode_rr(response->buffer,
          response->capacity,
          &response_offset,
          query_msg->questions[0].qname,
          response_msg->answers[i]) < 0) {

      // truncate if we run out of space
      response_msg->header.tc = 1;
      response_offset = 12; // reset to after header
      dns_encode_header(response->buffer,
          response->capacity,
          &response_msg->header);
      response_offset = 12;
      dns_encode_question(response->buffer,
          response->capacity,
          &response_offset,
          response_msg->questions);
      break;
    }
  }

  response->length = response_offset;

  dns_message_free(query_msg);
  dns_message_free(response_msg);
  return 0;
}

int dns_server_run(dns_server_t *server) {
  if (!server || server->socket_fd < 0) return -1;

  uint8_t recv_buf[DNS_MAX_PACKET_SIZE];

  while (server->running) {
    dns_request_t request = {0};
    request.client_addr_len = sizeof(request.client_addr);

    // receive query
    ssize_t recv_len = recvfrom(server->socket_fd,
        recv_buf,
        sizeof(recv_buf),
        0,
        (struct sockaddr*) &request.client_addr,
        &request.client_addr_len);

    if (recv_len < 0) {
      if (errno == EINTR) continue;
      perror("recvfrom failed");
      continue;
    }
    if (recv_len < 12) { // too small to be a valid DNS packet
      continue;
    }

    request.buffer = recv_buf;
    request.length = recv_len;

    // process query
    dns_response_t *response = dns_response_create(DNS_BUFFER_SIZE);
    if (!response) continue;

    if (dns_process_query(server, &request, response) == 0) {
      // send response
      ssize_t sent = sendto(server->socket_fd,
          response->buffer,
          response->length,
          0,
          (struct sockaddr*) &request.client_addr,
          request.client_addr_len);
      if (sent < 0) perror("sendto failed");
    }

    dns_response_free(response);
  }

  return 0;
}

dns_message_t *dns_server_process_query(dns_server_t *server, const dns_message_t *query) {
  if (!server || !query) return NULL;

  dns_message_t *response = dns_message_create();
  if (!response) return NULL;

  response->header.id = query->header.id;  // preserve query ID
  response->header.qr = DNS_QR_RESPONSE;
  response->header.opcode = query->header.opcode;
  response->header.aa = 0;  // set to 1 if authoritative
  response->header.tc = 0;  // not truncated
  response->header.rd = query->header.rd;  // preserve recursion desired
  response->header.ra = 0;  // recursion not available
  response->header.rcode = DNS_RCODE_NOERROR;
  response->header.qdcount = query->header.qdcount;
  response->header.ancount = 0;
  response->header.nscount = 0;
  response->header.arcount = 0;

  // copy question
  if (query->header.qdcount > 0) {
    response->questions = malloc(sizeof(dns_question_t));
    if (!response->questions) {
      dns_message_free(response);
      return NULL;
    }
    response->questions[0] = query->questions[0];
  }

  // process first question
  if (query->header.qdcount > 0) {
    dns_question_t *q = &query->questions[0];

    // find zone
    dns_zone_t *zone = dns_trie_find_zone(server->trie, q->qname);
    if (zone) response->header.aa = 1; // authoritative answer

    // check for CNAME
    uint32_t cname_ttl;
    dns_cname_t *cname = dns_trie_lookup_cname(server->trie, q->qname, &cname_ttl);
    if (cname) {
      response->answers = malloc(sizeof(dns_rr_t*));
      if (!response->answers) {
        dns_message_free(response);
        return NULL;
      }

      response->answers[0] = dns_rr_create(DNS_TYPE_CNAME, DNS_CLASS_IN, cname_ttl);
      if (!response->answers[0]) {
        free(response->answers);
        dns_message_free(response);
        return NULL;
      }

      strcpy(response->answers[0]->rdata.cname.cname, cname->cname);
      response->header.ancount = 1;
      response->header.rcode = DNS_RCODE_NOERROR;
      return response;
    }

    // lookup record
    dns_rrset_t *rrset = dns_trie_lookup(server->trie, q->qname, q->qtype);
    if (rrset && rrset->records) {
      // count records
      int count = 0;
      dns_rr_t *rr = rrset->records;
      while (rr) {
        ++count;
        rr = rr->next;
      }

      response->answers = calloc(count, sizeof(dns_rr_t*));
      if (!response->answers) {
        dns_message_free(response);
        return NULL;
      }

      response->header.ancount = count;

      rr = rrset->records;
      for (int i = 0; i < count; ++i) {
        response->answers[i] = dns_rr_create(rr->type, rr->class, rr->ttl);
        if (!response->answers[i]) {
          // cleanup already allocated answers
          for (int j = 0; j < i; ++j) {
            dns_rr_free(response->answers[j]);
          }
          free(response->answers);
          response->answers = NULL;
          dns_message_free(response);
          return NULL;
        }

        // copy rdata
        memcpy(&response->answers[i]->rdata, &rr->rdata, sizeof(dns_rdata_t));

        // handle TXT records (deep copy)
        if (rr->type == DNS_TYPE_TXT && rr->rdata.txt.text) {
          response->answers[i]->rdata.txt.text = malloc(rr->rdata.txt.length);
          if (response->answers[i]->rdata.txt.text) {
            memcpy(response->answers[i]->rdata.txt.text, rr->rdata.txt.text, rr->rdata.txt.length);
            response->answers[i]->rdata.txt.length = rr->rdata.txt.length;
          }
        }

        rr = rr->next;
      }

      response->header.rcode = DNS_RCODE_NOERROR;
    } else {
      response->header.rcode = DNS_RCODE_NXDOMAIN;
    }
  }

  return response;
}


#ifndef TESTING
int main(void) {
  dns_server_t *server = dns_server_create(DNS_DEFAULT_PORT);
  if (!server) {
    fprintf(stderr, "Failed to create server\n");
    return 1;
  }

  // add example records for testing
  dns_rr_t *example_a = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  example_a->rdata.a.address = htonl(0x5DB8D822); // 93.184.216.34 (example.com)
  dns_trie_insert_rr(server->trie, "example.com", example_a);

  dns_rr_t *localhost_a = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  localhost_a->rdata.a.address = htonl(0x7F000001); // 127.0.0.1
  dns_trie_insert_rr(server->trie, "localhost", localhost_a);

  if (dns_server_start(server) < 0) {
    fprintf(stderr, "Failed to start server\n");
    dns_server_free(server);
    return 1;
  }

  dns_server_run(server);

  dns_server_stop(server);
  dns_server_free(server);
  return 0;
}
#endif
