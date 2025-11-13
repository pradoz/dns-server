#include "dns_server.h"
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>


static volatile bool server_running = true;

static void signal_handler(int sig) {
  (void) sig;
  server_running = false;
}


dns_server_t *dns_server_create(uint16_t port) {
  dns_server_t *server = calloc(1, sizeof(dns_server_t));
  if (!server) return NULL;

  server->trie = dns_trie_create();
  if (!server->trie) {
    free(server);
    return NULL;
  }

  // create UDP socket
  server->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (server->socket_fd < 0) {
    dns_trie_free(server->trie);
    free(server);
    return NULL;
  }

  // bind to port
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(server->socket_fd, (struct sockaddr*) &addr, sizeof(addr)) < 0) {
     close(server->socket_fd);
     dns_trie_free(server->trie);
     free(server);
     return NULL;
  }

  server->running = true;
  printf("DNS server listening on port %d\n", port);
  return server;
}

void dns_server_free(dns_server_t *server) {
  if (!server) return;

  if (server->socket_fd >= 0) close(server->socket_fd);
  dns_trie_free(server->trie);
  free(server);
}

bool dns_server_load_zone_file(dns_server_t *server, const char *filename) {
  if (!server) return false;

  (void) filename; // add example records for now

  dns_soa_t *soa = calloc(1, sizeof(dns_soa_t));
  soa->serial = 2024010101;
  soa->refresh = 3600;
  soa->retry = 600;
  soa->expire = 86400;
  soa->minimum = 300;

  dns_rrset_t *ns_rrset = dns_rrset_create(DNS_TYPE_NS, 3600);
  dns_rr_t *ns1 = dns_rr_create(DNS_TYPE_NS, DNS_CLASS_IN, 3600);
  strcpy(ns1->rdata.ns.nsdname, "ns1.example.com");
  dns_rrset_add(ns_rrset, ns1);

  dns_trie_insert_zone(server->trie, "example.com", soa, ns_rrset);

  // A record: example.com
  dns_rr_t *a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  a_record->rdata.a.address = inet_addr("192.168.1.1");
  dns_trie_insert_rr(server->trie, "example.com", a_record);

  // A record: www.example.com
  dns_rr_t *www_a_record = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  www_a_record->rdata.a.address = inet_addr("192.168.1.2");
  dns_trie_insert_rr(server->trie, "www.example.com", www_a_record);

  // CNAME record: mail.example.com
  dns_trie_insert_cname(server->trie, "mail.example.com", "example.com", 300);

  printf("Loaded zone example.com with sample records\n");
  return true;
}

void dns_server_run(dns_server_t *server) {
  if (!server) return;

  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  uint8_t buf[DNS_MAX_PACKET_SIZE];
  struct sockaddr_in client_addr;
  socklen_t client_len = sizeof(client_addr);

  printf("DNS server running. Press ctrl+c to stop\n");

  while (server_running && server->running) {
    ssize_t recv_len = recvfrom(server->socket_fd,
        buf,
        DNS_MAX_PACKET_SIZE,
        0,
        (struct sockaddr*) &client_addr,
        &client_len);

    if (recv_len < 0) continue;

    printf("Received query from %s:%d (%zd bytes)\n",
        inet_ntoa(client_addr.sin_addr),
        ntohs(client_addr.sin_port),
        recv_len);

    // parse query
    dns_message_t *query = dns_message_create();
    size_t offset = 0;

    if (dns_parse_header(buf, recv_len, &query->header) < 0) {
      dns_message_free(query);
      continue;
    }

    // DEBUG: print raw bytes
    printf("Raw ID bytes: %02X %02X (should be network byte order)\n", buf[0], buf[1]);
    printf("Parsed query ID: 0x%04X (decimal: %u)\n", query->header.id, query->header.id);

    offset = 12;

    if (query->header.qdcount > 0) {
      query->questions = malloc(sizeof(dns_question_t) * query->header.qdcount);

      for (int i = 0; i < query->header.qdcount; ++i) {
        if (dns_parse_question(buf, recv_len, &offset, &query->questions[i]) < 0) {
          break;
        }

        printf("Question: %s (type=%d, class=%d)\n",
            query->questions[i].qname,
            query->questions[i].qtype,
            query->questions[i].qclass);
      }
    }

    // process query
    dns_message_t *response = dns_server_process_query(server, query);
    if (!response) {
      dns_message_free(query);
      continue;
    }

    printf("Query ID: 0x%04X, Response ID: 0x%04X\n", query->header.id, response->header.id);
    printf("Response ID: 0x%04X (decimal: %u)\n", response->header.id, response->header.id);

    // encode response
    uint8_t response_buf[DNS_MAX_PACKET_SIZE];
    offset = 0;

    if (dns_encode_header(response_buf, DNS_MAX_PACKET_SIZE, &response->header) < 0) {
      dns_message_free(response);
      continue;
    }

    offset = 12;

    // verify what was encoded
    dns_header_t verify_header;
    dns_parse_header(response_buf, 12, &verify_header);
    printf("Encoded ID: 0x%04X (decimal: %u)\n", verify_header.id, verify_header.id);
    printf("Encoded header: ID=0x%04X QR=%d AA=%d RD=%d RA=%d RCODE=%d ANCOUNT=%d\n",
        verify_header.id,
        verify_header.qr,
        verify_header.aa,
        verify_header.rd,
        verify_header.ra,
        verify_header.rcode,
        verify_header.ancount);

    printf("Response packet bytes:\n");
    for (size_t i = 0; i < offset && i < 64; i++) {
        printf("%02X ", response_buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n");

    // encode question
    if (response->header.qdcount > 0) {
      dns_encode_question(response_buf,
          DNS_MAX_PACKET_SIZE,
          &offset,
          &response->questions[0]);
    }

    // encode answers
    for (int i = 0; i < response->header.ancount; ++i) {
      dns_encode_rr(response_buf,
          DNS_MAX_PACKET_SIZE,
          &offset,
          response->questions[0].qname,
          response->answers[i]);
    }

    printf("Sending response (%zu bytes, %d answers, rcode=%d)\n",
         offset, response->header.ancount, response->header.rcode);

    // send response
    ssize_t sent = sendto(server->socket_fd,
        response_buf,
        offset,
        0,
        (struct sockaddr*)&client_addr,
        client_len);

    if (sent < 0) {
        perror("sendto failed");
    } else {
        printf("Successfully sent %zd bytes to %s:%d\n",
            sent,
            inet_ntoa(client_addr.sin_addr),
            ntohs(client_addr.sin_port));
    }
    dns_message_free(response);

  }

  printf("\nDNS server stopped.\n");

}

void dns_server_stop(dns_server_t *server) {
  if (server) server->running = false;;
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
          for (int j = 0; j < i; ++j) {
            dns_rr_free(response->answers[j]);
          }
          free(response->answers);
          dns_message_free(response);
          return NULL;
        }

        response->answers[i]->rdata = rr->rdata;
        rr = rr->next;
      }

      response->header.rcode = DNS_RCODE_NOERROR;
    } else {
      response->header.rcode = DNS_RCODE_NXDOMAIN;
    }
  }

  return response;
}


int main(int argc, char *argv[]) {
  uint16_t port = DNS_PORT;

  if (argc > 1) {
    port = atoi(argv[1]);
  }

  dns_server_t *server = dns_server_create(port);
  if (!server) {
    fprintf(stderr, "Failed to create DNS server\n");
  }

  // load zone
  dns_server_load_zone_file(server, NULL);

  dns_server_run(server);
  dns_server_free(server);


  return 0;
}
