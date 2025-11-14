#include "dns_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int main(void) {
  dns_server_t *server = dns_server_create(DNS_DEFAULT_PORT);
  if (!server) {
    fprintf(stderr, "Failed to create server\n");
    return 1;
  }

  // add some example records for testing
  dns_rr_t *example_a = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  example_a->rdata.a.address = htonl(0x5DB8D822); // 93.184.216.34 (example.com)
  dns_trie_insert_rr(server->trie, "example.com", example_a);

  dns_rr_t *localhost_a = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
  localhost_a->rdata.a.address = htonl(0x7F000001); // 127.0.0.1
  dns_trie_insert_rr(server->trie, "localhost", localhost_a);

  // add CNAME chain for testing
  dns_trie_insert_cname(server->trie, "www.example.com", "example.com", 300);
  dns_trie_insert_cname(server->trie, "web.example.com", "www.example.com", 300);

  // add a zone with SOA
  dns_soa_t *soa = calloc(1, sizeof(dns_soa_t));
  strcpy(soa->mname, "ns1.example.com");
  strcpy(soa->rname, "admin.example.com");
  soa->serial = 2024010101;
  soa->refresh = 3600;
  soa->retry = 600;
  soa->expire = 86400;
  soa->minimum = 300;

  dns_rrset_t *ns_rrset = dns_rrset_create(DNS_TYPE_NS, 3600);
  dns_rr_t *ns = dns_rr_create(DNS_TYPE_NS, DNS_CLASS_IN, 3600);
  strcpy(ns->rdata.ns.nsdname, "ns1.example.com");
  dns_rrset_add(ns_rrset, ns);

  dns_trie_insert_zone(server->trie, "example.com", soa, ns_rrset);

  if (dns_server_start(server) < 0) {
    fprintf(stderr, "Failed to start server\n");
    dns_server_free(server);
    return 1;
  }

  printf("Server statistics will be available at shutdown\n");
  printf("Press Ctrl+C to stop\n");

  dns_server_run(server);

  printf("\n=== Server Statistics ===\n");
  printf("Queries received:  %lu\n", server->queries_received);
  printf("Queries processed: %lu\n", server->queries_processed);
  printf("Queries failed:  %lu\n", server->queries_failed);
  printf("Responses sent:  %lu\n", server->responses_sent);

  dns_server_stop(server);
  dns_server_free(server);
  return 0;
}
