#include "dns_server.h"
#include "dns_zone_file.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>

static dns_server_t *global_server = NULL;

void signal_handler(int sig) {
  (void)sig;
  if (global_server) {
    printf("\nReceived signal, shutting down...\n");
    global_server->running = false;
  }
}

int main(int argc, char *argv[]) {
  // set up signal handling
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  // load configuration
  dns_server_config_t *config = dns_server_config_create();
  if (!config) {
    fprintf(stderr, "Failed to create configuration\n");
    return 1;
  }

  const char *config_file = (argc > 1) ? argv[1] : "dns_server.conf";
  dns_server_config_load(config, config_file);

  // create server with configuration
  dns_server_t *server = dns_server_create_with_config(config);
  global_server = server;

  if (!server) {
    fprintf(stderr, "Failed to create server\n");
    dns_server_config_free(config);
    return 1;
  }

  printf("DNS Server Configuration:\n");
  printf("  Port: %d\n", server->port);
  printf("  Recursion: %s\n", server->enable_recursion ? "enabled" : "disabled");
  if (server->recursive_resolver) {
    printf("  Recursive resolver socket: %s\n",
           (server->recursive_resolver->socket_fd >= 0) ? "initialized" : "failed");
  }

  // load zone file if configured
  if (strlen(config->zone_file) > 0) {
    zone_load_result_t zone_result;
    if (zone_load_file(server->trie, config->zone_file, "example.com", &zone_result) == 0) {
      printf("Loaded zone file '%s' with %d records\n",
             config->zone_file, zone_result.records_loaded);
    } else {
      printf("Failed to load zone file '%s', using manual records\n", config->zone_file);
    }
  }

  // add some default records if no zone file loaded
  if (!strlen(config->zone_file)) {
    // manual record insertion for testing
    dns_rr_t *localhost_a = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
    localhost_a->rdata.a.address = htonl(0x7F000001); // 127.0.0.1
    dns_trie_insert_rr(server->trie, "localhost", localhost_a);

    dns_rr_t *test_a = dns_rr_create(DNS_TYPE_A, DNS_CLASS_IN, 300);
    test_a->rdata.a.address = htonl(0xC0A80101); // 192.168.1.1
    dns_trie_insert_rr(server->trie, "test.local", test_a);

    printf("Added default test records\n");
  }

  if (dns_server_start(server) < 0) {
    fprintf(stderr, "Failed to start server\n");
    dns_server_free(server);
    dns_server_config_free(config);
    return 1;
  }

  printf("\nServer capabilities:\n");
  printf("  - Authoritative responses for loaded zones\n");
  printf("  - Zone file loading (RFC 1035 format)\n");
  if (server->enable_recursion) {
    printf("  - Full recursive DNS resolution\n");
    printf("  - Asynchronous query processing\n");
    printf("  - Authority section parsing\n");
    printf("  - Query timeout handling\n");
  } else {
    printf("  - Recursive resolution: DISABLED\n");
  }

  printf("\nPress Ctrl+C to stop\n");

  dns_server_run(server);

  char stats_buf[512];
  dns_trie_get_stats(server->trie, stats_buf, sizeof(stats_buf));
  printf("\n=== Trie Statistics ===\n%s\n", stats_buf);

  printf("\n=== Server Statistics ===\n");
  printf("Queries received:       %lu\n", server->queries_received);
  printf("Queries processed:      %lu\n", server->queries_processed);
  printf("Queries failed:         %lu\n", server->queries_failed);
  printf("Responses sent:         %lu\n", server->responses_sent);
  printf("Authoritative responses: %lu\n", server->authoritative_responses);
  printf("Recursive responses:    %lu\n", server->recursive_responses);

  if (server->recursive_resolver) {
    printf("\n=== Recursive Resolver Statistics ===\n");
    printf("Recursive queries:      %lu\n", server->recursive_resolver->recursive_queries);
    printf("Forwarded queries:      %lu\n", server->recursive_resolver->forwarded_queries);
    printf("Failed queries:         %lu\n", server->recursive_resolver->failed_queries);
  }

  dns_server_stop(server);
  dns_server_free(server);
  dns_server_config_free(config);
  return 0;
}
