#ifndef DNS_SERVER_H
#define DNS_SERVER_H


#include "dns_trie.h"
#include "dns_parser.h"
#include <arpa/inet.h>


#define DNS_DEFAULT_PORT 5353
#define DNS_MAX_PACKET_SIZE 512
#define DNS_BUFFER_SIZE 4096


typedef struct {
  int socket_fd;
  uint16_t port;
  dns_trie_t *trie;
  bool running;
} dns_server_t;

typedef struct {
  uint8_t *buffer;
  size_t length;
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
} dns_request_t;

typedef struct {
  uint8_t *buffer;
  size_t length;
  size_t capacity;
} dns_response_t;


// server lifecycle
dns_server_t *dns_server_create(uint16_t port);
void dns_server_free(dns_server_t *server);
int dns_server_start(dns_server_t *server);
void dns_server_stop(dns_server_t *server);
int dns_server_run(dns_server_t *server);

// request/response handling
dns_response_t *dns_response_create(size_t capacity);
void dns_response_free(dns_response_t *response);
int dns_process_query(dns_server_t *server, const dns_request_t *request, dns_response_t *response);

// query resolution
int dns_resolve_query(dns_trie_t *trie, const dns_question_t *question, dns_message_t *response_msg);


#endif // DNS_SERVER_H
