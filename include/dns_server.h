#ifndef DNS_SERVER_H
#define DNS_SERVER_H


#include "dns_trie.h"
#include "dns_parser.h"
#include <arpa/inet.h>


#define DNS_PORT 5353
#define DNS_MAX_PACKET_SIZE 512
#define DNS_MAX_UDP_SIZE 512


typedef struct {
    int socket_fd;
    dns_trie_t *trie;
    bool running;
} dns_server_t;


dns_server_t *dns_server_create(uint16_t port);
void dns_server_free(dns_server_t *server);
bool dns_server_load_zone_file(dns_server_t *server, const char *filename);
void dns_server_run(dns_server_t *server);
void dns_server_stop(dns_server_t *server);

dns_message_t *dns_server_process_query(dns_server_t *server, const dns_message_t *query);


#endif // DNS_SERVER_H
