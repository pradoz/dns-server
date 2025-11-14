#ifndef DNS_RECURSIVE_H
#define DNS_RECURSIVE_H


#include "dns_records.h"
#include "dns_parser.h"
#include "dns_error.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>


#define DNS_ROOT_HINTS_COUNT      13
#define DNS_MAX_RECURSION_DEPTH   16
#define DNS_RECURSIVE_TIMEOUT_SEC 5
#define DNS_MAX_UPSTREAM_SERVERS  8


typedef struct {
  char name[MAX_DOMAIN_NAME];
  struct sockaddr_in ipv4;
  struct sockaddr_in6 ipv6;
  bool has_ipv4;
  bool has_ipv6;

  // stats
  uint32_t queries_sent;
  uint32_t responses_received;
  uint32_t timeouts;
  time_t last_used;
} dns_nameserver_t;

typedef struct {
  dns_nameserver_t servers[DNS_MAX_UPSTREAM_SERVERS];
  int server_count;
  int current_server; // round-robin index
} dns_upstream_list_t;

typedef struct {
  uint16_t query_id;
  char qname[MAX_DOMAIN_NAME];
  uint16_t qtype;
  uint16_t qclass;

  time_t start_time;
  int recursion_depth;
  dns_upstream_list_t current_servers;

  // original query context for response
  struct sockaddr_storage client_addr;
  socklen_t client_addr_len;
  uint16_t original_id;
} dns_recursive_query_t;

typedef struct {
  dns_nameserver_t root_servers[DNS_ROOT_HINTS_COUNT];
  int socket_fd; // UDP socket for outbound queries

  // query tracking
  dns_recursive_query_t active_queries[256]; // indexed by query ID
  uint16_t next_query_id;

  // response forwarding
  int main_server_socket;

  // stats
  uint64_t recursive_queries;
  uint64_t cache_hits;
  uint64_t cache_misses;
  uint64_t forwarded_queries;
  uint64_t failed_queries;
} dns_recursive_resolver_t;


// lifecycle managment
dns_recursive_resolver_t *dns_recursive_create(void);
void dns_recursive_free(dns_recursive_resolver_t *resolver);
int dns_recursive_init_socket(dns_recursive_resolver_t *resolver);

// root hints
int dns_recursive_load_root_hints(dns_recursive_resolver_t *resolver);
int dns_recursive_add_upstream_server(dns_upstream_list_t *list,
                                      const char *server_ip,
                                      uint16_t port);

// query processing
int dns_recursive_resolve(dns_recursive_resolver_t *resolver,
                          const dns_question_t *question,
                          const struct sockaddr_storage *client_addr,
                          socklen_t client_addr_len,
                          uint16_t original_id);

int dns_recursive_handle_response(dns_recursive_resolver_t *resolver,
                                 const uint8_t *response_buf,
                                 size_t response_len,
                                 const struct sockaddr_storage *server_addr);

// response handling
int dns_recursive_set_main_socket(dns_recursive_resolver_t *resolver, int socket_fd);
int dns_recursive_forward_response(dns_recursive_resolver_t *resolver,
                                  const dns_recursive_query_t *query,
                                  const uint8_t *response_buffer,
                                  size_t response_len);
int dns_recursive_send_error_response(dns_recursive_resolver_t *resolver,
                                     const dns_recursive_query_t *query,
                                     uint8_t rcode);
int dns_extract_nameservers_from_authority(const uint8_t *buffer,
                                           size_t len,
                                           dns_upstream_list_t *servers);
// utility
dns_nameserver_t *dns_recursive_select_server(dns_upstream_list_t *list);
int dns_recursive_send_query(dns_recursive_resolver_t *resolver,
                             const dns_question_t *question,
                             const dns_nameserver_t *server,
                             uint16_t query_id);
int dns_recursive_load_root_hints_file(dns_recursive_resolver_t *resolver, const char *filename);


#endif // !DNS_RECURSIVE_H
