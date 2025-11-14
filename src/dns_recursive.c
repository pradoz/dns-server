#include "dns_recursive.h"
#include "dns_server.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>


// root server hints (simplified, real implementation would load from file)
static const char *root_servers[][2] = {
  {"a.root-servers.net", "198.41.0.4"},
  {"b.root-servers.net", "199.9.14.201"},
  {"c.root-servers.net", "192.33.4.12"},
  {"d.root-servers.net", "199.7.91.13"},
  {"e.root-servers.net", "192.203.230.10"},
  {"f.root-servers.net", "192.5.5.241"},
  {"g.root-servers.net", "192.112.36.4"},
  {"h.root-servers.net", "198.97.190.53"},
  {"i.root-servers.net", "192.36.148.17"},
  {"j.root-servers.net", "192.58.128.30"},
  {"k.root-servers.net", "193.0.14.129"},
  {"l.root-servers.net", "199.7.83.42"},
  {"m.root-servers.net", "202.12.27.33"}
};

dns_recursive_resolver_t *dns_recursive_create(void) {
  dns_recursive_resolver_t *resolver = calloc(1, sizeof(dns_recursive_resolver_t));
  if (!resolver) return NULL;

  resolver->socket_fd = -1;
  resolver->next_query_id = 1;

  // query tracking
  for (in i = 0; i < 256; ++i) {
    resolver->active_queries[i].query_id = 0; // inactive
  }

  return resolver;
}

void dns_recursive_free(dns_recursive_resolver_t *resolver) {
  if (!resolver) return;
  if (resolver->socket_fd >= 0) close(resolver->socket_fd);
  free(resolver);
}

int dns_recursive_init_socket(dns_recursive_resolver_t *resolver) {
  if (!resolver) return -1;

  resolver->socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (resolver->socket_fd < 0) {
    perror("Failed to create recursive resolver socket");
    return -1;
  }

  // set socket timeout
  struct timeval timeout;
  timeout.tv_sec = DNS_RECURSIVE_TIMEOUT_SEC;
  timeout.tv_usec = 0;

  if (setsockopt(resolver->socket_fd,
                 SOL_SOCKET,
                 SOL_RCVTIMEO,
                 &timeout,
                 sizeof(timeout)) < 0) {
    perror("Failed to set socket timeout");
    close(resolver->socket_fd);
    resolver->socket_fd = -1;
    return -1;
  }

  return 0;
}

int dns_recursive_load_root_hints(dns_recursive_resolver_t *resolver) {
  if (!resolver) return -1;

  for (int i = 0; i < DNS_ROOT_HINTS_COUNT; ++i) {
    dns_nameserver_t *server = &resolver->root_servers[i];
    strncpy(server->name, root_servers[i][0], MAX_DOMAIN_NAME - 1);

    // parse IPv4 address
    if (inet_pton(AF_INET, root_servers[i][1], &server->ipv4.sin_addr) == 1) {
      server->ipv4.sin_family = AF_INET;
      server->ipv4.sin_port = htons(53);
      server->has_ipv4 = true;
    }

    server->has_ipv6 = false; // TODO: IPv6 support
    server->queries_sent = 0;
    server->responses_received = 0;
    server->timeouts = 0;
    server->last_used = 0;
  }

  printf("Loaded %d root servers\n", DNS_ROOT_HINTS_COUNT);
  return 0;
}

int dns_recursive_add_upstream_server(dns_upstream_list_t *list,
                                      const char *server_ip,
                                      uint16_t port) {
  if (!list || !server_ip || list->server_count >= DNS_MAX_UPSTREAM_SERVERS) {
    return -1;
  }

  dns_nameserver_t *server = &list->servers[list->server_count];

  // parse IP address
  if (inet_pton(AF_INET, server_ip, &server->ipv4.sin_addr) == 1) {
    server->ipv4.sin_family = AF_INET;
    server->ipv4.sin_port = htons(port);
    server->has_ipv4 = true;
    server->has_ipv6 = false;

    snprintf(server->name, sizeof(server->name), "%s:%d\n", server_ip, port);
    list->server_count++;
    return 0;
  }

  return -1;
}

dns_nameserver_t *dns_recursive_select_server(dns_upstream_list_t *list) {
  if (!list || list->server_count == 0) return NULL;

  // simple round-robin
  dns_server_t *server = &list->servers[list->current_server];
  list->current_server = (list->current_server + 1) % list->server_count;

  return server;
}

int dns_recursive_send_query(dns_recursive_resolver_t *resolver,
                             const dns_question_t *question,
                             const dns_nameserver_t *server,
                             uint16_t query_id) {
  if (!resolver || !question || !server || resolver->socket_fd < 0) {
    return -1;
  }

  // query packet
  uint8_t query_buf[512];
  size_t offset = 0;

  // create header
  dns_header_t header = {
    .id = query_id,
    .qr = DNS_QR_QUERY,
    .opcode = DNS_OPCODE_QUERY,
    .aa = 0,
    .tc = 0,
    .rd = 1, // request recursion
    .ra = 0,
    .rcode = DNS_RCODE_NOERROR,
    .qdcount = 1,
    .ancount = 0,
    .nscount = 0,
    .arcount = 0
  };

  if (dns_encode_header(query_buf, sizeof(query_buf), &header) < 0) {
    return -1;
  }
  offset = 12;

  // encode question
  if (dns_encode_question(query_buf, sizeof(query_buf), &offset, question) < 0) {
    return -1;
  }

  // send to server
  struct sockaddr *addr;
  socklen_t addr_len;

  if (server->has_ipv4) {
    addr = (struct sockadd*) &server->ipv4;
    addr_len = sizeof(server->ipv4);
  } else {
    return -1; // no valid address
  }

  ssize_t sent = sendto(resolver->socket_fd,
                        query_buf,
                        offset,
                        0,
                        addr,
                        addr_len);
  if (sent < 0) {
    perror("Failed to send recursive query");
    return -1;
  }

  printf("Sent recursive query for %s to %s (ID: %u)\n",
         question->qname,
         server->name,
         query_id);

  return 0;
}

int dns_recursive_resolve(dns_recursive_resolver_t *resolver,
                          const dns_question_t *question,
                          const struct sockaddr_storage *client_addr,
                          socklen_t client_addr_len,
                          uint16_t original_id) {
  if (!resolver || !question || !client_addr) return -1;

  // generate unique query id
  uint16_t query_id = resolver->next_query_id++;
  if (resolver->next_query_id == 0) resolver->next_query_id = 1; // skip 0

  // store query context
  dns_recursive_query_t *query = &resolver->active_queries[query_id & 0xFF];
  query->query_id = query_id;
  strncpy(query->qname, question->qname, MAX_DOMAIN_NAME - 1);
  query->qtype = question->qtype;
  query->qclass = question->qclass;
  query->start_time = time(NULL);
  query->recursion_depth = 0;
  query->original_id = original_id;
  memcpy(&query->client_addr, client_addr, sizeof(struct sockaddr_storage));
  query->client_addr_len = client_addr_len;

  // initialize with root servers
  query->current_servers.server_count = 0;
  query->current_servers.current_server = 0;

  for (int i = 0; i < DNS_ROOT_HINTS_COUNT; ++i) {
    if (query->current_servers.server_count < DNS_MAX_UPSTREAM_SERVERS) {
      query->current_servers.servers[query->current_servers.server_count] = resolver->root_servers[i];
      query->current_servers.server_count++;
    }
  }

  // send initial query to a root server
  dns_nameserver_t *root_server = dns_recursive_select_server(&query->current_servers);
  if (!root_server) {
    query->query_id = 0; // mark as inactive
    return -1;
  }

  int result = dns_recursive_send_query(resolver, question, root_server, query_id);
  if (result < 0) {
    query->query_id = 0; // mark as inactive
    return -1;
  }

  resolver->recursive_queries++;
  root_server->queries_sent++;
  root_server->last_used = time(NULL);

  return 0;
}

static int dns_extract_nameservers_from_response(const uint8_t *buffer,
                                                 size_t len,
                                                 dns_upstream_list_t *servers) {
  // TODO: parse the authority section for NS records
  // TODO: parse additional section for their A records

  // for now, add some common public DNS servers as fallback
  dns_recursive_add_upstream_server(servers, "8.8.8.8", 53);
  dns_recursive_add_upstream_server(servers, "1.1.1.1", 53);

  return servers->server_count;
}

int dns_recursive_handle_response(dns_recursive_resolver_t *resolver,
                                 const uint8_t *response_buf,
                                 size_t response_len,
                                 const struct sockaddr_storage *server_addr) {
  if (!resolver || !response_buf || response_len < 12) return -1;

  // parse header
  dns_header_t header;
  if (dns_parse_header(response_buf, sizeof(response_buf), &header) < 0) {
    return -1;
  }

  // find matching query
  dns_recursive_query_t *query = &resolver->active_queries[header.id & 0xFF];
  if (query->query_id != header.id) {
    printf("Received response from unknown query ID: %u\n", header.id);
    return -1;
  }

  printf("Received response for %s (ID: %u, RCODE: %u)\n",
         query->qname,
         header.id,
         header.rcode);

  // update server stats
  for (int i = 0; i < query->current_servers.server_count; i++) {
    dns_nameserver_t *server = &query->current_servers.servers[i];

    // TODO: match by address
    server->responses_received++;
  }

  if (header.rcode == DNS_RCODE_NOERROR && header.ancount > 0) {
    // answer found, forward it back to the client
    uint8_t *response_copy = malloc(response_len);
    if (response_copy) {
      memcpy(response_copy, response_buf, response_len);

      // modify response ID to match original query
      uint16_t original_id = htons(query->original_id);
      memcpy(response_copy, &original_id, 2);

      // TODO: send response back to client and integrate with main server
      printf("Would forward answer back to client (ID: %u)\n", query->original_id);

      free(response_copy);
    }

    // query complete
    query->query_id = 0;
    return 0;

  } else if (header.rcode == DNS_RCODE_NOERROR && header.nscount > 0) {
    // referral, found, extract nameservers and continue
    query->recursion_depth++;

    if (query->recursion_depth >= DNS_MAX_RECURSION_DEPTH) {
      printf("Maximum recursion depth reached for %s\n", query->qname);
      query->query_id = 0;
      return -1;
    }

    // extract nameservers from authority section
    dns_upstream_list_t new_servers = {0};
    dns_extract_nameservers_from_response(response_buf, response_len, &new_servers);

    if (new_servers.server_count > 0) {
      query->current_servers = new_servers;

      // send query to new nameserver
      dns_question_t question = {
        .qtype = query->qtype,
        .qclass = query->qclass
      };
      strncpy(question.qname, query->qname, MAX_DOMAIN_NAME - 1);

      dns_nameserver_t *next_server = dns_recursive_select_server(&query->current_servers);
      if (next_server) {
        dns_recursive_send_query(resolver, &question, next_server, query->query_id);
        next_server->queries_sent++;
        next_server->last_used = time(NULL);
        return 0;
      }
    }

    // failed to continue recursion
    query->query_id = 0;
    return -1;

  } else {
    // error response or NXDOMAIN
    printf("Query failed with RCODE: %u\n", header.rcode);

    // TODO: send error response back to client
    query->query_id = 0;
    resolver->failed_queries++;
    return -1;
  }

  return 0;
}
