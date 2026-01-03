#include "dns_recursive.h"
#include "dns_server.h"
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>


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
  for (int i = 0; i < 256; ++i) {
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
                 SO_RCVTIMEO,
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
    dns_safe_strncpy(server->name, root_servers[i][0], sizeof(server->name));

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

    snprintf(server->name, sizeof(server->name), "%s:%d", server_ip, port);
    list->server_count++;
    return 0;
  }

  return -1;
}

dns_nameserver_t *dns_recursive_select_server(dns_upstream_list_t *list) {
  if (!list || list->server_count == 0) return NULL;

  // simple round-robin
  dns_nameserver_t *server = &list->servers[list->current_server];
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
    addr = (struct sockaddr*) &server->ipv4;
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

int dns_recursive_load_root_hints_file(dns_recursive_resolver_t *resolver, const char *filename) {
  if (!resolver) return -1;

  // use built-in hints file as fallback
  if (!filename) return dns_recursive_load_root_hints(resolver);

  FILE *file = fopen(filename, "r");
  if (!file) {
    printf("Root hints file not found, using local roots.hint\n");
    return dns_recursive_load_root_hints(resolver);
  }

  char line[512];
  int server_count = 0;

  while (fgets(line, sizeof(line), file) && server_count < DNS_ROOT_HINTS_COUNT) {
    // skip comments/empty lines
    if (line[0] == ';' || line[0] == '\n' || line[0] == '\0') continue;

    // parse: name, ttl, class, type, rdata
    char name[MAX_DOMAIN_NAME];
    // char class_str[16];
    char type_str[16];
    char rdata[64];
    uint32_t ttl;

    if (sscanf(line, "%s %u IN %s %s", name, &ttl, type_str, rdata) == 4) {
      if (strcmp(type_str, "A") == 0) {
        // find server or create an entry
        dns_nameserver_t *server = NULL;
        for (int i = 0; i < server_count; ++i) {
          if (strcmp(resolver->root_servers[i].name, name) == 0) {
            server = &resolver->root_servers[i];
            break;
          }
        }

        if (!server && server_count < DNS_ROOT_HINTS_COUNT) {
          server = &resolver->root_servers[server_count++];
          dns_safe_strncpy(server->name, name, sizeof(server->name));
        }

        if (server && inet_pton(AF_INET, rdata, &server->ipv4.sin_addr) == 1) {
          server->ipv4.sin_family = AF_INET;
          server->ipv4.sin_port = htons(53);
          server->has_ipv4 = true;
        }
      }
    }
  }

  fclose(file);
  printf("Loaded %d root servers from %s\n", server_count, filename);
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
  dns_safe_strncpy(query->qname, question->qname, sizeof(query->qname));
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

int dns_recursive_handle_response(dns_recursive_resolver_t *resolver,
                                 const uint8_t *response_buf,
                                 size_t response_len,
                                 const struct sockaddr_storage *server_addr) {
  (void)server_addr; // suppress unused parameter warning

  if (!resolver || !response_buf || response_len < 12) return -1;

  // parse response header
  dns_response_summary_t summary;
  if (dns_parse_response_summary(response_buf, response_len, &summary) < 0) {
    return -1;
  }

  // find matching query
  dns_recursive_query_t *query = &resolver->active_queries[summary.query_id & 0xFF];
  if (query->query_id != summary.query_id) {
    printf("Received response for unknown query ID: %u\n", summary.query_id);
    return -1;
  }

  printf("Received response for %s (ID: %u, RCODE: %u, Answers: %u, Authority: %u)\n",
         query->qname,
         summary.query_id,
         summary.rcode,
         summary.ancount,
         summary.nscount);

  // update server stats
  for (int i = 0; i < query->current_servers.server_count; i++) {
    dns_nameserver_t *server = &query->current_servers.servers[i];
    server->responses_received++;
  }

  if (summary.rcode == DNS_RCODE_NOERROR && summary.ancount > 0) {
    // found an answer, forward it back to the client
    dns_recursive_forward_response(resolver, query, response_buf, response_len);

    // query complete
    query->query_id = 0;
    resolver->forwarded_queries++;
    return 0;

  } else if (summary.rcode == DNS_RCODE_NOERROR && summary.nscount > 0) {
    // found a referral, extract nameservers and continue
    query->recursion_depth++;

    if (query->recursion_depth >= DNS_MAX_RECURSION_DEPTH) {
      printf("Maximum recursion depth reached for %s\n", query->qname);
      dns_recursive_send_error_response(resolver, query, DNS_RCODE_SERVFAIL);
      query->query_id = 0;
      resolver->failed_queries++;
      return -1;
    }

    // get nameservers from authority section
    dns_upstream_list_t new_servers = {0};
    if (dns_extract_nameservers_from_authority(response_buf, response_len, &new_servers) > 0) {
      query->current_servers = new_servers;

      // query new nameserver
      dns_question_t question = {
        .qtype = query->qtype,
        .qclass = query->qclass
      };
      dns_safe_strncpy(question.qname, query->qname, sizeof(question.qname));

      dns_nameserver_t *next_server = dns_recursive_select_server(&query->current_servers);
      if (next_server) {
        dns_recursive_send_query(resolver, &question, next_server, query->query_id);
        next_server->queries_sent++;
        next_server->last_used = time(NULL);
        return 0;
      }
    }

    // failed recursion
    dns_recursive_send_error_response(resolver, query, DNS_RCODE_SERVFAIL);
    query->query_id = 0;
    resolver->failed_queries++;
    return -1;

  } else {
    // error response or NXDOMAIN - forward to client
    dns_recursive_forward_response(resolver, query, response_buf, response_len);
    query->query_id = 0;

    if (summary.rcode != DNS_RCODE_NXDOMAIN) {
      resolver->failed_queries++;
    }
    return 0;
  }
}

int dns_recursive_set_main_socket(dns_recursive_resolver_t *resolver, int socket_fd) {
  if (!resolver) return -1;
  resolver->main_server_socket = socket_fd;
  return 0;
}

int dns_recursive_forward_response(dns_recursive_resolver_t *resolver,
                                   const dns_recursive_query_t *query,
                                   const uint8_t *response_buf,
                                   size_t response_len) {
  if (!resolver || !query || !response_buf || response_len < 12) return -1;

  uint8_t *response_copy = malloc(response_len);
  if (!response_copy) return -1;
  memcpy(response_copy, response_buf, response_len);

  // update ID to match original query
  uint16_t orig_id = htons(query->original_id);
  memcpy(response_copy, &orig_id, 2);

  // send response back to client
  ssize_t sent = sendto(resolver->main_server_socket,
                        response_copy,
                        response_len,
                        0,
                        (struct sockaddr*) &query->client_addr,
                        query->client_addr_len);
  free(response_copy);

  if (sent < 0) {
    perror("Failed to forward recursive response");
    return -1;
  }

  printf("Forwarded recursive response to client (original ID: %u)\n", query->original_id);
  return 0;
}

int dns_recursive_send_error_response(dns_recursive_resolver_t *resolver,
                                     const dns_recursive_query_t *query,
                                     uint8_t rcode) {
  if (!resolver || !query) return -1;

  uint8_t err_buf[512];
  size_t offset = 0;

  // build error response with RA bit set
  dns_header_t error_header = {
    .id = query->original_id,
    .qr = DNS_QR_RESPONSE,
    .opcode = DNS_OPCODE_QUERY,
    .aa = 0,
    .tc = 0,
    .rd = 1,
    .ra = 1, // attempted recursion
    .rcode = rcode,
    .qdcount = 1,
    .ancount = 0,
    .nscount = 0,
    .arcount = 0
  };

  // Note: can't use dns_build_error_response_header here it assumes RA=1
  if (dns_encode_header(err_buf, sizeof(err_buf), &error_header) < 0) {
    return -1;
  }
  offset = 12;

  // encode original question
  dns_question_t question = {
    .qtype = query->qtype,
    .qclass = query->qclass,
  };

  dns_safe_strncpy(question.qname, query->qname, sizeof(question.qname));

  if (dns_encode_question(err_buf, sizeof(err_buf), &offset, &question) < 0) {
    return -1;
  }

  // send error response
  ssize_t sent = sendto(resolver->main_server_socket,
                        err_buf,
                        offset,
                        0,
                        (struct sockaddr*) &query->client_addr,
                        query->client_addr_len);
  if (sent < 0) {
    perror("Failed to send error response");
    return -1;
  }

  printf("Sent error response (RCODE: %u) to client for %s\n", rcode, query->qname);
  return 0;
}

int dns_extract_nameservers_from_authority(const uint8_t *buffer,
                                           size_t len,
                                           dns_upstream_list_t *servers) {
  if (!buffer || !servers || len < 12) return -1;

  dns_response_summary_t summary;
  if (dns_parse_response_summary(buffer, len, &summary) < 0) return -1;

  if (summary.nscount == 0) {
    // no authority section, use fallback servers
    dns_recursive_add_upstream_server(servers, "8.8.8.8", 53);
    dns_recursive_add_upstream_server(servers, "1.1.1.1", 53);
    return servers->server_count;
  }

  size_t offset = 12;

  // skip question section
  for (int i = 0; i < summary.qdcount; ++i) {
    dns_question_t question;
    if (dns_parse_question(buffer, len, &offset, &question) < 0) {
      return -1;
    }
  }

  // skip answer section
  for (int i = 0; i < summary.ancount; ++i) {
    char name[MAX_DOMAIN_NAME];
    if (dns_parse_name(buffer, len, &offset, name, sizeof(name)) < 0) {
      return -1;
    }

    if (offset + 10 > len) return -1;
    offset += 10; // skip type, class, ttl, rdlength

    uint16_t rdlength;
    memcpy(&rdlength, buffer + offset - 2, 2);

    rdlength = ntohs(rdlength);

    if (offset + rdlength > len) return -1;
    offset += rdlength;
  }

  // parse authority section (NS records)
  char ns_names[16][MAX_DOMAIN_NAME]; // store NS names for IP lookup
  int ns_count = 0;

  for (int i = 0; i < summary.nscount && ns_count < 16; ++i) {
    char name[MAX_DOMAIN_NAME];
    if (dns_parse_name(buffer, len, &offset, name, sizeof(name)) < 0) {
      break;
    }
    if (offset + 10 > len) break;

    uint16_t type, class, rdlength;
    uint32_t ttl;

    memcpy(&type, buffer + offset, 2);
    offset += 2;
    memcpy(&class, buffer + offset, 2);
    offset += 2;
    memcpy(&ttl, buffer + offset, 4);
    offset += 4;
    memcpy(&rdlength, buffer + offset, 2);
    offset += 2;

    type = ntohs(type);
    rdlength = ntohs(rdlength);

    if (type == DNS_TYPE_NS && offset + rdlength <= len) {
      size_t ns_offset = offset;
      if (dns_parse_name(buffer, len, &ns_offset, ns_names[ns_count], MAX_DOMAIN_NAME) == 0) {
        printf("Found NS: %s\n", ns_names[ns_count]);
        ++ns_count;
      }
    }

    offset += rdlength;
  }

  // parse additional section for A records of NS servers
  for (int i = 0; i < summary.arcount && servers->server_count < DNS_MAX_UPSTREAM_SERVERS; i++) {
    char name[MAX_DOMAIN_NAME];
    if (dns_parse_name(buffer, len, &offset, name, sizeof(name)) < 0) break;

    if (offset + 10 > len) break;

    uint16_t type, class, rdlength;
    uint32_t ttl;

    memcpy(&type, buffer + offset, 2);
    offset += 2;
    memcpy(&class, buffer + offset, 2);
    offset += 2;
    memcpy(&ttl, buffer + offset, 4);
    offset += 4;
    memcpy(&rdlength, buffer + offset, 2);
    offset += 2;

    type = ntohs(type);
    rdlength = ntohs(rdlength);

    if (type == DNS_TYPE_A && rdlength == 4 && offset + 4 <= len) {
      // check if A record matches any NS names
      for (int j = 0; j < ns_count; j++) {
        if (strcasecmp(name, ns_names[j]) == 0) {
          // found IP for this nameserver
          struct in_addr addr;
          memcpy(&addr, buffer + offset, 4);

          char ip_str[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

          if (dns_recursive_add_upstream_server(servers, ip_str, 53) == 0) {
            printf("Added nameserver: %s (%s)\n", name, ip_str);
          }
          break;
        }
      }
    }

    offset += rdlength;
  }

  // if we don't find any IPs, add fallback servers
  if (servers->server_count == 0) {
    printf("No nameserver IPs found, using fallback servers\n");
    dns_recursive_add_upstream_server(servers, "8.8.8.8", 53);
    dns_recursive_add_upstream_server(servers, "1.1.1.1", 53);
  }

  return servers->server_count;

}
