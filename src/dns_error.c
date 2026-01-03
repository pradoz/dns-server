#include "dns_error.h"
#include "dns_parser.h"
#include <stddef.h>


const char *dns_error_string(dns_error_code_t code) {
  switch (code) {
    case DNS_ERR_NONE: return "No error";
    case DNS_ERR_INVALID_PACKET: return "Invalid packet";
    case DNS_ERR_BUFFER_TOO_SMALL: return "Buffer too small";
    case DNS_ERR_MALFORMED_NAME: return "Malformed domain name";
    case DNS_ERR_INVALID_QUESTION: return "Invalid question section";
    case DNS_ERR_MEMORY_ALLOCATION: return "Memory allocation failed";
    case DNS_ERR_COMPRESSION_LOOP: return "Compression pointer loop detected";
    case DNS_ERR_LABEL_TOO_LONG: return "Label exceeds maximum length";
    case DNS_ERR_NAME_TOO_LONG: return "Domain name too long";
    case DNS_ERR_CNAME_LOOP: return "CNAME loop detected";
    case DNS_ERR_CNAME_CHAIN_TOO_LONG: return "CNAME chain too long";
    case DNS_ERR_UNSUPPORTED_OPCODE: return "Unsupported opcode";
    case DNS_ERR_UNSUPPORTED_TYPE: return "Unsupported record type";
    case DNS_ERR_INVALID_ARG: return "Invalid argument";
    case DNS_ERR_NOT_FOUND: return "Not found";
    case DNS_ERR_WOULD_BLOCK: return "Operation would block";
    case DNS_ERR_TIMEOUT: return "Operation timed out";
    case DNS_ERR_IO: return "I/O error";
    default: return "Unknown error";
  }
}

uint8_t dns_error_to_rcode(dns_error_code_t code) {
  switch (code) {
    case DNS_ERR_NONE:
      return DNS_RCODE_NOERROR;
    case DNS_ERR_INVALID_PACKET:
    case DNS_ERR_MALFORMED_NAME:
    case DNS_ERR_INVALID_QUESTION:
    case DNS_ERR_COMPRESSION_LOOP:
    case DNS_ERR_LABEL_TOO_LONG:
    case DNS_ERR_NAME_TOO_LONG:
    case DNS_ERR_INVALID_ARG:
      return DNS_RCODE_FORMERROR;
    case DNS_ERR_UNSUPPORTED_OPCODE:
    case DNS_ERR_UNSUPPORTED_TYPE:
      return DNS_RCODE_NOTIMP;
    case DNS_ERR_NOT_FOUND:
      return DNS_RCODE_NXDOMAIN;
    case DNS_ERR_MEMORY_ALLOCATION:
    case DNS_ERR_BUFFER_TOO_SMALL:
    case DNS_ERR_CNAME_LOOP:
    case DNS_ERR_CNAME_CHAIN_TOO_LONG:
    case DNS_ERR_WOULD_BLOCK:
    case DNS_ERR_TIMEOUT:
    case DNS_ERR_IO:
    default:
      return DNS_RCODE_SERVFAIL;
  }
}
