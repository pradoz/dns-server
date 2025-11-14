# Simple DNS Server

[![C CI](https://github.com/pradoz/dns-server/actions/workflows/c.yml/badge.svg)](https://github.com/pradoz/dns-server/actions/workflows/c.yml)

A simple DNS Server implemented in C.

## Building

```bash
make
```

## Running Tests
```bash
make test
```

## Running an Example

After building:

```bash
make run

# In another terminal:
dig @localhost -p 5353 example.com A
dig @localhost -p 5353 www.example.com A
dig @localhost -p 5353 mail.example.com CNAME
```

Expected output:

```bash
# example.com A
;; ANSWER SECTION:
example.com.    300    IN    A    192.168.1.1

# www.example.com A
;; ANSWER SECTION:
www.example.com.    300    IN    A    192.168.1.2

# mail.example.com CNAME
;; ANSWER SECTION:
mail.example.com.    300    IN    CNAME    example.com.
```

## Cleaning up
```bash
make clean
```

## Notes
* Zone file format follows [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035)
