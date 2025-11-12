# DNS Parsing Explained

DNS messages are binary packets with a specific structure

---

## DNS Message Structure

```
+---------------------+
|     Header (12)     |  Fixed 12 bytes
+---------------------+
|    Question(s)      |  Variable length
+---------------------+
|     Answer(s)       |  Variable length
+---------------------+
|   Authority(s)      |  Variable length
+---------------------+
|   Additional(s)     |  Variable length
+---------------------+
```

---

## DNS Header (12 bytes)

### Wire Format (Binary)
```
 0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |  Bytes 0-1
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |  Bytes 2-3
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |  Bytes 4-5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |  Bytes 6-7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |  Bytes 8-9
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |  Bytes 10-11
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Field Breakdown

```c
typedef struct {
    uint16_t id;        // Transaction ID - matches query to response

    // Byte 2-3 (flags)
    uint8_t qr;         // 1 bit:  0=Query, 1=Response
    uint8_t opcode;     // 4 bits: 0=Standard query, 1=Inverse query, 2=Status
    uint8_t aa;         // 1 bit:  Authoritative Answer
    uint8_t tc;         // 1 bit:  Truncated (message too large for UDP)
    uint8_t rd;         // 1 bit:  Recursion Desired
    uint8_t ra;         // 1 bit:  Recursion Available
    uint8_t rcode;      // 4 bits: Response code (0=success, 3=NXDOMAIN, etc.)

    // Counts (how many of each section follow)
    uint16_t qdcount;   // Number of questions
    uint16_t ancount;   // Number of answer records
    uint16_t nscount;   // Number of authority records
    uint16_t arcount;   // Number of additional records
} dns_header_t;
```

### Example: Query for "example.com"

```
Hex dump of header:
AB CD 01 00 00 01 00 00 00 00 00 00
│  │  │  │  │  │  │  │  │  │  │  │
│  │  │  │  │  │  │  │  │  │  │  └─ ARCOUNT (low byte)
│  │  │  │  │  │  │  │  │  │  └──── ARCOUNT (high byte)
│  │  │  │  │  │  │  │  │  └─────── NSCOUNT (low byte)
│  │  │  │  │  │  │  │  └────────── NSCOUNT (high byte)
│  │  │  │  │  │  │  └───────────── ANCOUNT (low byte)
│  │  │  │  │  │  └──────────────── ANCOUNT (high byte)
│  │  │  │  │  └─────────────────── QDCOUNT (low byte)
│  │  │  │  └────────────────────── QDCOUNT (high byte)
│  │  │  └───────────────────────── Flags byte 2
│  │  └──────────────────────────── Flags byte 1
│  └─────────────────────────────── ID (low byte)
└────────────────────────────────── ID (high byte)

Decoded:
  ID: 0xABCD (43981)
  QR=0 (query), OPCODE=0 (standard), RD=1 (recursion desired)
  QDCOUNT=1 (one question), others=0
```

---

## Question Section

### Wire Format
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /  Variable
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

### Domain Name Encoding (QNAME)

Domain names use **label format**:

```
"example.com" becomes:
  07 65 78 61 6D 70 6C 65  03 63 6F 6D  00
  │  └──────┬──────┘        │  └─┬─┘    │
  │      "example"          │  "com"    │
  │                         │           └─ Root (terminator)
  │                         └─ Length: 3
  └─ Length: 7

"www.example.com" becomes:
  03 77 77 77  07 65 78 61 6D 70 6C 65  03 63 6F 6D  00
  │  └─┬─┘     │  └──────┬──────┘       │  └─┬─┘     │
  │  "www"     │      "example"          │  "com"     └─ Terminator
  │            │                         └─ Length: 3
  │            └─ Length: 7
  └─ Length: 3
```

---

## Resource Records (Answer/Authority/Additional)

### Wire Format
```
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                      NAME                     /  Variable
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TYPE                     |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |  4 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   RDLENGTH                    |  2 bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     RDATA                     /  RDLENGTH bytes
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
