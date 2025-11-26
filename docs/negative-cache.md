# DNS Negative Caching

Negative caching stores **"this domain doesn't exist"** or **"this record type doesn't exist"** responses in the cache. This helps avoid asking the same failed question repeatedly.

---

## Scenario

### Typo in Domain Name

```
User types: "googl.com" (typo, missing 'e')

Without negative caching:
┌─────────┐
│ Client  │
└────┬────┘
     │ 1. Query "googl.com"
     ├──────────────────────────────────┐
     │                                  │
┌────▼────┐                        ┌────▼────┐
│  Cache  │  MISS (not in cache)   │   DNS   │
└────┬────┘                        │ Server  │
     │                             └────┬────┘
     │                                  │
     │                             2. NXDOMAIN
     │                                  │ (doesn't exist)
     │◄─────────────────────────────────┤
     │
     │ 3. Return NXDOMAIN to client
     │

Next second, user retries same typo:

     │ 4. Query "googl.com" AGAIN
     ├──────────────────────────────────┐
     │                                  │
┌────▼────┐                        ┌────▼────┐
│  Cache  │  MISS AGAIN!           │   DNS   │
└────┬────┘                        │ Server  │
     │                             └────┬────┘
     │                                  │
     │                             5. NXDOMAIN AGAIN
     │◄─────────────────────────────────┤

Result: We query the DNS server EVERY TIME for something, even though we know it does not exist
```

---

## With Negative Caching

```
First query:
┌─────────┐
│ Client  │
└────┬────┘
     │ 1. Query "googl.com"
     ├──────────────────────────────────┐
     │                                  │
┌────▼────┐                        ┌────▼────┐
│  Cache  │  MISS                  │   DNS   │
└────┬────┘                        │ Server  │
     │                             └────┬────┘
     │                                  │
     │                             2. NXDOMAIN
     │                                  │
     │◄─────────────────────────────────┤
     │
     │ 3. STORE negative result in cache
     │    Entry: "googl.com" → NXDOMAIN (TTL: 300s)
     │
     │ 4. Return NXDOMAIN to client
     │

Second query (within 5 minutes):
     │ 5. Query "googl.com" AGAIN
     ├──────────────────────────────────┐
     │                                  │
┌────▼────┐                        ┌────▼────┐
│  Cache  │  HIT! Found negative   │   DNS   │
│         │  entry: NXDOMAIN       │ Server  │
└────┬────┘                        │         │
     │                             │ (never  │
     │                             │  asked) │
     │                             └─────────┘
     │ 6. Return cached NXDOMAIN
     │    (no network query needed!)
     │

Result: Saves network traffic, reduces latency, reduces load on DNS servers
```

---

## Negative Response Types

### 1. **NXDOMAIN** (Name Error)

The domain **does not exist at all**.

```
Query: "thisdomaindoesnotexist12345.com" for A record

Response: RCODE = NXDOMAIN (3)

Meaning: This domain name doesn't exist in DNS
         No point asking for ANY record type
```

**Cache Entry:**
```c
{
  qname: "thisdomaindoesnotexist12345.com"
  qtype: DNS_TYPE_A
  qclass: DNS_CLASS_IN
  entry_type: DNS_CACHE_TYPE_NXDOMAIN
  rcode: DNS_RCODE_NXDOMAIN
  ttl: 300  // 5 minutes
}
```

### 2. **NODATA** (No Data)

The domain **exists**, but does not have the requested record type.

```
Query: "google.com" for MX record (but google.com has no MX!)

Response: RCODE = NOERROR (0)
          Answer section: empty

Meaning: google.com exists, but has no MX records
         (It has A records, AAAA records, etc., just not MX)
```

**Cache Entry:**
```c
{
  qname: "google.com"
  qtype: DNS_TYPE_MX
  qclass: DNS_CLASS_IN
  entry_type: DNS_CACHE_TYPE_NODATA
  rcode: DNS_RCODE_NOERROR
  ttl: 300
}
```

---

## Hypothetical Examples

### Positive Cache Entry

```
┌──────────────────────────────────────┐
│ Cache Entry: google.com A            │
├──────────────────────────────────────┤
│ Type: POSITIVE                       │
│ Records: 142.250.80.46 (TTL: 300)    │
│          142.250.80.78 (TTL: 300)    │
├──────────────────────────────────────┤
│ Meaning: "google.com exists and      │
│          has these IP addresses"     │
└──────────────────────────────────────┘
```

### Negative Cache Entry (NXDOMAIN)

```
┌──────────────────────────────────────┐
│ Cache Entry: badtypo.com A           │
├──────────────────────────────────────┤
│ Type: NXDOMAIN                       │
│ Records: (none)                      │
│ RCODE: NXDOMAIN                      │
├──────────────────────────────────────┤
│ Meaning: "badtypo.com does NOT exist"│
└──────────────────────────────────────┘
```

### Negative Cache Entry (NODATA)

```
┌──────────────────────────────────────┐
│ Cache Entry: google.com MX           │
├──────────────────────────────────────┤
│ Type: NODATA                         │
│ Records: (none)                      │
│ RCODE: NOERROR                       │
├──────────────────────────────────────┤
│ Meaning: "google.com exists but has  │
│          no MX records"              │
└──────────────────────────────────────┘
```

---

## Real-World Example

### Malware Domain Blocking

```c
// Security software queries known malware domain
Query: "malware-site-12345.ru" A record

First time:
1. Cache MISS
2. Query authoritative DNS
3. Get NXDOMAIN (good! domain taken down)
4. Cache negative result for 5 minutes

Next 300 seconds (any queries):
5. Cache HIT on negative entry
6. Immediately return NXDOMAIN
7. Malware can't resolve domain
8. No network traffic needed

Benefits:
* Faster response (no network delay)
* Reduced DNS traffic
* Malware blocked quicker
* Less load on DNS infrastructure
```

---

## TTL for Negative Caching

Negative cache entries typically have a **shorter TTL**:

```c
Positive cache: 300-3600 seconds (5 min - 1 hour)
Negative cache: 60-300 seconds   (1 min - 5 minutes)

Why?
* Typo might be fixed
* DNS changes happen
* Domain might be registered soon
```
