#ifndef __NGX_QUIC_UTIL_H
#define __NGX_QUIC_UTIL_H

#include <unistd.h>
#include <assert.h>

#ifdef WORDS_BIGENDIAN
#define bswap64(N) (N)
#else /* !WORDS_BIGENDIAN */
#define bswap64(N)                                                           \
    ((uint64_t)(ntohl((uint32_t)(N))) << 32 | ntohl((uint32_t)((N) >> 32)))
#endif /* !WORDS_BIGENDIAN */



static ngx_inline
uint64_t ngx_quic_get_uint64(const uint8_t *p) {
  uint64_t n;
  memcpy(&n, p, 8);
  return bswap64(n);
}

uint64_t ngx_quic_get_uint48(const uint8_t *p) {
  uint64_t n = 0;
  memcpy(((uint8_t *)&n) + 2, p, 6);
  return bswap64(n);
}

static ngx_inline
uint32_t ngx_quic_get_uint32(const uint8_t *p) {
  uint32_t n;
  memcpy(&n, p, 4);
  return ntohl(n);
}

static ngx_inline
uint32_t ngx_quic_get_uint24(const uint8_t *p) {
  uint32_t n = 0;
  memcpy(((uint8_t *)&n) + 1, p, 3);
  return ntohl(n);
}

static ngx_inline
uint16_t ngx_quic_get_uint16(const uint8_t *p) {
  uint16_t n;
  memcpy(&n, p, 2);
  return ntohs(n);
}

/* varintlen_def is an array of required length of variable-length
   integer encoding.  Use 2 most significant bits as an index to get
   the length in bytes. */

extern uint8_t varintlen_def[];


static ngx_inline
uint64_t ngx_quic_get_varint(uint8_t *plen, const uint8_t *p) {
  union {
    char b[8];
    uint16_t n16;
    uint32_t n32;
    uint64_t n64;
  } n;
    uint8_t bytes = varintlen_def[*p >> 6];

    if(plen){
        *plen = bytes;
    }
  switch (bytes) {
  case 1:
    return *p;
  case 2: {
    memcpy(&n, p, 2);
    n.b[0] &= 0x3f;
    return ntohs(n.n16);
  }
  case 4: {
    memcpy(&n, p, 4);
    n.b[0] &= 0x3f;
    return ntohl(n.n32);
  }
  case 8: {
    memcpy(&n, p, 8);
    n.b[0] &= 0x3f;
    return bswap64(n.n64);
  }
  }

  assert(0);
}

static ngx_inline
uint64_t ngx_quic_get_pkt_num(size_t *plen, const uint8_t *p) {
  union {
    char b[4];
    uint16_t n16;
    uint32_t n32;
  } n;

  if ((*p >> 7) == 0) {
    *plen = 1;
    return *p;
  }

  switch (*p >> 6) {
  case 2:
    *plen = 2;
    memcpy(&n, p, 2);
    n.b[0] &= 0x3fu;
    return ntohs(n.n16);
  case 3:
    *plen = 4;
    memcpy(&n, p, 4);
    n.b[0] &= 0x3fu;
    return ntohl(n.n32);
  }

  assert(0);
}

static ngx_inline
uint8_t *ngx_quic_put_uint64be(uint8_t *p, uint64_t n) {
  n = bswap64(n);
  return memcpy(p, (const uint8_t *)&n, sizeof(n));
}

static ngx_inline
uint8_t *ngx_quic_put_uint48be(uint8_t *p, uint64_t n) {
  n = bswap64(n);
  return memcpy(p, ((const uint8_t *)&n) + 2, 6);
}

static ngx_inline
uint8_t *ngx_quic_put_uint32be(uint8_t *p, uint32_t n) {
  n = htonl(n);
  return memcpy(p, (const uint8_t *)&n, sizeof(n));
}

static ngx_inline
uint8_t *ngx_quic_put_uint24be(uint8_t *p, uint32_t n) {
  n = htonl(n);
  return memcpy(p, ((const uint8_t *)&n) + 1, 3);
}

static ngx_inline
uint8_t *ngx_quic_put_uint16be(uint8_t *p, uint16_t n) {
  n = htons(n);
  return memcpy(p, (const uint8_t *)&n, sizeof(n));
}

static ngx_inline
uint8_t *ngx_quic_put_varint(uint8_t *p, uint64_t n) {
  uint8_t *rv;
  if (n < 64) {
    *p++ = (uint8_t)n;
    return p;
  }
  if (n < 16384) {
    rv = ngx_quic_put_uint16be(p, (uint16_t)n);
    *p |= 0x40;
    return rv;
  }
  if (n < 1073741824) {
    rv = ngx_quic_put_uint32be(p, (uint32_t)n);
    *p |= 0x80;
    return rv;
  }
  assert(n < 4611686018427387904ULL);
  rv = ngx_quic_put_uint64be(p, n);
  *p |= 0xc0;
  return rv;
}

static ngx_inline
uint8_t *ngx_quic_put_varint14(uint8_t *p, uint16_t n) {
  uint8_t *rv;

  assert(n < 16384);

  rv = ngx_quic_put_uint16be(p, n);
  *p |= 0x40;

  return rv;
}

static ngx_inline
uint8_t *ngx_quic_put_pkt_num(uint8_t *p, uint64_t pkt_num, size_t len) {
  switch (len) {
  case 1:
    *p++ = (uint8_t)(pkt_num & ~0x80u);
    return p;
  case 2:
    ngx_quic_put_uint16be(p, (uint16_t)pkt_num);
    *p = (uint8_t)((*p & ~0xc0u) | 0x80u);
    return p + 2;
  case 4:
    ngx_quic_put_uint32be(p, (uint32_t)pkt_num);
    *p |= 0xc0u;
    return p + 4;
  default:
    assert(0);
  }
}

static ngx_inline
uint8_t ngx_quic_get_varint_len(const uint8_t *p) {
  return varintlen_def[*p >> 6];
}

static ngx_inline
size_t ngx_quic_get_pkt_num_len(const uint8_t *p) {
  if ((*p >> 7) == 0) {
    return 1;
  }

  switch (*p >> 6) {
  case 2:
    return 2;
  case 3:
    return 4;
  default:
    assert(0);
  }
}

static ngx_inline
size_t ngx_quic_put_varint_len(uint64_t n) {
  if (n < 64) {
    return 1;
  }
  if (n < 16384) {
    return 2;
  }
  if (n < 1073741824) {
    return 4;
  }
  assert(n < 4611686018427387904ULL);
  return 8;
}

static ngx_inline
uint64_t ngx_quic_nth_server_bidi_id(uint16_t n) {
  if (n == 0) {
    return 0;
  }
  return ((uint64_t)n << 2) - 3;
}

static ngx_inline
uint64_t ngx_quic_nth_client_bidi_id(uint16_t n) {
  if (n == 0) {
    return 0;
  }
  return (uint64_t)(n - 1) << 2;
}

static ngx_inline
uint64_t ngx_quic_nth_server_uni_id(uint16_t n) {
  if (n == 0) {
    return 0;
  }

  return ((uint64_t)n << 2) - 1;
}

static ngx_inline
uint64_t ngx_quic_nth_client_uni_id(uint16_t n) {
  if (n == 0) {
    return 0;
  }

  return ((uint64_t)n << 2) - 2;
}



static ngx_inline ngx_int_t 
ngx_quic_get_varint2(ngx_str_t * buf, ngx_int_t offset, uint8_t * pbytes, uint64_t *pvalue)
{
    uint8_t     bytes;
    uint64_t    length;
    uint8_t    *p; 
    
    p = buf->data + offset;
    if ((size_t)(offset + 1) < buf->len) {
        return NGX_ERROR;
    }

    bytes = ngx_quic_get_varint_len(p);
    if ((size_t)(offset + bytes) < buf->len) {
        return NGX_ERROR;
    }

    length = ngx_quic_get_varint(NULL, p);

    if(pbytes) {
        *pbytes = bytes;
    }
    
    if(pvalue){
        *pvalue = length;
    }

    return NGX_OK; 
}

#endif
