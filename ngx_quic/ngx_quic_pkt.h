#ifndef __NGX_QUIC_PKT_H
#define __NGX_QUIC_PKT_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_queue.h>

#include <stdint.h>


#define NGX_QUIC_PROTO_VER_D13  0xff00000du
#define NGX_QUIC_PROTO_VER      NGX_QUIC_PROTO_VER_D13



#define NGX_QUIC_PKT_TYPE_MASK  0x7f
#define NGX_QUIC_PKT_SHORT                  0x00

#define NGX_QUIC_PKT_VERSION_NEGOTIATION    0x00
#define NGX_QUIC_PKT_0RTT_PROTECTED         0x7c
#define NGX_QUIC_PKT_HANDSHAKE              0x7d
#define NGX_QUIC_PKT_RETRY                  0x7e
#define NGX_QUIC_PKT_INITIAL                0x7f

typedef struct{
      
    
    
} ngx_quic_frame_t;


typedef struct {
    ngx_queue_t next;
    ngx_pool_t  *pool;

    ngx_str_t   dcid;
    ngx_str_t   scid;
    ngx_str_t   odcid;
    ngx_str_t   token;
    ngx_str_t   encoded_number;

    uint32_t    version;
    uint32_t    number;
    uint8_t     type;
    uint8_t     flags; 

    uint16_t    length;

    ngx_queue_t frame_list;

    ngx_str_t   pkt;
    ngx_str_t   payload;
} ngx_quic_pkt_t;


#define NGX_QUIC_LONG_HDR(first_byte) ((first_byte)&0x80)




#endif

