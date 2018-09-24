
#include <ngx_config.h>
#include <ngx_core.h>


#include "ngx_quic_pkt.h"
#include "ngx_quic_util.h"

#define NGX_QUIC_PKT_POOL_SIZE  (1024*2)

ngx_quic_pkt_t* 
ngx_quic_pkt_new()
{
    ngx_pool_t      *pool = NULL;
    ngx_quic_pkt_t  *pkt = NULL;

    pool = ngx_create_pool(NGX_QUIC_PKT_POOL_SIZE, ngx_cycle->log);

    if (pool != NULL) {
        pkt = ngx_pcalloc(pool, sizeof(ngx_quic_pkt_t));
        if (pkt != NULL) {
            pkt->pool = pool;
        } else {
            ngx_destroy_pool(pool);
        }
    }


    return pkt;
}


void 
ngx_quic_pkt_free(ngx_quic_pkt_t *pkt)
{
    if(pkt && pkt->pool) {
        ngx_destroy_pool(pkt->pool);
    }
}


static ngx_inline ngx_int_t 
ngx_quic_pkt_get_cid_long(ngx_quic_pkt_t *pkt, ngx_str_t *buf)
{
    uint8_t    *data = buf->data;
    uint8_t     dcil,scil;  
    ngx_int_t   len = 0;    /* type,version,dcil|scil */

    if (buf->len < 6) {
        return NGX_ERROR;
    }

    /*
    Non-zero encoded lengths are increased by 3 to get the full length of the connection ID */

    dcil = data[5] >> 4;
    scil = data[5] & 0xf;

    if (dcil) {
        dcil += 3;
    }

    if (scil) {
        scil += 3;
    }

    len = 6 + dcil + scil;

    if (buf->len < (size_t)len) {
        return NGX_ERROR;
    }
    
    pkt->dcid.data = data + 6;
    pkt->dcid.len  = dcil;
    pkt->scid.data = data + 6 + dcil;
    pkt->scid.len  = scil;

    return len;
}


static ngx_inline void 
ngx_quic_pkt_set_type_payload(ngx_quic_pkt_t *pkt, ngx_str_t *buf,ngx_int_t offset, uint8_t type)
{
    pkt->type         = type;
    pkt->payload.data = buf->data + offset;
    pkt->payload.len  = buf->len - offset;
}


static ngx_inline ngx_int_t 
ngx_quic_pkt_get_normal(ngx_quic_pkt_t *pkt, ngx_str_t *buf,ngx_int_t offset, uint8_t type)
{
    uint8_t     bytes;
    uint64_t    length;
    uint64_t    number;

    if (ngx_quic_get_varint2(buf, offset, &bytes, &length) != NGX_OK) {
        return NGX_ERROR;
    }
    

    offset += bytes;
    pkt->length = length;

    if (ngx_quic_get_varint2(buf, offset, &bytes, &number) != NGX_OK) {
        return NGX_ERROR;
    }

    offset      += bytes;
    pkt->number = number;

    ngx_quic_pkt_set_type_payload(pkt, buf, offset, type);

    return NGX_OK;
}


static ngx_inline ngx_int_t 
ngx_quic_pkt_get_initial(ngx_quic_pkt_t *pkt, ngx_str_t *buf, ngx_int_t offset)
{
    uint8_t      bytes;      
    uint64_t     token_len;

    if(ngx_quic_get_varint2(buf, offset, &bytes, &token_len) != NGX_OK) {
        return NGX_ERROR;
    }

    offset += token_len + bytes;
    if (buf->len < (size_t)offset) {
        return NGX_ERROR;
    }

    pkt->token.data = buf->data + offset + bytes;
    pkt->token.len  = token_len;

    return ngx_quic_pkt_get_normal(pkt, buf, offset,  NGX_QUIC_PKT_INITIAL); 
}

static ngx_inline ngx_int_t 
ngx_quic_pkt_get_retry(ngx_quic_pkt_t *pkt, ngx_str_t *buf, ngx_int_t offset)
{
    uint8_t     odcil;  
 
    if (buf->len < (size_t)(offset + 1)) {
        return NGX_ERROR;
    }
    
    odcil = buf->data[offset] &0xf;
    if (odcil) {
        odcil += 3;
    }

    if(buf->len < (size_t)(offset + 1 + odcil)) {
        return NGX_ERROR;
    }
    
    pkt->odcid.data = buf->data + offset + 1;
    pkt->odcid.len  = odcil;

    offset +=  1 + odcil;
    ngx_quic_pkt_set_type_payload(pkt, buf, offset, NGX_QUIC_PKT_RETRY);
    return NGX_OK;
}



static ngx_inline ngx_int_t 
ngx_quic_pkt_get_version_negotiation(ngx_quic_pkt_t *pkt, ngx_str_t *buf, ngx_int_t offset)
{
    ngx_quic_pkt_set_type_payload(pkt, buf, offset, NGX_QUIC_PKT_VERSION_NEGOTIATION);
    return NGX_OK;
}

ngx_int_t 
ngx_quic_pkt_get_long(ngx_quic_pkt_t *pkt, ngx_str_t *buf)
{
    uint8_t    *data = buf->data;
    uint32_t    version;
    uint8_t     type;
    ngx_int_t   offset = 6;    /* type,version,dcil|scil */


    if ((offset = ngx_quic_pkt_get_cid_long(pkt, buf)) < 0) {
        return NGX_ERROR;
    }


    version = ngx_quic_get_uint32(&data[1]);
    
    if (version) {
        if(version != NGX_QUIC_PROTO_VER_D13) {
            return NGX_ERROR;
        }

        pkt->version = version;

        type = data[0] & NGX_QUIC_PKT_TYPE_MASK;

        switch (type) {
        case NGX_QUIC_PKT_INITIAL:
            return ngx_quic_pkt_get_initial(pkt, buf, offset);
        case NGX_QUIC_PKT_RETRY: 
            return ngx_quic_pkt_get_retry(pkt, buf, offset);
        case NGX_QUIC_PKT_0RTT_PROTECTED: 
        case NGX_QUIC_PKT_HANDSHAKE:           
            return ngx_quic_pkt_get_normal(pkt, buf, offset, type);
        default:
            return NGX_ERROR;
        } 
    } else {
        return ngx_quic_pkt_get_version_negotiation(pkt, buf,offset);
    }
}




