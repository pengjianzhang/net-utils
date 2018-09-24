#ifndef NGX_QUIC_CONN_H
#define NGX_QUIC_CONN_H

#include <ngx_config.h>
#include <ngx_core.h>

#include <ngx_queue.h>

#include <stdint.h>



typedef struct {
    ngx_queue_t  next;  /* todo hash */
    ngx_str_t    dcid;
    ngx_str_t    scid;
    ngx_pool_t  *pool;
    uint8_t      state;


    uint32_t version;

    /* setting */

} ngx_quic_conn_t;


#endif
