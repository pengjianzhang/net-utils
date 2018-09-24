
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>



static ngx_command_t  ngx_quic_commands[] = {
      ngx_null_command
};


static ngx_http_module_t  ngx_quic_module_ctx = {
    NULL,                           /* preconfiguration */
    NULL,                           /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    NULL,                           /* create location configuration */
    NULL                            /* merge location configuration */
};


ngx_module_t  ngx_quic_module = {
    NGX_MODULE_V1,
    &ngx_quic_module_ctx,    /* module context */
    ngx_quic_commands,       /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};


