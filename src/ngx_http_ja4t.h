#ifndef _NGX_HTTP_JA4T_H_INCLUDED_
#define _NGX_HTTP_JA4T_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


#define NGX_HTTP_JA4T_MAX_KINDS  40

typedef struct {
    unsigned int     window_size;
    unsigned char    kinds[NGX_HTTP_JA4T_MAX_KINDS];
    size_t           nkinds;
    unsigned int     mss;
    unsigned int     mss_present;
    unsigned int     window_scale;
    unsigned int     wscale_present;
} ngx_http_ja4t_t;


ngx_int_t ngx_http_ja4t_parse_syn(const u_char *buf, size_t len,
    ngx_http_ja4t_t *ja4t);

ngx_int_t ngx_http_ja4t(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *out);


#endif /* _NGX_HTTP_JA4T_H_INCLUDED_ */
