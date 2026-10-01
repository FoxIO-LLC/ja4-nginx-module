#ifndef _NGX_SSL_JA4_CLIENT_HELLO_H_INCLUDED_
#define _NGX_SSL_JA4_CLIENT_HELLO_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


typedef struct {
    ngx_uint_t       version;        /* highest supported_versions entry,
                                        GREASE skipped; 0 if absent */
    size_t           extensions_sz;
    char           **extensions;     /* "%04x" types in ClientHello order,
                                        GREASE included */
    char            *first_alpn;     /* NUL-terminated, or NULL */
} ngx_ssl_ja4_client_hello_t;


ngx_int_t ngx_ssl_ja4_parse_client_hello(const u_char *buf, size_t len,
    ngx_pool_t *pool, ngx_ssl_ja4_client_hello_t *ch);

ngx_int_t ngx_ssl_ja4_client_hello(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_ssl_ja4_client_hello_t *ch);


#endif /* _NGX_SSL_JA4_CLIENT_HELLO_H_INCLUDED_ */
