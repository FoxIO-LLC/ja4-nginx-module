#include "ngx_ssl_ja4_client_hello.h"


#define NGX_SSL_JA4_EXT_ALPN                 0x0010
#define NGX_SSL_JA4_EXT_SUPPORTED_VERSIONS   0x002b

#define ngx_ssl_ja4_is_grease(v)  (((v) & 0x0f0f) == 0x0a0a)


static ngx_int_t ngx_ssl_ja4_skip(const u_char **p, const u_char *end,
    size_t len_bytes);
static ngx_uint_t ngx_ssl_ja4_highest_version(const u_char *p, size_t len);
static char *ngx_ssl_ja4_first_alpn(const u_char *p, size_t len,
    ngx_pool_t *pool);


/*
 * Parses the ClientHello handshake message (msg_type and uint24 length
 * included) that the nginx patch saves in c->ssl->raw_client_hello.
 */

ngx_int_t
ngx_ssl_ja4_client_hello(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_ssl_ja4_client_hello_t *ch)
{
    ngx_memzero(ch, sizeof(ngx_ssl_ja4_client_hello_t));

    if (c->ssl == NULL || c->ssl->raw_client_hello == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_ssl_ja4_parse_client_hello(c->ssl->raw_client_hello,
                                       c->ssl->raw_client_hello_len,
                                       pool, ch)
        != NGX_OK)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "ja4: malformed ClientHello");
        ngx_memzero(ch, sizeof(ngx_ssl_ja4_client_hello_t));
        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ja4_parse_client_hello(const u_char *buf, size_t len,
    ngx_pool_t *pool, ngx_ssl_ja4_client_hello_t *ch)
{
    size_t         n, msg_len, ext_len;
    ngx_uint_t     i, type, count;
    const u_char  *p, *end, *ext;

    ngx_memzero(ch, sizeof(ngx_ssl_ja4_client_hello_t));

    if (len < 4 || buf[0] != 1) {
        return NGX_ERROR;
    }

    msg_len = (size_t) buf[1] << 16 | buf[2] << 8 | buf[3];

    if (len - 4 < msg_len) {
        return NGX_ERROR;
    }

    p = buf + 4;
    end = p + msg_len;

    /* legacy_version, random */

    if ((size_t) (end - p) < 2 + 32) {
        return NGX_ERROR;
    }

    p += 2 + 32;

    /* legacy_session_id, cipher_suites, legacy_compression_methods */

    if (ngx_ssl_ja4_skip(&p, end, 1) != NGX_OK
        || ngx_ssl_ja4_skip(&p, end, 2) != NGX_OK
        || ngx_ssl_ja4_skip(&p, end, 1) != NGX_OK)
    {
        return NGX_ERROR;
    }

    if (p == end) {
        return NGX_OK;
    }

    if (end - p < 2) {
        return NGX_ERROR;
    }

    n = p[0] << 8 | p[1];
    p += 2;

    if ((size_t) (end - p) < n) {
        return NGX_ERROR;
    }

    end = p + n;

    /* first pass validates and counts, second pass collects */

    count = 0;

    for (ext = p; ext != end; ext += 4 + ext_len) {
        if (end - ext < 4) {
            return NGX_ERROR;
        }

        ext_len = ext[2] << 8 | ext[3];

        if ((size_t) (end - ext - 4) < ext_len) {
            return NGX_ERROR;
        }

        count++;
    }

    if (count == 0) {
        return NGX_OK;
    }

    ch->extensions = ngx_pnalloc(pool, count * sizeof(char *));
    if (ch->extensions == NULL) {
        return NGX_ERROR;
    }

    for (ext = p, i = 0; i < count; ext += 4 + ext_len, i++) {
        type = ext[0] << 8 | ext[1];
        ext_len = ext[2] << 8 | ext[3];

        ch->extensions[i] = ngx_pnalloc(pool, sizeof("ffff"));
        if (ch->extensions[i] == NULL) {
            return NGX_ERROR;
        }

        *ngx_sprintf((u_char *) ch->extensions[i], "%04xi", type) = '\0';

        switch (type) {

        case NGX_SSL_JA4_EXT_SUPPORTED_VERSIONS:
            ch->version = ngx_ssl_ja4_highest_version(ext + 4, ext_len);
            break;

        case NGX_SSL_JA4_EXT_ALPN:
            if (ch->first_alpn == NULL) {
                ch->first_alpn = ngx_ssl_ja4_first_alpn(ext + 4, ext_len,
                                                        pool);
            }
            break;
        }
    }

    ch->extensions_sz = count;

    return NGX_OK;
}


/* skips a vector with a length prefix of len_bytes */

static ngx_int_t
ngx_ssl_ja4_skip(const u_char **p, const u_char *end, size_t len_bytes)
{
    size_t  n;

    if ((size_t) (end - *p) < len_bytes) {
        return NGX_ERROR;
    }

    n = (len_bytes == 1) ? (*p)[0] : (size_t) ((*p)[0] << 8 | (*p)[1]);
    *p += len_bytes;

    if ((size_t) (end - *p) < n) {
        return NGX_ERROR;
    }

    *p += n;

    return NGX_OK;
}


static ngx_uint_t
ngx_ssl_ja4_highest_version(const u_char *p, size_t len)
{
    size_t      i, n;
    ngx_uint_t  v, highest;

    if (len < 1) {
        return 0;
    }

    n = p[0];

    if (n + 1 > len) {
        return 0;
    }

    highest = 0;

    for (i = 1; i + 1 <= n; i += 2) {
        v = p[i] << 8 | p[i + 1];

        if (!ngx_ssl_ja4_is_grease(v) && v > highest) {
            highest = v;
        }
    }

    return highest;
}


static char *
ngx_ssl_ja4_first_alpn(const u_char *p, size_t len, ngx_pool_t *pool)
{
    size_t   n;
    u_char  *alpn;

    /* ProtocolNameList: uint16 length, then uint8-prefixed names */

    if (len < 3) {
        return NULL;
    }

    n = p[2];

    if (n == 0 || n + 3 > len) {
        return NULL;
    }

    alpn = ngx_pnalloc(pool, n + 1);
    if (alpn == NULL) {
        return NULL;
    }

    *ngx_cpymem(alpn, p + 3, n) = '\0';

    return (char *) alpn;
}
