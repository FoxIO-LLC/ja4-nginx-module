#include "ngx_http_ja4t.h"

#ifdef NGX_HAVE_TCP_SAVE_SYN

ngx_int_t
ngx_http_ja4t_parse_syn(const u_char *buf, size_t len, ngx_http_ja4t_t *ja4t)
{
    size_t        off, tcp_off, tcp_hlen, remaining, adv;
    const u_char *tcp, *opt, *opt_end;
    u_char        kind, olen, ver, nxt, seen_eol;

    if (buf == NULL || len < 20) {
        return NGX_DECLINED;
    }

    ngx_memset(ja4t, 0, sizeof(ngx_http_ja4t_t));

    ver = buf[0] >> 4;

    if (ver == 4) {
        off = (buf[0] & 0x0f) * 4;
        if (off < 20 || off + 20 > len) {
            return NGX_DECLINED;
        }

        tcp_off = off;

    } else if (ver == 6) {
        if (len < 40) {
            return NGX_DECLINED;
        }

        nxt = buf[6];
        off = 40;

        while (nxt != IPPROTO_TCP) {
            if (off + 2 > len) {
                return NGX_DECLINED;
            }

            switch (nxt) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
                adv = ((size_t) buf[off + 1] + 1) * 8;
                nxt = buf[off];
                off += adv;
                break;

            case IPPROTO_FRAGMENT:
                nxt = buf[off];
                off += 8;
                adv = 8;
                break;

            case IPPROTO_AH:
                adv = ((size_t) buf[off + 1] + 2) * 4;
                nxt = buf[off];
                off += adv;
                break;

            default:
                return NGX_DECLINED;
            }

            /* every extension header advances by at least 8 bytes */
            if (adv < 8 || off + 20 > len) {
                return NGX_DECLINED;
            }
        }

        tcp_off = off;

    } else {
        return NGX_DECLINED;
    }

    if (tcp_off + 20 > len) {
        return NGX_DECLINED;
    }

    tcp = buf + tcp_off;
    tcp_hlen = ((tcp[12] >> 4) & 0x0f) * 4;
    if (tcp_hlen < 20 || tcp_off + tcp_hlen > len) {
        return NGX_DECLINED;
    }

    ja4t->window_size = ((unsigned int) tcp[14] << 8) | tcp[15];

    opt = tcp + 20;
    opt_end = tcp + tcp_hlen;
    seen_eol = 0;

    while (opt < opt_end) {
        remaining = (size_t) (opt_end - opt);
        kind = opt[0];

        if (ja4t->nkinds >= NGX_HTTP_JA4T_MAX_KINDS) {
            return NGX_DECLINED;
        }

        ja4t->kinds[ja4t->nkinds++] = kind;

        if (kind == 0) {
            seen_eol = 1;

            opt++;
            continue;
        }

        if (kind == 1) {
            opt++;
            continue;
        }

        if (remaining < 2) {
            return NGX_DECLINED;
        }

        olen = opt[1];
        if (olen < 2 || olen > remaining) {
            return NGX_DECLINED;
        }

        /* kinds after EOL stay in the list; MSS / window scale do not */
        if (!seen_eol && kind == 2 && olen == 4) {
            ja4t->mss = ((unsigned int) opt[2] << 8) | opt[3];
            ja4t->mss_present = 1;
        }

        if (!seen_eol && kind == 3 && olen == 3) {
            ja4t->window_scale = opt[2];
            ja4t->wscale_present = 1;
        }

        opt += olen;
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_ja4t(ngx_connection_t *c, ngx_str_t *out)
{
    ngx_http_ja4t_t  ja4t;
    u_char          *p, *last;
    size_t           i, size;

    out->data = NULL;
    out->len = 0;

    if (c == NULL || c->pool == NULL || c->type != SOCK_STREAM) {
        return NGX_DECLINED;
    }

#if (NGX_QUIC || NGX_COMPAT)
    if (c->quic) {
        return NGX_DECLINED;
    }
#endif

    if (c->ja4t.data != NULL) {
        *out = c->ja4t;
        return NGX_OK;
    }

    if (c->saved_syn.len < 20 || c->saved_syn.data == NULL) {
        return NGX_DECLINED;
    }

    if (ngx_http_ja4t_parse_syn(c->saved_syn.data, c->saved_syn.len, &ja4t)
        != NGX_OK)
    {
        return NGX_DECLINED;
    }

    /*
     * worst case: window_size(5) + "_" + kinds(each up to 3 digits plus a
     * separator) + "_" + mss(5) + "_" + wscale(3) + margin.
     */
    size = 32 + (size_t) NGX_HTTP_JA4T_MAX_KINDS * 4;

    out->data = ngx_pnalloc(c->pool, size);
    if (out->data == NULL) {
        return NGX_ERROR;
    }

    p = out->data;
    last = out->data + size;

#define NGX_JA4T_NEED(n)                                                       \
    if ((size_t) (last - p) < (size_t) (n)) {                                  \
        out->data = NULL;                                                      \
        out->len = 0;                                                          \
        return NGX_DECLINED;                                                   \
    }

    NGX_JA4T_NEED(6);
    p = ngx_sprintf(p, "%uD", ja4t.window_size);
    *p++ = '_';

    if (ja4t.nkinds == 0) {
        NGX_JA4T_NEED(2);
        *p++ = '0';
        *p++ = '0';
    } else {
        for (i = 0; i < ja4t.nkinds; i++) {
            NGX_JA4T_NEED(5);
            if (i > 0) {
                *p++ = '-';
            }

            p = ngx_sprintf(p, "%ud", (unsigned) ja4t.kinds[i]);
        }
    }

    NGX_JA4T_NEED(1);
    *p++ = '_';

    if (ja4t.mss_present) {
        NGX_JA4T_NEED(6);
        p = ngx_sprintf(p, "%02uD", ja4t.mss);
    } else {
        NGX_JA4T_NEED(2);
        *p++ = '0';
        *p++ = '0';
    }

    NGX_JA4T_NEED(1);
    *p++ = '_';

    if (ja4t.wscale_present && ja4t.window_scale != 0) {
        NGX_JA4T_NEED(4);
        p = ngx_sprintf(p, "%uD", ja4t.window_scale);
    } else {
        NGX_JA4T_NEED(2);
        *p++ = '0';
        *p++ = '0';
    }

#undef NGX_JA4T_NEED

    out->len = p - out->data;

    c->ja4t = *out;

    return NGX_OK;
}

#endif /* NGX_HAVE_TCP_SAVE_SYN */
