
/*
 * Per-connection side of the upstream SYN-ACK capture.
 *
 * A connection registers its socket cookie before connect(), consumes the
 * captured SYN-ACK headers once the socket is established, and unregisters
 * when it is closed.  The maps are LRU: what failures leave behind, e.g.
 * after a crashed worker, is evicted when an insert needs the room.  The
 * loader, ngx_ebpf_module.c, creates the maps.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include <bpf/bpf.h>

#include "ngx_ebpf_module.h"
#include "ngx_ebpf_synack.h"
#include "ngx_ebpf.h"


static ngx_uint_t ngx_ebpf_remove(uint64_t cookie, ngx_uint_t consumed);


void
ngx_connection_register_synack(ngx_connection_t *c, struct sockaddr *sa,
    ngx_flag_t enabled)
{
    int                        rc;
    uint64_t                   cookie;
    socklen_t                  len;
    struct synack_connection   state;

    static ngx_msec_t          last_warning;

    if (!enabled
        || ngx_ebpf_conn_fd < 0
        || c->type != SOCK_STREAM
        || (sa->sa_family != AF_INET && sa->sa_family != AF_INET6))
    {
        return;
    }

    c->synack_enabled = 1;

    /* the cookie is assigned on first use, so it must precede connect() */

    len = sizeof(uint64_t);

    if (getsockopt(c->fd, SOL_SOCKET, SO_COOKIE, &cookie, &len) == -1
        || len != sizeof(uint64_t)
        || cookie == 0)
    {
        ngx_ebpf_count(SYNACK_STAT_REGISTER_FAILED);
        return;
    }

    ngx_memzero(&state, sizeof(struct synack_connection));

#if (NGX_SYNACK_TEST)
    if (getenv("NGX_SYNACK_TEST_MISS")) {
        /* not pending: synack_out ignores it, so its SYN-ACK is missed */
        state.phase = SYNACK_CLAIMED;
    }
#endif

    rc = bpf_map_update_elem(ngx_ebpf_conn_fd, &cookie, &state, BPF_NOEXIST);

    if (rc < 0) {
        ngx_ebpf_count(SYNACK_STAT_REGISTER_FAILED);

        /* the stats counter is exact; the log is limited to one per second */

        if (ngx_current_msec - last_warning >= 1000) {
            last_warning = ngx_current_msec;
            ngx_log_error(NGX_LOG_WARN, c->log, -rc,
                          "tcp_save_synack: registration failed, "
                          "metadata unavailable");
        }

        return;
    }

    c->synack_cookie = cookie;
}


void
ngx_connection_save_synack(ngx_connection_t *c)
{
    int                    rc;
    u_char                *buf;
    uint64_t               cookie;
    socklen_t              len;
    ngx_uint_t             registered;
    struct tcp_info        info;
    struct synack_record   record;

    if (!c->synack_enabled
        || c->synack_processed
        || c->synack_cookie == 0
        || c->pool == NULL
        || ngx_ebpf_capture_fd < 0)
    {
        return;
    }

    /* confirm the handshake completed before consuming the capture */

    ngx_memzero(&info, sizeof(struct tcp_info));
    len = sizeof(struct tcp_info);

    if (getsockopt(c->fd, IPPROTO_TCP, TCP_INFO, &info, &len) == -1
        || (info.tcpi_state != TCP_ESTABLISHED
            && info.tcpi_state != TCP_CLOSE_WAIT))
    {
        return;
    }

    /* one attempt: from here on the record is consumed or absent */

    c->synack_processed = 1;

    cookie = c->synack_cookie;

#if (NGX_SYNACK_TEST)
    if (getenv("NGX_SYNACK_TEST_EVICT")) {
        (void) bpf_map_delete_elem(ngx_ebpf_capture_fd, &cookie);
        (void) bpf_map_delete_elem(ngx_ebpf_conn_fd, &cookie);
    }
#endif

    rc = bpf_map_lookup_and_delete_elem(ngx_ebpf_capture_fd, &cookie,
                                        &record);

    /*
     * The registration has no further use either way: a successful capture
     * has already deleted it in BPF, and a missed one can no longer happen.
     */

    registered = ngx_ebpf_remove(cookie, 1);
    c->synack_cookie = 0;

    if (rc < 0) {
        if (rc != -ENOENT) {
            ngx_ebpf_count(SYNACK_STAT_HANDOFF_ERROR);

        } else if (registered) {

            /*
             * The registration is still pending: the SYN-ACK was not
             * captured.  The *_FULL, SECOND_KEY and COLLISION counters
             * explain some misses; the rest took a path the programs cannot
             * see, or are bugs.
             */

            ngx_ebpf_count(SYNACK_STAT_MISSED);

        } else {

            /*
             * A capture replaces the registration with the record: with
             * neither left, the LRU maps evicted one of them.
             */

            ngx_ebpf_count(SYNACK_STAT_EVICTED);
        }

        return;
    }

    /*
     * No freshness check: only this socket's SYN-ACK can create its record,
     * and it is consumed right after the handshake.
     */

    if (record.version != SYNACK_VERSION
        || record.length < 40
        || record.length > SYNACK_MAX_HEADERS)
    {
        ngx_ebpf_count(SYNACK_STAT_INVALID_RECORD);
        return;
    }

#if (NGX_SYNACK_TEST)
    buf = getenv("NGX_SYNACK_TEST_ALLOC_FAIL")
          ? NULL : ngx_pnalloc(c->pool, record.length);
#else
    buf = ngx_pnalloc(c->pool, record.length);
#endif

    if (buf == NULL) {
        ngx_ebpf_count(SYNACK_STAT_ALLOC_FAILED);
        return;
    }

    ngx_memcpy(buf, record.headers, record.length);

    c->saved_synack.data = buf;
    c->saved_synack.len = record.length;

#if (NGX_SYNACK_TEST)
    {
    int                        present;
    u_char                     hex[SYNACK_MAX_HEADERS * 2];
    ngx_str_t                  raw;
    struct synack_record       retained;
    struct synack_connection   state;

    present = bpf_map_lookup_elem(ngx_ebpf_capture_fd, &cookie, &retained)
              == 0
              || bpf_map_lookup_elem(ngx_ebpf_conn_fd, &cookie, &state) == 0;

    raw.data = hex;
    raw.len = ngx_hex_dump(hex, c->saved_synack.data, c->saved_synack.len)
              - hex;

    ngx_log_error(NGX_LOG_NOTICE, c->log, 0,
                  "synack test handoff: cookie=%uL len=%uz kernel=%d raw=%V",
                  cookie, c->saved_synack.len, present, &raw);
    }
#endif
}


void
ngx_connection_cleanup_synack(ngx_connection_t *c)
{
    if (c->synack_cookie == 0 || ngx_ebpf_conn_fd < 0) {
        return;
    }

    (void) ngx_ebpf_remove(c->synack_cookie, c->synack_processed);

    c->synack_cookie = 0;
}


/*
 * "consumed" means the connection has already taken (or discarded) its
 * capture record, so only the registration is left to delete.  Returns
 * whether the registration still existed.
 */

static ngx_uint_t
ngx_ebpf_remove(uint64_t cookie, ngx_uint_t consumed)
{
    ngx_uint_t                  registered;
    struct synack_connection    state;
    struct synack_expectation   owner;

    registered = bpf_map_lookup_and_delete_elem(ngx_ebpf_conn_fd, &cookie,
                                                &state)
                 == 0;

    /* a completed capture has already removed the key it owned in BPF */

    if (registered
        && state.phase != SYNACK_COMPLETE
        && state.has_key
        && bpf_map_lookup_elem(ngx_ebpf_expect_fd, &state.key, &owner) == 0
        && owner.cookie == cookie)
    {
        (void) bpf_map_delete_elem(ngx_ebpf_expect_fd, &state.key);
    }

    if (!consumed) {
        (void) bpf_map_delete_elem(ngx_ebpf_capture_fd, &cookie);
    }

    return registered;
}
