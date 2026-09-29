
/*
 * nginx eBPF loader: upstream SYN-ACK capture.
 *
 * The master loads the BPF object and attaches it to Netfilter PREROUTING and
 * POSTROUTING; workers inherit the map descriptors.  The per-connection side
 * of the capture is in ngx_ebpf_synack.c.
 */


#include <ngx_config.h>
#include <ngx_core.h>

#include <sys/mman.h>
#include <stdarg.h>
#include <stdio.h>
#include <linux/netfilter.h>
#include <bpf/libbpf.h>

#include "ngx_ebpf_module.h"
#include "ngx_ebpf_synack.h"
#include "ngx_ebpf.h"
#include "ngx_ebpf.skel.h"


#define NGX_EBPF_LINKS          4       /* {PRE,POST}ROUTING x {IPv4,IPv6} */

/*
 * Netfilter refuses a second BPF program at the same hook and priority, so
 * each capture-enabled process in a network namespace takes the next free
 * one: INT_MIN + 1, + 2, ... and INT_MAX - 1, - 2, ...
 */
#define NGX_EBPF_PRIORITIES     64


typedef struct {
    ngx_flag_t                  enabled;
} ngx_ebpf_conf_t;


static void *ngx_ebpf_create_conf(ngx_cycle_t *cycle);
static ngx_int_t ngx_ebpf_init(ngx_cycle_t *cycle);
static void ngx_ebpf_exit(ngx_cycle_t *cycle);
static int ngx_ebpf_libbpf_print(enum libbpf_print_level level,
    const char *fmt, va_list args);


static ngx_core_module_t  ngx_ebpf_module_ctx = {
    ngx_string("ebpf"),
    ngx_ebpf_create_conf,
    NULL
};


ngx_module_t  ngx_ebpf_module = {
    NGX_MODULE_V1,
    &ngx_ebpf_module_ctx,                  /* module context */
    NULL,                                  /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    ngx_ebpf_init,                         /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_ebpf_exit,                         /* exit process */
    ngx_ebpf_exit,                         /* exit master */
    NGX_MODULE_V1_PADDING
};


/* Process lifetime, deliberately independent of configuration-cycle pools. */

int                         ngx_ebpf_conn_fd = -1;
int                         ngx_ebpf_expect_fd = -1;
int                         ngx_ebpf_capture_fd = -1;
uint64_t                   *ngx_ebpf_stats;

static struct ngx_ebpf     *ngx_ebpf_skel;
static struct bpf_link     *ngx_ebpf_links[NGX_EBPF_LINKS];
static ngx_uint_t           ngx_ebpf_started;
static ngx_log_t           *ngx_ebpf_log;
static ngx_uint_t           ngx_ebpf_quiet;


static void *
ngx_ebpf_create_conf(ngx_cycle_t *cycle)
{
    return ngx_pcalloc(cycle->pool, sizeof(ngx_ebpf_conf_t));
}


ngx_int_t
ngx_ebpf_require(ngx_conf_t *cf)
{
    ngx_ebpf_conf_t  *conf;

    if (ngx_ebpf_started && ngx_ebpf_skel == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "tcp_save_synack: enabling capture requires "
                           "a restart");
        return NGX_ERROR;
    }

    conf = (ngx_ebpf_conf_t *) ngx_get_conf(cf->cycle->conf_ctx,
                                            ngx_ebpf_module);
    conf->enabled = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_ebpf_init(ngx_cycle_t *cycle)
{
    ngx_err_t                   err;
    ngx_uint_t                  i, n, skipped;
    ngx_ebpf_conf_t            *conf;
    struct bpf_link            *link;
    struct bpf_program         *prog;
    struct bpf_netfilter_opts   opts;

    if (ngx_test_config || ngx_process == NGX_PROCESS_SIGNALLER) {
        return NGX_OK;
    }

    conf = (ngx_ebpf_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_ebpf_module);

    if (ngx_ebpf_started) {

        /* reload: keep what the first cycle created */

        if (conf->enabled && ngx_ebpf_skel == NULL) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "tcp_save_synack: enabling capture requires "
                          "a restart");
            return NGX_ERROR;
        }

        return NGX_OK;
    }

    ngx_ebpf_started = 1;

    if (!conf->enabled) {
        return NGX_OK;
    }

    /* libbpf prints to stderr by default; keep its detail in the error log */

    ngx_ebpf_log = cycle->log;
    (void) libbpf_set_print(ngx_ebpf_libbpf_print);

    ngx_ebpf_skel = ngx_ebpf__open_and_load();
    if (ngx_ebpf_skel == NULL) {
        goto failed;
    }

    ngx_ebpf_conn_fd = bpf_map__fd(ngx_ebpf_skel->maps.synack_conn);
    ngx_ebpf_expect_fd = bpf_map__fd(ngx_ebpf_skel->maps.synack_expect);
    ngx_ebpf_capture_fd = bpf_map__fd(ngx_ebpf_skel->maps.synack_capture);

    ngx_ebpf_stats = mmap(NULL, SYNACK_STAT_COUNT * sizeof(uint64_t),
                          PROT_READ|PROT_WRITE, MAP_SHARED,
                          bpf_map__fd(ngx_ebpf_skel->maps.synack_stats), 0);
    if (ngx_ebpf_stats == MAP_FAILED) {
        ngx_ebpf_stats = NULL;
        goto failed;
    }

    /* both PREROUTING links precede either POSTROUTING link */

    skipped = 0;

    for (i = 0; i < NGX_EBPF_LINKS; i++) {
        ngx_memzero(&opts, sizeof(struct bpf_netfilter_opts));
        opts.sz = sizeof(struct bpf_netfilter_opts);
        opts.pf = (i & 1) ? AF_INET6 : AF_INET;

        if (i < 2) {
            prog = ngx_ebpf_skel->progs.synack_in;
            opts.hooknum = NF_INET_PRE_ROUTING;

        } else {
            prog = ngx_ebpf_skel->progs.synack_out;
            opts.hooknum = NF_INET_POST_ROUTING;
        }

        link = NULL;
        err = NGX_EBUSY;

        for (n = 0; n < NGX_EBPF_PRIORITIES; n++) {
            opts.priority = (i < 2) ? INT_MIN + 1 + (int) n
                                    : INT_MAX - 1 - (int) n;

            /* a taken priority is expected; libbpf would warn each time */

            ngx_ebpf_quiet = 1;
            link = bpf_program__attach_netfilter(prog, &opts);
            err = ngx_errno;
            ngx_ebpf_quiet = 0;

            if (link != NULL && libbpf_get_error(link) == 0) {
                break;
            }

            link = NULL;

            if (err != NGX_EBUSY) {
                break;
            }
        }

        if (link == NULL) {
            ngx_set_errno(err);
            goto failed;
        }

        ngx_ebpf_links[i] = link;
        skipped = ngx_max(skipped, n);
    }

    if (skipped) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "tcp_save_synack: other processes capture in this "
                      "network namespace; attached %ui hook priorities "
                      "further in", skipped);
    }

    ngx_ebpf_log = NULL;

    return NGX_OK;

failed:

    err = ngx_errno;

    if (err == NGX_EBUSY) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                      "tcp_save_synack: all %d Netfilter hook priorities "
                      "for capture are taken by other processes in this "
                      "network namespace", NGX_EBPF_PRIORITIES);

    } else if (err == NGX_EPERM || err == NGX_EACCES) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                      "tcp_save_synack: cannot load the BPF capture "
                      "programs; the master process needs root, or "
                      "CAP_BPF, CAP_PERFMON and CAP_NET_ADMIN");

    } else {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, err,
                      "tcp_save_synack: cannot initialize Netfilter BPF "
                      "capture (requires Linux 6.4+ with kernel BTF)");
    }

    ngx_ebpf_exit(cycle);

    ngx_ebpf_log = NULL;

    return NGX_ERROR;
}


/*
 * libbpf warnings are logged at the notice level: the emerg message above
 * reports the failure, and "error_log ... notice" shows libbpf's reasons.
 * Attach attempts are quiet: a taken priority is expected, and the emerg
 * message carries the errno of the last attempt.
 */

static int
ngx_ebpf_libbpf_print(enum libbpf_print_level level, const char *fmt,
    va_list args)
{
    int         n;
    char        buf[NGX_MAX_ERROR_STR];
    ngx_log_t  *log;

    if (ngx_ebpf_quiet) {
        return 0;
    }

    log = ngx_ebpf_log ? ngx_ebpf_log : ngx_cycle->log;

    n = vsnprintf(buf, sizeof(buf), fmt, args);
    if (n < 0) {
        return 0;
    }

    if (n > (int) sizeof(buf) - 1) {
        n = sizeof(buf) - 1;
    }

    while (n > 0 && buf[n - 1] == '\n') {
        n--;
    }

    if (level == LIBBPF_WARN) {
        ngx_log_error(NGX_LOG_NOTICE, log, 0, "%*s", (size_t) n, buf);

    } else {
        ngx_log_debug2(NGX_LOG_DEBUG_CORE, log, 0, "%*s",
                       (size_t) n, buf);
    }

    return 0;
}


static void
ngx_ebpf_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    /*
     * Close inherited references only; never BPF_LINK_DETACH a link that
     * other processes share.  These links are not in skel->links, so
     * ngx_ebpf__destroy() does not touch them.
     */

    for (i = 0; i < NGX_EBPF_LINKS; i++) {
        if (ngx_ebpf_links[i]) {
            (void) close(bpf_link__fd(ngx_ebpf_links[i]));
            ngx_ebpf_links[i] = NULL;
        }
    }

    if (ngx_ebpf_stats) {
        (void) munmap(ngx_ebpf_stats, SYNACK_STAT_COUNT * sizeof(uint64_t));
        ngx_ebpf_stats = NULL;
    }

    if (ngx_ebpf_skel) {
        ngx_ebpf__destroy(ngx_ebpf_skel);
        ngx_ebpf_skel = NULL;
    }

    ngx_ebpf_conn_fd = -1;
    ngx_ebpf_expect_fd = -1;
    ngx_ebpf_capture_fd = -1;
}
