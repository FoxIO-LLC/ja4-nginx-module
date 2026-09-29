
/*
 * State the loader (ngx_ebpf_module.c) sets up for the per-connection
 * capture (ngx_ebpf_synack.c).  Private to the ebpf addon.
 */


#ifndef _NGX_EBPF_SYNACK_H_INCLUDED_
#define _NGX_EBPF_SYNACK_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/* map descriptors, -1 without capture */
extern int        ngx_ebpf_conn_fd;
extern int        ngx_ebpf_expect_fd;
extern int        ngx_ebpf_capture_fd;

/* the mmapped synack_stats array, indexed by enum synack_stat */
extern uint64_t  *ngx_ebpf_stats;


#define ngx_ebpf_count(stat)                                                  \
    (void) __sync_fetch_and_add(&ngx_ebpf_stats[stat], 1)


#endif /* _NGX_EBPF_SYNACK_H_INCLUDED_ */
