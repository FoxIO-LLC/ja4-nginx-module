
/*
 * nginx eBPF loader: upstream SYN-ACK capture.
 */


#ifndef _NGX_EBPF_MODULE_H_INCLUDED_
#define _NGX_EBPF_MODULE_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


ngx_int_t ngx_ebpf_require(ngx_conf_t *cf);

void ngx_connection_register_synack(ngx_connection_t *c, struct sockaddr *sa,
    ngx_flag_t enabled);
void ngx_connection_save_synack(ngx_connection_t *c);
void ngx_connection_cleanup_synack(ngx_connection_t *c);


#endif /* _NGX_EBPF_MODULE_H_INCLUDED_ */
