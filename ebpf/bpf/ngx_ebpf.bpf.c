// SPDX-License-Identifier: GPL-2.0

/*
 * Upstream SYN-ACK capture.
 *
 * synack_out (POSTROUTING, the last hook, after SNAT and OUTPUT DNAT) sees
 * a registered socket's first SYN and records the SYN-ACK it expects: the
 * SYN's wire tuple reversed, acknowledging S + 1.  synack_in runs first in
 * PREROUTING, before conntrack undoes NAT, so a reply from another host or
 * namespace arrives in exactly that form, across DNAT/SNAT.  A reply that
 * loops back inside this namespace is un-NATed on its way out and does not
 * match; such local backends are not captured.  nginx does not use TCP Fast
 * Open upstream, so a SYN-ACK that acknowledges SYN data is not expected.
 * synack_in matches incoming SYN-ACKs against those keys and stores the
 * original IP/TCP headers for nginx to consume by socket cookie.
 */


/* the kfuncs used are declared below, whatever bpftool put in vmlinux.h */
#define BPF_NO_KFUNC_PROTOTYPES

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "ngx_ebpf.h"


#define SYNACK_NF_ACCEPT  1

#define SYNACK_AF_INET              2
#define SYNACK_AF_INET6             10

#define SYNACK_IPV6_HOPOPTS         0
#define SYNACK_IPV6_ROUTING         43
#define SYNACK_IPV6_DSTOPTS         60
#define SYNACK_IPV6_AH              51
#define SYNACK_IPV6_MAX_EXTENSIONS  8

#define SYNACK_TCP_SYN              0x02
#define SYNACK_TCP_RST              0x04
#define SYNACK_TCP_ACK              0x10
#define SYNACK_TCP_FLAGS                                                      \
    (SYNACK_TCP_SYN|SYNACK_TCP_RST|SYNACK_TCP_ACK)

/* the last offset at which a minimal TCP header still fits the record */
#define SYNACK_MAX_TCP_OFFSET       (SYNACK_MAX_HEADERS - 20)

#define SYNACK_FLAGS_READ_V4        34      /* IPv4 + TCP up to the flags */
#define SYNACK_FLAGS_READ_V6        54      /* IPv6 + TCP up to the flags */
#define SYNACK_MIN_TCP_V4           40      /* IPv4 + TCP headers, no options */
#define SYNACK_MIN_TCP_V6           60      /* IPv6 + TCP headers */


extern int bpf_dynptr_from_skb(struct __sk_buff *skb, __u64 flags,
    struct bpf_dynptr *ptr__uninit) __ksym;


/*
 * A packet from its network header on.  Reads go through an skb dynptr,
 * which bounds them by the whole packet and copies headers out of page
 * fragments when a driver left them outside the linear data.
 */
struct synack_packet {
    struct bpf_dynptr  ptr;
    __u32              offset;      /* of the network header in ptr */
    __u32              length;      /* bytes from the network header */
};


static __always_inline int
synack_packet_init(struct sk_buff *skb, struct synack_packet *p)
{
    __u32  data, network;

    /* the dynptr starts at skb->data; the network header normally is there */
    data = skb->data - skb->head;
    network = skb->network_header;

    if (network < data || network - data > skb->len) {
        return -1;
    }

    p->offset = network - data;
    p->length = skb->len - p->offset;

    return bpf_dynptr_from_skb((struct __sk_buff *) skb, 0, &p->ptr);
}


static __always_inline int
synack_read(struct synack_packet *p, __u32 off, void *buf, __u32 len)
{
    return bpf_dynptr_read(buf, len, &p->ptr, p->offset + off, 0);
}


/*
 * Bounded IP/TCP header reader for Netfilter BPF programs.
 *
 * synack_parse_packet() validates the headers from small stack copies and
 * returns the TCP flags, or 0 if it rejects the packet; synack_out needs no
 * more.  synack_in checks the flags and the expectation before
 * synack_copy_headers() copies the complete headers, so packets that are not
 * of interest never pay for the full copy.
 */
static __always_inline int
synack_parse_packet(struct synack_packet *p, struct synack_key *key,
    __u32 *header_len, __u32 *sequence)
{
    int    i;
    __u8   ip[40], tcp[20], ext[2], next;
    __u32  off, total, tcp_len, step;

    if (synack_read(p, 0, ip, 20)) {
        return 0;
    }

    if (ip[0] >> 4 == 4) {
        off = (ip[0] & 0x0f) * 4;
        total = ((__u32) ip[2] << 8) | ip[3];

        /* options are allowed; fragments and non-TCP are not */
        if (off < 20 || ip[9] != IPPROTO_TCP || (ip[6] & 0x3f) || ip[7]) {
            return 0;
        }

        key->family = SYNACK_AF_INET;
        __builtin_memcpy(key->src, ip + 12, 4);
        __builtin_memcpy(key->dst, ip + 16, 4);

    } else if (ip[0] >> 4 == 6) {

        if (synack_read(p, 0, ip, 40)) {
            return 0;
        }

        total = ((__u32) ip[4] << 8) | ip[5];

        if (total == 0) {
            return 0;               /* jumbogram */
        }

        total += 40;

        key->family = SYNACK_AF_INET6;
        __builtin_memcpy(key->src, ip + 8, 16);
        __builtin_memcpy(key->dst, ip + 24, 16);

        next = ip[6];
        off = 40;

        for (i = 0;
             i < SYNACK_IPV6_MAX_EXTENSIONS && next != IPPROTO_TCP;
             i++)
        {
            if (off > SYNACK_MAX_TCP_OFFSET || off + 2 > total) {
                return 0;
            }

            if (synack_read(p, off, ext, 2)) {
                return 0;
            }

            if (next == SYNACK_IPV6_HOPOPTS
                || next == SYNACK_IPV6_ROUTING
                || next == SYNACK_IPV6_DSTOPTS)
            {
                step = ((__u32) ext[1] + 1) * 8;

            } else if (next == SYNACK_IPV6_AH && ext[1] >= 1) {
                step = ((__u32) ext[1] + 2) * 4;

            } else {
                return 0;           /* fragment, ESP, a short AH or unknown */
            }

            off += step;
            next = ext[0];
        }

        if (next != IPPROTO_TCP) {
            return 0;
        }

    } else {
        return 0;
    }

    /* within total, which is within the packet, so the full copy fits too */
    if (total > p->length
        || off > SYNACK_MAX_TCP_OFFSET
        || off + 20 > total)
    {
        return 0;
    }

    if (synack_read(p, off, tcp, 20)) {
        return 0;
    }

    tcp_len = (tcp[12] >> 4) * 4;

    if (tcp_len < 20
        || off + tcp_len > SYNACK_MAX_HEADERS
        || off + tcp_len > total)
    {
        return 0;
    }

    *header_len = off + tcp_len;

    key->protocol = IPPROTO_TCP;
    __builtin_memcpy(&key->sport, tcp, 2);
    __builtin_memcpy(&key->dport, tcp + 2, 2);
    __builtin_memcpy(&key->ack, tcp + 8, 4);
    __builtin_memcpy(sequence, tcp + 4, 4);

    return tcp[13];
}


/*
 * Whether a packet is a SYN-ACK candidate, worth synack_parse_packet().
 * synack_in sees every inbound packet, so this looks first: one read covers
 * the IP header and the TCP flags byte for the common layouts, IPv4 without
 * options and IPv6 without extension headers, and decides those.  Packets
 * too short for the full parse, or with a bad version or IPv4 header length,
 * are turned away here too.  IPv4 options and IPv6 extension headers, which
 * one read cannot cover, are left to the full parse.  Returns 0 only where
 * the full parse could not yield a SYN-ACK either.
 */
static __always_inline int
synack_candidate(struct synack_packet *p)
{
    __u8  b[SYNACK_FLAGS_READ_V6], next, flags;

    /* the full parse needs at least an IPv4 and a TCP header */
    if (p->length < SYNACK_MIN_TCP_V4) {
        return 0;
    }

    if (synack_read(p, 0, b, p->length >= SYNACK_FLAGS_READ_V6
                             ? SYNACK_FLAGS_READ_V6 : SYNACK_FLAGS_READ_V4))
    {
        return 0;
    }

    if (b[0] >> 4 == 4) {

        if (b[9] != IPPROTO_TCP || (b[6] & 0x3f) || b[7]) {
            return 0;                   /* not TCP, or a fragment */
        }

        if (b[0] < 0x45) {
            return 0;                   /* header shorter than 20 bytes */
        }

        if (b[0] > 0x45) {
            return 1;                   /* options: the full parse decides */
        }

        flags = b[33];

    } else if (b[0] >> 4 == 6) {

        next = b[6];

        if (next != IPPROTO_TCP) {
            return next == SYNACK_IPV6_HOPOPTS
                   || next == SYNACK_IPV6_ROUTING
                   || next == SYNACK_IPV6_DSTOPTS
                   || next == SYNACK_IPV6_AH;
        }

        if (p->length < SYNACK_MIN_TCP_V6) {
            return 0;                   /* no room for the TCP header */
        }

        flags = b[53];

    } else {
        return 0;
    }

    return (flags & SYNACK_TCP_FLAGS) == (SYNACK_TCP_SYN|SYNACK_TCP_ACK);
}


/* header_len must come from a successful synack_parse_packet() on p */
static __always_inline int
synack_copy_headers(struct synack_packet *p, __u8 *bytes, __u32 header_len)
{
    __u32  read_len;

    read_len = header_len;

    /* keep the verifier's bound on the exact register used by the helper */
    asm volatile("" : "+r"(read_len));

    if (read_len == 0 || read_len > SYNACK_MAX_HEADERS) {
        return -1;
    }

    return synack_read(p, 0, bytes, read_len) ? -1 : 0;
}


/*
 * Capture, consume and close remove entries on the fast path.  What escapes
 * them (a crashed worker's entries, a SYN that NFQUEUE releases after close,
 * an expectation whose registration was evicted) is never looked up again,
 * so it ages out of the LRU maps as inserts need room; no sweep runs, and
 * nothing needs the clock.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SYNACK_CONNECTIONS);
    __type(key, __u64);                         /* socket cookie */
    __type(value, struct synack_connection);
} synack_conn SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SYNACK_CONNECTIONS);
    __type(key, struct synack_key);
    __type(value, struct synack_expectation);
} synack_expect SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, SYNACK_CONNECTIONS);
    __type(key, __u64);                         /* socket cookie */
    __type(value, struct synack_record);
} synack_capture SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(map_flags, BPF_F_MMAPABLE);
    __uint(max_entries, SYNACK_STAT_COUNT);
    __type(key, __u32);
    __type(value, __u64);
} synack_stats SEC(".maps");


/* temporary storage only; it never retains a connection's result */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct synack_record);
} synack_scratch SEC(".maps");


static __always_inline void
synack_count(__u32 id)
{
    __u64  *n;

    n = bpf_map_lookup_elem(&synack_stats, &id);
    if (n) {
        __sync_fetch_and_add(n, 1);
    }
}


SEC("netfilter")
int
synack_out(struct bpf_nf_ctx *ctx)
{
    int                          flags;
    __u8                         state;
    __u32                        length, seq;
    __u64                        cookie;
    struct sock                 *sk;
    struct synack_key            packet = {}, wire = {};
    struct synack_packet         p;
    struct synack_connection    *c;
    struct synack_expectation    expect;

    /*
     * Every outbound packet in the namespace reaches this hook, and only a
     * registered socket's SYN matters: a few field reads, the socket, its
     * state and its cookie, let everything else through before the map
     * lookup.
     */
    sk = ctx->state->sk;
    if (sk == NULL) {
        sk = ctx->skb->sk;
    }

    if (sk == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    /*
     * A TCP socket sends SYNs (first and retransmitted) only in SYN_SENT,
     * which no other protocol uses: established TCP, UDP and raw sockets,
     * the bulk of traffic, stop here.  The SYN flag is still checked once
     * the headers are parsed.
     */
    state = sk->__sk_common.skc_state;
    if (state != TCP_SYN_SENT) {
        return SYNACK_NF_ACCEPT;
    }

    /* the cookie is assigned on first use; nginx asks before registering */
    cookie = sk->__sk_common.skc_cookie.counter;
    if (cookie == 0) {
        return SYNACK_NF_ACCEPT;
    }

    /* not registered: another application's, capture off, or evicted */
    c = bpf_map_lookup_elem(&synack_conn, &cookie);
    if (c == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    /*
     * Only the first SYN that parses adds the key, which is recorded
     * (family not 0) even if adding it fails.  A socket's SYNs normally
     * pass this hook one at a time, under its socket lock; SYNs released
     * by NFQUEUE may race, but build the same key.  A retransmission builds
     * the same key, the same tuple and ISN with the same SNAT mapping, and
     * adds nothing: a key the LRU map evicted, a failed insert or a re-NAT
     * after conntrack lost the entry is not retried, and the capture is
     * missed.
     */
    if (c->key.family != 0) {
        return SYNACK_NF_ACCEPT;
    }

    length = 0;
    seq = 0;

    if (synack_packet_init(ctx->skb, &p)) {
        return SYNACK_NF_ACCEPT;
    }

    flags = synack_parse_packet(&p, &packet, &length, &seq);

    if ((flags & SYNACK_TCP_FLAGS) != SYNACK_TCP_SYN) {
        return SYNACK_NF_ACCEPT;
    }

    /* the SYN-ACK as it will arrive: the wire SYN reversed, acknowledging it */
    wire.family = packet.family;
    wire.protocol = IPPROTO_TCP;
    __builtin_memcpy(wire.src, packet.dst, 16);
    __builtin_memcpy(wire.dst, packet.src, 16);
    wire.sport = packet.dport;
    wire.dport = packet.sport;
    wire.ack = bpf_htonl(bpf_ntohl(seq) + 1);

    /*
     * A captured SYN-ACK removes the key and the registration in synack_in,
     * so nginx typically finds no registration and never reads the key or
     * synack_expect.  When nothing was captured (refused, timed out, closed
     * early or the capture insert failed), nginx removes the registration
     * at close and, through its key, the expectation.  It does so after
     * connect() has sent this SYN, unless something like NFQUEUE holds the
     * SYN back; then at worst the key is left for the LRU map.  The update
     * overwrites a key left behind by an owner that is gone; two live
     * connections never build the same key, which needs the same wire tuple
     * and ISN.
     */
    c->key = wire;
    expect.cookie = cookie;

    if (bpf_map_update_elem(&synack_expect, &wire, &expect, BPF_ANY)) {
        synack_count(SYNACK_STAT_EXPECT_FAILED);
    }

    return SYNACK_NF_ACCEPT;
}


SEC("netfilter")
int
synack_in(struct bpf_nf_ctx *ctx)
{
    int                          flags;
    __u32                        zero, length, seq;
    __u64                        cookie;
    struct synack_key            key = {};
    struct synack_packet         p;
    struct synack_record        *record;
    struct synack_connection    *c;
    struct synack_expectation   *e;

    zero = 0;
    length = 0;
    seq = 0;

    /* every inbound packet reaches this hook: stay cheap until a match */
    if (synack_packet_init(ctx->skb, &p) || !synack_candidate(&p)) {
        return SYNACK_NF_ACCEPT;
    }

    flags = synack_parse_packet(&p, &key, &length, &seq);

    if ((flags & SYNACK_TCP_FLAGS) != (SYNACK_TCP_SYN|SYNACK_TCP_ACK)) {
        return SYNACK_NF_ACCEPT;
    }

    e = bpf_map_lookup_elem(&synack_expect, &key);
    if (e == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    record = bpf_map_lookup_elem(&synack_scratch, &zero);
    if (record == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    __builtin_memset(record, 0, sizeof(*record));

    if (synack_copy_headers(&p, record->headers, length)) {
        return SYNACK_NF_ACCEPT;
    }

    cookie = e->cookie;

    /* a key whose owner is gone matches nothing */
    c = bpf_map_lookup_elem(&synack_conn, &cookie);
    if (c == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    /* claim the connection so only one SYN-ACK is ever stored */
    if (__sync_val_compare_and_swap(&c->phase, SYNACK_PENDING, SYNACK_CLAIMED)
        != SYNACK_PENDING)
    {
        return SYNACK_NF_ACCEPT;
    }

    record->length = length;

    if (bpf_map_update_elem(&synack_capture, &cookie, record, BPF_NOEXIST)) {
        __sync_lock_test_and_set(&c->phase, SYNACK_PENDING);
        synack_count(SYNACK_STAT_CAPTURE_FAILED);
        return SYNACK_NF_ACCEPT;
    }

    /* the key this SYN-ACK matched is the one the connection's SYN added */
    e = bpf_map_lookup_elem(&synack_expect, &key);
    if (e && e->cookie == cookie) {
        bpf_map_delete_elem(&synack_expect, &key);
    }

    /* the capture now carries the result; c must not be used after this */
    bpf_map_delete_elem(&synack_conn, &cookie);

    synack_count(SYNACK_STAT_CAPTURED);

    return SYNACK_NF_ACCEPT;
}


char LICENSE[] SEC("license") = "GPL";
