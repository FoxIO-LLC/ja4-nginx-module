// SPDX-License-Identifier: GPL-2.0

/*
 * Upstream SYN-ACK capture.
 *
 * synack_out (POSTROUTING, the last hook, after SNAT and OUTPUT DNAT) sees
 * each SYN of a registered socket and records the SYN-ACK it expects: the
 * SYN's wire tuple reversed, acknowledging S + 1.  synack_in runs first in
 * PREROUTING, before conntrack undoes NAT, so a reply from another host or
 * namespace arrives in exactly that form, across DNAT/SNAT.  A reply that
 * loops back inside this namespace is un-NATed on its way out and does not
 * match; such local backends are not captured.  nginx does not use TCP Fast
 * Open upstream, so a SYN-ACK that acknowledges SYN data is not expected.  synack_in (early
 * PREROUTING) matches incoming SYN-ACKs against those keys and stores the
 * original IP/TCP headers for nginx to consume by socket cookie.
 */


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


/*
 * Bounded IP/TCP header reader for Netfilter BPF programs.
 *
 * synack_parse_packet() validates the headers from small stack copies and
 * returns the TCP flags; synack_copy_headers() then copies the complete
 * headers.  Callers check the flags and map state in between, so packets that
 * are not of interest never pay for the full copy.
 */

static __always_inline int
synack_parse_packet(struct sk_buff *skb, struct synack_key *key,
    __u32 *header_len, __u32 *sequence)
{
    int             i;
    __u8            ip[40], tcp[20], ext[2], next;
    __u32           offset, tail, off, total, tcp_len, step;
    __u64           data_offset, packet_length;
    unsigned char  *head;

    /*
     * ctx->skb is a BTF pointer: direct CO-RE loads avoid helper calls on
     * the per-packet path.  Packet bytes still need bounded probe reads.
     */

    head = skb->head;
    offset = skb->network_header;
    tail = skb->tail;
    data_offset = skb->data - head;
    packet_length = skb->len;

    /*
     * Probe reads do not enforce skb bounds, so check the linear head
     * explicitly.  Headers outside it are deliberately rejected.
     */

    if (offset > tail
        || tail - offset < 20
        || data_offset > tail
        || packet_length + data_offset < offset)
    {
        return 0;
    }

    packet_length += data_offset - offset;

    if (bpf_probe_read_kernel(ip, 20, head + offset)) {
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

        if (tail - offset < 40
            || bpf_probe_read_kernel(ip, 40, head + offset))
        {
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
            if (off > SYNACK_MAX_TCP_OFFSET
                || off + 2 > tail - offset
                || off + 2 > total)
            {
                return 0;
            }

            if (bpf_probe_read_kernel(ext, 2, head + offset + off)) {
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
                return 0;           /* fragment, ESP or unknown */
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

    if (total > packet_length
        || off > SYNACK_MAX_TCP_OFFSET
        || off + 20 > tail - offset
        || off + 20 > total)
    {
        return 0;
    }

    if (bpf_probe_read_kernel(tcp, 20, head + offset + off)) {
        return 0;
    }

    tcp_len = (tcp[12] >> 4) * 4;

    if (tcp_len < 20
        || off + tcp_len > SYNACK_MAX_HEADERS
        || off + tcp_len > total
        || off + tcp_len > tail - offset)
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
 * synack_in sees every inbound packet, so this looks first: one probe read
 * covers the IP header and the TCP flags byte for the common layouts, IPv4
 * without options and IPv6 without extension headers, and decides those.
 * Packets too short or malformed for the full parse are turned away here
 * too, so only IPv4 options and IPv6 extension headers, which one read
 * cannot cover, are left to it.  Returns 0 only where the full parse could
 * not yield a SYN-ACK either.
 */

#define SYNACK_FLAGS_READ_V4        34      /* IPv4 + TCP up to the flags */
#define SYNACK_FLAGS_READ_V6        54      /* IPv6 + TCP up to the flags */
#define SYNACK_MIN_TCP_V4           40      /* IPv4 + TCP headers, no options */
#define SYNACK_MIN_TCP_V6           60      /* IPv6 + TCP headers */

static __always_inline int
synack_candidate(struct sk_buff *skb)
{
    __u8            b[SYNACK_FLAGS_READ_V6], next, flags;
    __u32           offset, tail;
    unsigned char  *head;

    head = skb->head;
    offset = skb->network_header;
    tail = skb->tail;

    /* the full parse needs at least an IPv4 and a TCP header */

    if (offset > tail || tail - offset < SYNACK_MIN_TCP_V4) {
        return 0;
    }

    if (tail - offset >= SYNACK_FLAGS_READ_V6) {
        if (bpf_probe_read_kernel(b, SYNACK_FLAGS_READ_V6, head + offset)) {
            return 1;
        }

    } else if (bpf_probe_read_kernel(b, SYNACK_FLAGS_READ_V4, head + offset)) {
        return 1;                       /* not invalid: let the full parse try */
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

        if (tail - offset < SYNACK_MIN_TCP_V6) {
            return 0;                   /* no room for the TCP header */
        }

        flags = b[53];

    } else {
        return 0;
    }

    return (flags & SYNACK_TCP_FLAGS) == (SYNACK_TCP_SYN|SYNACK_TCP_ACK);
}


/* header_len must come from a successful synack_parse_packet() on skb */

static __always_inline int
synack_copy_headers(struct sk_buff *skb, __u8 *bytes, __u32 header_len)
{
    __u64           read_len;
    unsigned char  *head;

    head = skb->head + skb->network_header;
    read_len = header_len;

    /* keep the verifier's bound on the exact register used by the helper */
    asm volatile("" : "+r"(read_len));

    if (read_len == 0 || read_len > SYNACK_MAX_HEADERS) {
        return -1;
    }

    return bpf_probe_read_kernel(bytes, read_len, head) ? -1 : 0;
}


/*
 * Capture, consume and close remove entries on the fast path.  What a failure
 * leaves behind (a crashed worker, a missed SYN-ACK) is
 * never looked up again, so the LRU maps evict it first when an insert needs
 * room; no sweep runs, and nothing needs the clock.
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


static __always_inline void
synack_remove_owned(struct synack_key *key, __u64 cookie)
{
    struct synack_expectation  *e;

    e = bpf_map_lookup_elem(&synack_expect, key);

    if (e && e->cookie == cookie) {
        bpf_map_delete_elem(&synack_expect, key);
    }
}


/*
 * A key's owner is alive while its registration exists: nginx removes it at
 * consume or close, and synack_in once it stores the capture.
 */

static __always_inline int
synack_owner_alive(__u64 cookie)
{
    return bpf_map_lookup_elem(&synack_conn, &cookie) != NULL;
}


static __always_inline void
synack_add_expectation(struct synack_key *key, __u64 cookie,
    struct synack_connection *c)
{
    struct synack_expectation  *e, value = {
        .cookie = cookie
    };

    if (c->phase != SYNACK_PENDING) {
        return;
    }

    /*
     * A retransmitted SYN has the same key, and goes on to re-add it if the
     * LRU map evicted it.  A SYN with another sequence number would need a
     * second key; a socket never sends one, so keep the first.
     */

    if (c->has_key && __builtin_memcmp(&c->key, key, sizeof(*key)) != 0) {
        synack_count(SYNACK_STAT_SECOND_KEY);
        return;
    }

    e = bpf_map_lookup_elem(&synack_expect, key);

    if (e == NULL
        && bpf_map_update_elem(&synack_expect, key, &value, BPF_NOEXIST))
    {
        /* lost an insert race */

        e = bpf_map_lookup_elem(&synack_expect, key);
        if (e == NULL) {
            synack_count(SYNACK_STAT_EXPECT_FULL);
            return;
        }
    }

    if (e && e->cookie != cookie) {

        /*
         * Another live connection already expects this key: the same tuple
         * and initial sequence number, which only crafted traffic produces.
         * The first owner keeps it; a SYN-ACK matching it is captured for
         * that owner, and this connection misses.
         */

        if (synack_owner_alive(e->cookie)) {
            synack_count(SYNACK_STAT_COLLISION);
            return;
        }

        /*
         * The owner is gone, e.g. its worker crashed: take the key over as
         * if absent.  A concurrent synack_in that still reads the old cookie
         * finds no registration for it and ignores the key.
         */

        e->cookie = cookie;
    }

    if (!c->has_key) {
        c->key = *key;
        c->has_key = 1;
    }

    /* a concurrent synack_in may have completed while the key was added */

    if (c->phase != SYNACK_PENDING) {
        synack_remove_owned(key, cookie);
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
    struct synack_connection    *c;

    /*
     * Every outbound packet in the namespace reaches this hook, and only a
     * registered socket's SYN matters: two field reads let everything else
     * through before the map lookup.
     */

    sk = ctx->state->sk;
    if (sk == NULL) {
        sk = ctx->skb->sk;
    }

    if (sk == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    /*
     * A TCP socket sends SYNs (first and retransmitted) only in SYN_SENT.
     * Established TCP and connected UDP, the bulk of traffic, stop here.
     * CLOSE passes too: unconnected raw and UDP sockets report it (capture.py
     * injects crafted SYNs from a raw socket), and a TCP socket in CLOSE sends
     * no data; they stop at the cookie check.  The SYN flag is still checked
     * once the headers are parsed.
     */

    state = sk->__sk_common.skc_state;
    if (state != TCP_SYN_SENT && state != TCP_CLOSE) {
        return SYNACK_NF_ACCEPT;
    }

    /* the cookie is assigned on first use; nginx asks before registering */

    cookie = sk->__sk_common.skc_cookie.counter;
    if (cookie == 0) {
        return SYNACK_NF_ACCEPT;
    }

    c = bpf_map_lookup_elem(&synack_conn, &cookie);

    if (c == NULL || c->phase != SYNACK_PENDING) {
        return SYNACK_NF_ACCEPT;
    }

    length = 0;
    seq = 0;

    flags = synack_parse_packet(ctx->skb, &packet, &length, &seq);

    if ((flags & SYNACK_TCP_FLAGS) != SYNACK_TCP_SYN) {
        return SYNACK_NF_ACCEPT;
    }

    /* a retransmitted SYN re-adds the same keys */

    /* the SYN-ACK as it will arrive: the wire SYN reversed, acknowledging it */

    wire.family = packet.family;
    wire.protocol = IPPROTO_TCP;
    __builtin_memcpy(wire.src, packet.dst, 16);
    __builtin_memcpy(wire.dst, packet.src, 16);
    wire.sport = packet.dport;
    wire.dport = packet.sport;
    wire.ack = bpf_htonl(bpf_ntohl(seq) + 1);

    synack_add_expectation(&wire, cookie, c);

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
    struct synack_record        *tmp;
    struct synack_connection    *c;
    struct synack_expectation   *e;

    zero = 0;
    length = 0;
    seq = 0;

    /* every inbound packet reaches this hook: stay cheap until a match */

    if (!synack_candidate(ctx->skb)) {
        return SYNACK_NF_ACCEPT;
    }

    flags = synack_parse_packet(ctx->skb, &key, &length, &seq);

    if ((flags & SYNACK_TCP_FLAGS) != (SYNACK_TCP_SYN|SYNACK_TCP_ACK)) {
        return SYNACK_NF_ACCEPT;
    }

    e = bpf_map_lookup_elem(&synack_expect, &key);

    if (e == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    tmp = bpf_map_lookup_elem(&synack_scratch, &zero);
    if (tmp == NULL) {
        return SYNACK_NF_ACCEPT;
    }

    __builtin_memset(tmp, 0, sizeof(*tmp));

    if (synack_copy_headers(ctx->skb, tmp->headers, length)) {
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

    tmp->version = SYNACK_VERSION;
    tmp->length = length;

    if (bpf_map_update_elem(&synack_capture, &cookie, tmp, BPF_NOEXIST)) {
        __sync_lock_test_and_set(&c->phase, SYNACK_PENDING);
        synack_count(SYNACK_STAT_CAPTURE_FULL);
        return SYNACK_NF_ACCEPT;
    }

    __sync_lock_test_and_set(&c->phase, SYNACK_COMPLETE);

    if (c->has_key) {
        synack_remove_owned(&c->key, cookie);
    }

    /* the capture now carries the result; c must not be used after this */

    bpf_map_delete_elem(&synack_conn, &cookie);

    synack_count(SYNACK_STAT_CAPTURED);

    return SYNACK_NF_ACCEPT;
}


char LICENSE[] SEC("license") = "GPL";
