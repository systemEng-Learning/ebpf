#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <bcc/proto.h>


BPF_HASH(syn_map, u32, u8);
BPF_HASH(ack_map, u32, u8);
BPF_HASH(data_map, struct sock *, u64);
BPF_HISTOGRAM(dist);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
	// unstable API. verify logic in tcp_hdr() -> skb_transport_header().
	return (struct tcphdr *)(skb->head + skb->transport_header);
}

static inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb) {
    return (struct iphdr *)(skb->head + skb->network_header);
}

int kprobe__tcp_v4_rcv(struct pt_regs *ctx, struct sk_buff *skb) {
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    u16 dport = tcp->dest;
    dport = ntohs(dport);
    if ( dport != 8000 ) {
        return 0;
    } 
    u8 flag = ((u_int8_t *)tcp)[13];
    u8 rst = flag & 4;
    u32 key = ip->saddr + (u32)tcp->source;
    u8 *synp = syn_map.lookup(&key);
    if ( rst && synp != 0 ) {
        syn_map.delete(&key);
        bpf_trace_printk("state: rst_received: %u\\n", key);
        dist.increment(0);
    }

    u8 *ackp = ack_map.lookup(&key);
    if ( rst && ackp != 0 ) {
        ack_map.delete(&key);
        bpf_trace_printk("state: rst_received for ack: %u\\n", key);
        dist.increment(1);
    }
    return 0;
}


int kprobe__tcp_rcv_state_process(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if ( sk->sk_state != TCP_SYN_RECV && sk->sk_state != TCP_LISTEN  ) {
        return 0;
    }
    u16 family = sk->__sk_common.skc_family;
    if ( family != AF_INET ) {
        return 0;
    }
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    u16 dport = tcp->dest;
    dport = ntohs(dport);
    if ( dport != 8000 ) {
        return 0;
    } 
    u8 flag = ((u_int8_t *)tcp)[13];
    u8 fin = flag & 1;
    u8 syn = flag & 2;
    u8 ack = flag & 16;
    u32 key = ip->saddr + (u32)tcp->source;
    u8 *synp, *ackp;
    if ( fin ) {
        synp = syn_map.lookup(&key);
        ackp = ack_map.lookup(&key);
        if ( synp != 0 ) {
            syn_map.delete(&key);
        }
        if ( ackp != 0 ) {
            ack_map.delete(&key);
        }
        return 0;
    }
    u8 ts = 1;

    if ( syn && !fin ) {
        syn_map.update(&key, &ts);
        bpf_trace_printk("state: syn_received: %u\\n", key);
    }

    synp = syn_map.lookup(&key);
    if ( ack && !fin && synp != 0 ) {
        syn_map.delete(&key);
        ack_map.update(&key, &ts);
        bpf_trace_printk("state: ack_received: %u\\n", key);
    }
    return 0;
}

int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    u16 dport = tcp->dest;
    dport = ntohs(dport);
    if ( dport != 8000 ) {
        return 0;
    }
    u8 flag = ((u_int8_t *)tcp)[13];
    bpf_trace_printk("state: flag: %u\\n", flag);
    u8 psh = flag & 8;
    if ( psh ) {
        bpf_trace_printk("state: psh received: %u\\n");
    }

    u32 key = sk->__sk_common.skc_rcv_saddr + (u32)sk->__sk_common.skc_num;
    u8 *ackp = ack_map.lookup(&key);
    if ( ackp != 0 ) {
        bpf_trace_printk("state: ack_to_established: %u\\n", key);
    }
    return 0;
}

/**int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    u8 *tsp, ts = 1;
    u64 *csp;
    tsp = traced.lookup(&sk);
    if ( tsp == 0 && ( state == TCP_SYN_SENT || state == TCP_SYN_RECV )) {
        traced.update(&sk, &ts);
    } else {
        return 0;
    }
    int old_state = sk->__sk_common.skc_state;
    if ( old_state == TCP_SYN_SENT && state == TCP_CLOSE ) {
        dist.increment(0);
	bpf_trace_printk("state: syn_sent->close\\n");
    }
    tsp = is_rst.lookup(&sk);
    if ( old_state == TCP_SYN_RECV && state == TCP_CLOSE && tsp == 0 ) {
        dist.increment(0);
	bpf_trace_printk("state: syn_recv->close\\n");
        is_rst.update(&sk, &ts);
    }
    if ( old_state == TCP_ESTABLISHED && state == TCP_CLOSE && tsp == 0 ) {
        csp = counts.lookup(&sk);
        if ( csp == 0 ) {
            dist.increment(1);
	    bpf_trace_printk("state: post_ack->close\\n");

        } else {
            u64 cs = *csp;
            if ( cs == 1 ) {
                dist.increment(2);
		bpf_trace_printk("state: psh->close\\n");
            } else if ( cs > 1 && cs < 11 ) {
                dist.increment(3);
		bpf_trace_printk("state: later->close\\n");
            }
        }
        is_rst.update(&sk, &ts);
    }
    
    if ( state == TCP_CLOSE ) {
        traced.delete(&sk);
        if ( tsp != 0 ) {
            is_rst.delete(&sk);
        }
        if ( csp != 0 ) {
            counts.delete(&sk);
        }
    }
    return 0;
}

int kprobe__tcp_reset(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u8 *tsp, ts = 1;
    tsp = traced.lookup(&sk);
    if ( tsp == 0 ) {
        return 0;
    }
    tsp = is_rst.lookup(&sk);
    if ( tsp != 0 ) {
        return 0;
    }
    u64 *csp;
    csp = counts.lookup(&sk);
    if ( csp == 0 ) {
        dist.increment(1);
	bpf_trace_printk("reset: post_ack->close\\n");
    } else {
        u64 cs = *csp;
        if ( cs == 1 ) {
            dist.increment(2);
	    bpf_trace_printk("reset: psh->close\\n");
        } else if ( cs > 1 && cs < 11 ) {
            dist.increment(3);
	    bpf_trace_printk("reset: later->close\\n");
        }
    }
    is_rst.update(&sk, &ts);
    return 0;
}*/

