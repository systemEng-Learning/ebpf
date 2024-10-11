#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>


BPF_HASH(traced, struct sock *, u8);
BPF_HASH(counts, struct sock *, u64);
BPF_HASH(is_rst, struct sock *, u8);
BPF_HISTOGRAM(dist);

static struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb) {
	// unstable API. verify logic in tcp_hdr() -> skb_transport_header().
	return (struct tcphdr *)(skb->head + skb->transport_header);
}

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
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

int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u8 *tsp;
    tsp = traced.lookup(&sk);
    if ( tsp == 0 ) {
        return 0;
    }
    u64 *csp;
    csp = counts.lookup(&sk);
    if ( csp == 0 ) {
        u64 c = 1;
        counts.update(&sk, &c);
    } else {
        counts.increment(sk);
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
}

int kprobe__tcp_rcv_state_process(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    if ( sk->__sk_common.skc_state != TCP_LISTEN ) {
        return 0;
    }
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    u8 flag = ((u_int8_t *)tcp)[13];
    u8 syn = flag & 2;
    u8 fin = flag & 1;
    u8 ts = 1;
    if ( syn && !fin ) {
        traced.update(&sk, &ts);
        bpf_trace_printk("state: syn_received\\n");
    }
    return 0;
}
