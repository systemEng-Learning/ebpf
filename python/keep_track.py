from bcc import BPF

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>

struct event_data_t {
    int type;
    u64 skaddr;
};

BPF_HASH(last, struct sock *, u64);

BPF_PERF_OUTPUT(events);

int kprobe__tcp_set_state(struct pt_regs *ctx, struct sock *sk, int state) {
    struct event_data_t data = {
        .type = 1,
    };
    u64 *tsp;
    tsp = last.lookup(&sk);
    if ( tsp == 0 && state != TCP_CLOSE ) {
        u64 ts = 1;
        last.update(&sk, &ts);
    } else if ( state == TCP_CLOSE ) {
        last.delete(&sk);
    }
    data.skaddr = (u64)sk;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int kprobe__tcp_rcv_established(struct pt_regs *ctx, struct sock *sk, struct sk_buff *skb) {
    u64 *tsp;
    tsp = last.lookup(&sk);
    if ( tsp == 0 ) {
        return 0;
    }
    struct event_data_t data = {
        .type = 2,
    };
    data.skaddr = (u64)sk;
    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(("%-16x %d") % (event.skaddr, event.type))

print(("%-16s %s") % ("ADDR", "TYPE")) 
b = BPF(text=bpf_text, cflags=["-Wno-macro-redefined"])
b["events"].open_perf_buffer(print_event, page_cnt=64)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
