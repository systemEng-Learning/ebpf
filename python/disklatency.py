from bcc import BPF
from time import sleep


b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, struct request *);
BPF_HISTOGRAM(dist);

void trace_start(struct pt_regs *ctx, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;
    tsp = start.lookup(&req);
    if ( tsp != 0 ) {
        delta = bpf_ktime_get_ns() - *tsp;
        dist.increment(bpf_log2l(delta/1000));
        start.delete(&req);
    }
}
""", cflags=["-Wno-macro-redefined"])

if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion")
b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")

print("Tracing... Hit Ctrl-C to end")

try:
    sleep(999999999)
except KeyboardInterrupt:
    print()

b["dist"].print_log2_hist("us")
