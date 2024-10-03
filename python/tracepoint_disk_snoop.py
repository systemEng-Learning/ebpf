from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1

b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(bytes, dev_t);
BPF_HASH(times, dev_t);

TRACEPOINT_PROBE(block, block_rq_issue){
    u64 ts = bpf_ktime_get_ns();
    times.update(&(args->dev), &ts);
    bytes.update(&(args->dev), (u64 *)&(args->bytes));
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete){
    u64 *tsp, delta, *len;
    tsp = times.lookup(&(args->dev));
    if ( tsp != 0 ) {
        delta = bpf_ktime_get_ns() - *tsp;
        len = bytes.lookup(&(args->dev));
        bpf_trace_printk("%u %s %d\\n", len, args->rwbs, delta/1000);
        times.delete(&(args->dev));
        bytes.delete(&(args->dev));
    }
    return 0;
}
""", cflags=["-Wno-macro-redefined"])


print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (bytes_s, bflags_s, us_s) = msg.split()

        ms = float(int(us_s, 10)) / 1000

        printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, bflags_s, bytes_s, ms))
    except KeyboardInterrupt:
        exit()
