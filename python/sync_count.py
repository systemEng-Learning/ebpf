from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

prog = """
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, *csp, delta, key = 0;
    u64 ckey = 1;
    u64 count = 0;
    tsp = last.lookup(&key);
    csp = last.lookup(&ckey);
    if (tsp != NULL && csp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        count = *csp;
        if (delta < 1000000000) {
            bpf_trace_printk("%d %d\\n", delta / 1000000, count);
        }
        last.delete(&key);
        last.delete(&ckey);
    }
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    count = count + 1;
    last.update(&ckey, &count);
    return 0;
}
"""
b = BPF(text=prog, cflags=["-Wno-macro-redefined"])
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")

print("Tracing for quick sync's... Ctrl-C to end")

start = 0
while True:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (ms, count) = msg.split()
        if start == 0:
            start = ts
        ts = ts - start
        printb(b"At time %.2f s: multiple syncs detected, last %s ms ago, called %s times" % (ts, ms, count))
    except KeyboardInterrupt:
        exit()
