from __future__ import print_function
from bcc import BPF
from bcc.utils import printb

prog = """
#include <uapi/linux/ptrace.h>

struct data_t {
    u64 ts;
    u64 ms;
    u64 count;
};

BPF_PERF_OUTPUT(timings);
BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, *csp, delta, key = 0;
    u64 ckey = 1;
    u64 count = 0;
    struct data_t data = {};
    tsp = last.lookup(&key);
    csp = last.lookup(&ckey);
    ts = bpf_ktime_get_ns();
    if (tsp != NULL && csp != NULL) {
        delta = ts - *tsp;
        count = *csp;
        if (delta < 1000000000) {
            data.ts = ts;
            data.count = count + 1;
            data.ms = delta / 1000000;
            timings.perf_submit(ctx, &data, sizeof(data));
        }
        last.delete(&key);
        last.delete(&ckey);
    }
    last.update(&key, &ts);
    count = count + 1;
    last.update(&ckey, &count);
    return 0;
}
"""
b = BPF(text=prog, cflags=["-Wno-macro-redefined"])
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")

print("%-18s %-8s %s" % ("TIME(s)", "DIFF", "COUNT"))
start = 0

def print_timing(cpu, data, size):
    global start
    timings = b["timings"].event(data)
    if start == 0:
        start = timings.ts
    time_s = (float(timings.ts - start)) / 1000000000
    print("%-18.9f %-8d %d" % (time_s, timings.ms, timings.count))

b["timings"].open_perf_buffer(print_timing)
while True:
    b.perf_buffer_poll()
