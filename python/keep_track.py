from bcc import BPF
from bcc.utils import printb
from time import sleep

b = BPF(src_file="track.c", cflags=["-Wno-macro-redefined"])

print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
s = True
while s:
    try:
        (task, pid, cpu, flags, ts, ms) = b.trace_fields()
        printb(b"%s" % (ms))
    except KeyboardInterrupt:
        print()
        s = False

# output
b["dist"].print_linear_hist("count")
