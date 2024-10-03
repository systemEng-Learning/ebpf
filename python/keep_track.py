from bcc import BPF
from time import sleep

b = BPF(src_file="track.c", cflags=["-Wno-macro-redefined"])

print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
	sleep(99999999)
except KeyboardInterrupt:
	print()

# output
b["dist"].print_log2_hist("count")
