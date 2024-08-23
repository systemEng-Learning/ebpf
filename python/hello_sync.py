from bcc import BPF

print("Tracing sys_sync.....Ctrc-C to end")
BPF(text='int kprobe__sys_sync(void *ctx) { bpf_trace_printk("sys_sync() called\\n"); return 0; }', cflags=["-Wno-macro-redefined"]).trace_print()
