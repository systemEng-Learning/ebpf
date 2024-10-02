from bcc import BPF
import ctypes as ct
import time

# Load the eBPF program from the C file
b = BPF(src_file="tcpabort.c")

# Attach probes to kernel functions
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_syn")
b.attach_kprobe(event="tcp_set_state", fn_name="trace_ack")
b.attach_kprobe(event="tcp_sendmsg", fn_name="trace_psh")
b.attach_kprobe(event="tcp_recvmsg", fn_name="trace_data")
b.attach_kprobe(event="tcp_close", fn_name="trace_close")

# Time interval for reporting statistics (in seconds)
REPORT_INTERVAL = 10

# Enum values to be used for lookup instead of string names
STAGE_POST_SYN = 1
STAGE_POST_ACK = 2
STAGE_POST_PSH = 3
STAGE_LATER = 4

def calculate_percentage(stage_key):
    # Convert stage_key to ctypes for use in BPF table lookup
    key = ct.c_ulonglong(stage_key)
    
    total = total_connections[key].value if key in total_connections else 0
    aborted = aborted_connections[key].value if key in aborted_connections else 0
    if total == 0:
        return 0
    return (aborted / total) * 100

print("Tracking connection resets/timeouts at different stages. Press Ctrl+C to stop.")

try:
    while True:
        time.sleep(REPORT_INTERVAL)

        # Fetch connection stats
        total_connections = b.get_table("total_connections")
        aborted_connections = b.get_table("aborted_connections")

        # Calculate and display percentages for each stage using enum values
        for stage_key, stage_name in [(STAGE_POST_SYN, "STAGE_POST_SYN"), 
                                      (STAGE_POST_ACK, "STAGE_POST_ACK"),
                                      (STAGE_POST_PSH, "STAGE_POST_PSH"),
                                      (STAGE_LATER, "STAGE_LATER")]:
            percent = calculate_percentage(stage_key)
            print(f"Stage {stage_name}: {percent:.2f}% aborted connections")

except KeyboardInterrupt:
    print("Stopping...")
