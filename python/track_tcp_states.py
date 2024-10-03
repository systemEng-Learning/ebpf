from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6;
from time import strftime, time
from os import getuid

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <bcc/proto.h>

BPF_HASH(last, struct sock *, u64);

struct ipv4_data_t {
    u64 ts_us;
    u64 skaddr;
    u32 saddr[1];
    u32 daddr[1];
    u64 span_us;
    u32 pid;
    u16 lport;
    u16 dport;
    int oldstate;
    int newstate;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u64 ts_us;
    u64 skaddr;
    u32 saddr[4];
    u32 daddr[4];
    u64 span_us;
    u32 pid;
    u16 lport;
    u16 dport;
    int oldstate;
    int newstate;
    char task[TASK_COMM_LEN];
};

BPF_PERF_OUTPUT(ipv6_events);

TRACEPOINT_PROBE(sock, inet_sock_set_state) {
    if ( args->protocol != IPPROTO_TCP ) {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct sock *sk = (struct sock *)args->skaddr;

    u16 lport = args->sport;
    u16 dport = args->dport;

    u64 *tsp, delta_us;
    tsp = last.lookup(&sk);
    if ( tsp == 0 ) {
        delta_us = 0;
    } else {
        delta_us = (bpf_ktime_get_ns() - *tsp)/1000;
    }
    int tcp_newstate = args->newstate;
    if ( args->family == AF_INET ) {
        struct ipv4_data_t data4 = {
            .span_us = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate };
        data4.skaddr = (u64)args->skaddr;
        data4.ts_us = bpf_ktime_get_ns()/1000;
        __builtin_memcpy(&data4.saddr, args->saddr, sizeof(data4.saddr));
        __builtin_memcpy(&data4.daddr, args->daddr, sizeof(data4.daddr));
        data4.lport = lport;
        data4.dport = dport;
        data4.pid = pid;

        bpf_get_current_comm(&data4.task, sizeof(data4.task));
        ipv4_events.perf_submit(args, &data4, sizeof(data4));
    } else {
        struct ipv6_data_t data6 = {
            .span_us = delta_us,
            .oldstate = args->oldstate,
            .newstate = args->newstate };
        data6.skaddr = (u64)args->skaddr;
        data6.ts_us = bpf_ktime_get_ns()/1000;
        __builtin_memcpy(&data6.saddr, args->saddr_v6, sizeof(data6.saddr));
        __builtin_memcpy(&data6.daddr, args->daddr_v6, sizeof(data6.daddr));
        data6.lport = lport;
        data6.dport = dport;
        data6.pid = pid;

        bpf_get_current_comm(&data6.task, sizeof(data6.task));
        ipv6_events.perf_submit(args, &data6, sizeof(data6));
    }

    if ( tcp_newstate == TCP_CLOSE ) {
        last.delete(&sk);
    } else {
        u64 ts = bpf_ktime_get_ns();
        last.update(&sk, &ts);
    }

    return 0;
}
"""
header_string = "%-16s %-5s %-10.10s %s%-15s %-5s %-15s %-5s %-11s -> %-11s %s"
format_string = ("%-16x %-5d %-10.10s %s%-15s %-5d %-15s %-5d %-11s -> %-11s %.3f")


def tcpstate2str(state):
    tcpstate = {
            1: "ESTABLISHED",
            2: "SYN_SENT",
            3: "SYN_RECV",
            4: "FIN_WAIT1",
            5: "FIN_WAIT2",
            6: "TIME_WAIT",
            7: "CLOSE",
            8: "CLOSE_WAIT",
            9: "LAST_ACK",
            10: "LISTEN",
            11: "CLOSING",
            12: "NEW_SYN_RECV",
     }

    if state in tcpstate:
        return tcpstate[state]
    else:
        return str(state)


def print_event(event, addr_family):
    global start_ts
    if start_ts == 0:
        start_ts = event.ts_us
    delta_s = (float(event.ts_us) - start_ts)/1000000

    print(format_string % (event.skaddr, event.pid, event.task.decode('utf-8', 'replace'),
        "",  inet_ntop(addr_family, event.saddr), event.lport,
        inet_ntop(addr_family, event.daddr), event.dport,
        tcpstate2str(event.oldstate), tcpstate2str(event.newstate),
        float(event.span_us)/1000))

def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    print_event(event, AF_INET)

def print_ipv6_event(cpu, data, size):
    event = b["ipv6_events"].event(data)
    print_event(event, AF_INET6)

b = BPF(text=bpf_text, cflags=["-Wno-macro-redefined"])

print("%-9s " % ("TIME(s)"), end="")
print(header_string % ("SKADDR", "C-PID", "C-COMM", "", "LADDR", "LPORT", "RADDR", "RPORT", "OLDSTATE", "NEWSTATE", "MS"))

start_ts = 0

b["ipv4_events"].open_perf_buffer(print_ipv4_event, page_cnt=64)
b["ipv6_events"].open_perf_buffer(print_ipv6_event, page_cnt=64)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
