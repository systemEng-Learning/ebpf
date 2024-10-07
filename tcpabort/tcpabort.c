#include <uapi/linux/ptrace.h>
#include <net/tcp.h>
#include <bcc/proto.h>

BPF_HASH(conn_stage, struct sock *, u64);
BPF_HASH(total_connections, u64, u64);
BPF_HASH(aborted_connections, u64, u64);

enum conn_stages {
    STAGE_POST_SYN = 1,
    STAGE_POST_ACK,
    STAGE_POST_PSH,
    STAGE_LATER
};

// Track Post-SYN stage (mid-handshake)
int trace_syn(struct pt_regs *ctx, struct sock *sk) {
    u64 ts = bpf_ktime_get_ns();
    u64 stage = STAGE_POST_SYN;
    conn_stage.update(&sk, &stage);

    // Increment total connection count for Post-SYN stage
    u64 stage_key = STAGE_POST_SYN;
    u64 zero = 0;
    u64 *val = total_connections.lookup_or_try_init(&stage_key, &zero);
    if (val) {
        (*val)++;
    }
    
    return 0;
}

// Track Post-ACK stage (after handshake)
int trace_ack(struct pt_regs *ctx, struct sock *sk) {
    u64 *stage = conn_stage.lookup(&sk);
    if (stage && *stage == STAGE_POST_SYN) {
        u64 new_stage = STAGE_POST_ACK;
        conn_stage.update(&sk, &new_stage);

        // Increment total connection count for Post-ACK stage
        u64 stage_key = STAGE_POST_ACK;
        u64 zero = 0;
        u64 *val = total_connections.lookup_or_try_init(&stage_key, &zero);
        if (val) {
            (*val)++;
        }
    }
    return 0;
}

// Track Post-PSH stage (after first data packet)
int trace_psh(struct pt_regs *ctx, struct sock *sk) {
    u64 *stage = conn_stage.lookup(&sk);
    if (stage && *stage == STAGE_POST_ACK) {
        u64 new_stage = STAGE_POST_PSH;
        conn_stage.update(&sk, &new_stage);

        // Increment total connection count for Post-PSH stage
        u64 stage_key = STAGE_POST_PSH;
        u64 zero = 0;
        u64 *val = total_connections.lookup_or_try_init(&stage_key, &zero);
        if (val) {
            (*val)++;
        }
    }
    return 0;
}

// Track later stages (after multiple data packets)
int trace_data(struct pt_regs *ctx, struct sock *sk) {
    u64 *stage = conn_stage.lookup(&sk);
    if (stage && *stage == STAGE_POST_PSH) {
        u64 new_stage = STAGE_LATER;
        conn_stage.update(&sk, &new_stage);

        // Increment total connection count for Later stage
        u64 stage_key = STAGE_LATER;
        u64 zero = 0;
        u64 *val = total_connections.lookup_or_try_init(&stage_key, &zero);
        if (val) {
            (*val)++;
        }
    }
    return 0;
}

// Detect connection resets or timeouts (this is where resets and timeouts are tracked)
int trace_close(struct pt_regs *ctx, struct sock *sk) {
    u64 *stage = conn_stage.lookup(&sk);
    if (stage) {
        if (sk->sk_state == TCP_CLOSE || sk->sk_state == TCP_FIN_WAIT1 || sk->sk_state == TCP_FIN_WAIT2) {
            // Check which stage we are in and increment aborted connection count
            u64 *aborted_val, stage_key;

            if (*stage == STAGE_POST_SYN) {
                stage_key = STAGE_POST_SYN;
                bpf_trace_printk("Connection reset/timeout at Post-SYN stage\\n");
            } else if (*stage == STAGE_POST_ACK) {
                stage_key = STAGE_POST_ACK;
                bpf_trace_printk("Connection reset/timeout at Post-ACK stage\\n");
            } else if (*stage == STAGE_POST_PSH) {
                stage_key = STAGE_POST_PSH;
                bpf_trace_printk("Connection reset/timeout at Post-PSH stage\\n");
            } else if (*stage == STAGE_LATER) {
                stage_key = STAGE_LATER;
                bpf_trace_printk("Connection reset/timeout at Later stage\\n");
            }

            
            u64 zero = 0;
            aborted_val = aborted_connections.lookup_or_try_init(&stage_key, &zero);
            if (aborted_val) {
                (*aborted_val)++;
            }

            conn_stage.delete(&sk); 
        }
    }
    return 0;
}