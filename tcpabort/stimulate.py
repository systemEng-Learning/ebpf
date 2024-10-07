import socket
import time
import struct

def simulate_post_ack_abort(target_ip, target_port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        print("Handshake complete (STAGE_POST_ACK)")
        sock.close()  # Closing after handshake but before data transfer
        print("Connection aborted at STAGE_POST_ACK")
    except Exception as e:
        print(f"Connection failed (STAGE_POST_ACK): {e}")

def simulate_data_transfer_abort(target_ip, target_port, data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        print("Handshake complete (STAGE_POST_ACK)")
        sock.sendall(data)  # Send data (reaching PSH stage)
        print("Data sent (STAGE_POST_PSH)")
        sock.close()  # Aborting right after sending data (PSH stage abort)
        print("Connection aborted at STAGE_POST_PSH")
    except Exception as e:
        print(f"Connection failed (STAGE_POST_PSH): {e}")

def simulate_later_stage_abort(target_ip, target_port, data):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target_ip, target_port))
        print("Handshake complete (STAGE_POST_ACK)")
        sock.sendall(data)  # Send data (reaching PSH stage)
        print("Data sent (STAGE_POST_PSH)")
        response = sock.recv(1024)  # Waiting for server's response
        print(f"Response from server: {response} (STAGE_LATER)")
        # Abort after receiving server response but before graceful shutdown
        sock.close()
        print("Connection aborted at STAGE_LATER")
    except Exception as e:
        print(f"Connection failed (STAGE_LATER): {e}")

if __name__ == "__main__":
    target_ip = "0.0.0.0"
    target_port = 8000

    for _ in range(5):
        simulate_post_ack_abort(target_ip, target_port)
        time.sleep(1)

    data = b"Hello, this is a test message!"
    for _ in range(5):
        simulate_data_transfer_abort(target_ip, target_port, data)
        time.sleep(1)

    for _ in range(5):
        simulate_later_stage_abort(target_ip, target_port, data)
        time.sleep(1)
