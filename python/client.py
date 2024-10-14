from scapy.all import *

def test_syn_rst():
    ip = IP(dst="178.79.140.213")
    syn = TCP(sport=19994, dport=8000,flags="S",seq=100)
    synack = sr1(ip/syn)
    rst = TCP(sport=19994, dport=8000, flags="RA", seq=synack.seq)
    send(ip/rst)


def test_syn_ack_rst():
    ip = IP(dst="178.79.140.213")
    syn = TCP(sport=19994, dport=8000,flags="S",seq=100)
    synack = sr1(ip/syn)
    ack = TCP(sport=19994, dport=8000, flags="A", seq=synack.ack + 1, ack=synack.seq + 1 )
    send(ip/ack)
    rst = TCP(sport=19994, dport=8000, flags="RP", seq = synack.ack + 2, window=0)
    send(ip/rst)

def test_psh():
    ip = IP(dst="178.79.140.213")
    syn = TCP(sport=19994, dport=8000,flags="S",seq=100)
    synack = sr1(ip/syn)
    ack = TCP(sport=19994, dport=8000, flags="A", seq=synack.ack + 1, ack=synack.seq + 1 )
    send(ip/ack)
    

if __name__ == "__main__":
    test_syn_ack_rst()