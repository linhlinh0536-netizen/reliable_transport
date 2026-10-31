import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum

# Packet types defined by the RTP specification
START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16  # 4 IntFields x 4 bytes
MAX_PACKET_SIZE = 1472  # 1500 (Ethernet) - 20 (IP) - 8 (UDP)
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE  # 1456 bytes of data per packet
TIMEOUT = 0.5  # 500 ms retransmission timer


def make_packet(pkt_type, seq_num, payload=b""):
    """Build an RTP packet (header + payload) with its CRC32 checksum."""
    pkt_header = PacketHeader(type=pkt_type, seq_num=seq_num, length=len(payload))
    # The checksum is computed while the checksum field is still 0
    pkt_header.checksum = compute_checksum(pkt_header / payload)
    return bytes(pkt_header / payload)


def parse_ack(pkt):
    """Return the seq_num of a valid ACK packet, or None if corrupted / not an ACK."""
    if len(pkt) < HEADER_SIZE:
        return None
    pkt_header = PacketHeader(pkt[:HEADER_SIZE])
    msg = pkt[HEADER_SIZE : HEADER_SIZE + pkt_header.length]

    # Verify checksum exactly like the receiver does
    pkt_checksum = pkt_header.checksum
    pkt_header.checksum = 0
    if pkt_checksum != compute_checksum(pkt_header / msg):
        return None
    if pkt_header.type != ACK:
        return None
    return pkt_header.seq_num


def wait_for_ack(s, deadline):
    """Wait until `deadline` for one valid ACK. Return its seq_num, or None on timeout."""
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        s.settimeout(remaining)
        try:
            pkt, _ = s.recvfrom(2048)
        except socket.timeout:
            return None
        ack_seq = parse_ack(pkt)
        if ack_seq is not None:
            return ack_seq
        # Corrupted packet: ignore it and keep waiting until the deadline


def sender(receiver_ip, receiver_port, window_size):
    """Open socket and send message from sys.stdin."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver_addr = (receiver_ip, receiver_port)

    # 1. Read the whole message (as bytes) and split it into chunks.
    #    DATA packet i (i = 1..n) carries chunks[i - 1].
    message = sys.stdin.buffer.read()
    chunks = [
        message[i : i + MAX_PAYLOAD_SIZE]
        for i in range(0, len(message), MAX_PAYLOAD_SIZE)
    ]
    last_data_seq = len(chunks)

    def send_data(seq_num):
        s.sendto(make_packet(DATA, seq_num, chunks[seq_num - 1]), receiver_addr)

    # 2. Connection setup: send START (seq_num 0), wait for its ACK (seq_num 1).
    #    The spec says a lost START ACK need not be handled; resending START
    #    every 500 ms only covers the case where START itself is lost.
    while True:
        s.sendto(make_packet(START, 0), receiver_addr)
        if wait_for_ack(s, time.time() + TIMEOUT) == 1:
            break

    # 3. Sliding window over DATA packets 1..last_data_seq.
    #    base     = oldest packet not yet acknowledged
    #    next_seq = next packet that has never been sent
    #    Packets in [base, next_seq) are in flight; there are never more than
    #    window_size of them.
    base = 1
    next_seq = 1
    while next_seq <= last_data_seq and next_seq < base + window_size:
        send_data(next_seq)
        next_seq += 1
    timer_deadline = time.time() + TIMEOUT

    while base <= last_data_seq:
        ack_seq = wait_for_ack(s, timer_deadline)

        if ack_seq is None:
            # Timeout: the window has not moved for 500 ms, so every packet
            # in it is considered unacknowledged -> retransmit all of them.
            for seq in range(base, next_seq):
                send_data(seq)
            timer_deadline = time.time() + TIMEOUT
            continue

        # Cumulative ACK: ack_seq is the next packet the receiver expects, so
        # every packet < ack_seq has arrived. Old or duplicate ACKs
        # (ack_seq <= base) are ignored so the window never moves backwards.
        if base < ack_seq <= next_seq:
            base = ack_seq
            # Window moved forward: send the new packets that now fit,
            # then reset the timer.
            while next_seq <= last_data_seq and next_seq < base + window_size:
                send_data(next_seq)
                next_seq += 1
            timer_deadline = time.time() + TIMEOUT

    # 4. Teardown: END takes the seq_num right after the last DATA packet.
    #    Exit when its ACK (seq_num end_seq + 1) arrives or after 500 ms.
    end_seq = last_data_seq + 1
    s.sendto(make_packet(END, end_seq), receiver_addr)
    end_deadline = time.time() + TIMEOUT
    while True:
        ack_seq = wait_for_ack(s, end_deadline)
        if ack_seq is None or ack_seq == end_seq + 1:
            break

    s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "receiver_ip", help="The IP address of the host that receiver is running on"
    )
    parser.add_argument(
        "receiver_port", type=int, help="The port number on which receiver is listening"
    )
    parser.add_argument(
        "window_size", type=int, help="Maximum number of outstanding packets"
    )
    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
