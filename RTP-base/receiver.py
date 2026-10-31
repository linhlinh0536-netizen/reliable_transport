import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum

# Packet types defined by the RTP specification
START, END, DATA, ACK = 0, 1, 2, 3

HEADER_SIZE = 16  # 4 IntFields x 4 bytes


def send_ack(s, address, seq_num):
    """Send an ACK packet (no payload) carrying seq_num back to the sender."""
    pkt_header = PacketHeader(type=ACK, seq_num=seq_num, length=0)
    pkt_header.checksum = compute_checksum(pkt_header)
    s.sendto(bytes(pkt_header), address)


def deliver(data):
    """Write in-order data to stdout immediately."""
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()


def receiver(receiver_ip, receiver_port, window_size):
    """Listen on socket and print received message to sys.stdout."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    in_connection = False  # True between START and END
    sender_address = None  # the only sender served in the current connection
    expected_seq = 1  # N: next in-order seq_num we are waiting for
    buffer = {}  # out-of-order packets: seq_num -> payload

    while True:
        # Receive packet; address includes both IP and port
        pkt, address = s.recvfrom(2048)
        if len(pkt) < HEADER_SIZE:
            continue

        # Extract header and payload
        pkt_header = PacketHeader(pkt[:HEADER_SIZE])
        msg = pkt[HEADER_SIZE : HEADER_SIZE + pkt_header.length]

        # Verify checksum; corrupted packets are dropped without an ACK
        pkt_checksum = pkt_header.checksum
        pkt_header.checksum = 0
        computed_checksum = compute_checksum(pkt_header / msg)
        if pkt_checksum != computed_checksum:
            continue

        pkt_type = pkt_header.type
        seq_num = pkt_header.seq_num

        if pkt_type == START:
            # Only one sender at a time: ignore START in the middle of a connection
            if in_connection:
                continue
            in_connection = True
            sender_address = address
            expected_seq = 1
            buffer = {}
            send_ack(s, address, 1)  # ACK of START has seq_num 1
            continue

        # Everything else needs an active connection with this sender
        if not in_connection or address != sender_address:
            continue

        if pkt_type == DATA:
            # Keep a window of window_size: drop packets too far ahead (no ACK)
            if seq_num >= expected_seq + window_size:
                continue

            if seq_num == expected_seq:
                # In-order packet: deliver it, then every buffered packet that
                # now continues the in-order sequence (M = highest in-order seq).
                deliver(msg)
                expected_seq += 1
                while expected_seq in buffer:
                    deliver(buffer.pop(expected_seq))
                    expected_seq += 1
            elif seq_num > expected_seq:
                # Out-of-order packet inside the window: buffer it once
                if seq_num not in buffer:
                    buffer[seq_num] = msg
            # seq_num < expected_seq: duplicate of delivered data, nothing to store

            # Cumulative ACK: always the next seq_num we expect (M + 1 or N)
            send_ack(s, address, expected_seq)

        elif pkt_type == END:
            if seq_num == expected_seq:
                # All data has been delivered: ACK the END and exit
                send_ack(s, address, seq_num + 1)
                break
            # END arrived before some data: keep acknowledging cumulatively
            send_ack(s, address, expected_seq)

        # ACK packets (or unknown types) are not expected at the receiver: ignore

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

    receiver(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
