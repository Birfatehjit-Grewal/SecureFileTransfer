# One way communication
import threading
from Util.fileloader import file_load
from Util.connection import Connection, Conn_state
from Util.cryptography import get_session_keys, compute_auth, symmetric_encrypy, compute_hmac, compare_hmac
from Util.protocal import create_TCP_header,create_encryption_packet, parse_TCP_header,verify_checksum, TCP_flags
import time
from socket import socket, AF_INET,SOCK_DGRAM
import random
import sys


def start_client(server_addr,file_path, client_port):
    """
    Constructs the packet according to the encryption header format

    Parameters:
        server_addr (tuple[string,int]): The servers address
        file_path (string): the path to the file being sent
        client_port (int): the port the client is listening on

    result:
        sends the file to the server
    """
    file = file_load(file_path)
    conn = Connection(server_addr,client_port)
    receive_socket = socket(AF_INET, SOCK_DGRAM)
    receive_socket.settimeout(2)
    receive_socket.bind(('', conn.port))
    handshake(conn, receive_socket)
    sender_thread = threading.Thread(target=send_handler,args=(file,conn,))
    retransmit_thread = threading.Thread(target=retransmit_handler, args=(conn,file,))
    receiver_thread = threading.Thread(target=receive_handler,args=(conn,receive_socket,))
    sender_thread.start()
    receiver_thread.start()
    retransmit_thread.start()
    sender_thread.join()
    receiver_thread.join()
    retransmit_thread.join()


def handshake(conn, receive_socket):
    """
        handshake for the connection plus key exchange

        Parameters:
            conn (Connection): object to manage connection
            receive_socket (socket): the socket that the client binds to receive the acks

        result:
            completes the handshake or exits after 5 tries
    """
    i = 0
    while i < 5:
        send_packet = conn.nonce_c + compute_auth(conn.psk, conn.nonce_c, b"Client")
        flags = TCP_flags.SYN
        message = create_TCP_header(conn.port, conn.client_ip, conn.address[1], conn.address[0], flags,
                                    conn.next_seq, conn.next_expected_seq, send_packet)
        conn.send_socket.sendto(message, conn.address)
        conn.state = Conn_state.SYN_SENT
        conn.next_seq = 1
        try:
            packet, addr = receive_socket.recvfrom(4096)
            s_port, s_ip, d_port, d_ip, flags, seq, ack, checksum, data = parse_TCP_header(packet)
            if not verify_checksum(s_port, s_ip, d_port, d_ip, flags, seq, ack, data, checksum):
                continue
            if flags & TCP_flags.ACK:
                conn.handle_ack(ack)
            if flags & TCP_flags.SYN:
                conn.nonce_s = data[:32]
                auth_hmac = data[32:]
                computed_hmac = compute_auth(conn.psk,conn.nonce_c,conn.nonce_s)
                if auth_hmac == computed_hmac:
                    conn.next_expected_seq = conn.next_expected_seq + 1
                    conn.state = Conn_state.ESTABLISHED
                    enc_key, hmac_key = get_session_keys(conn.psk, conn.nonce_c, conn.nonce_s)
                    conn.set_keys(enc_key, hmac_key)
                else:
                    print("Server Authentication Failed HMAC did not match")
                    print("Retrying Handshake")
                    i += 1
                    continue
                return
        except TimeoutError:
            i += 1
            continue
    print("Handshake Failed")
    exit()


def send_handler(file, conn):
    """
    thread function to send the file

    Parameters:
        file (file_load): object with the file loaded
        conn (Connection): object to manage connection
    result:
        sends the file to the server
    """
    file_seg_size = 4000
    while conn.next_seq - 1 < file.size:
        section_start = conn.next_seq - 1
        if section_start < conn.window_size + conn.window_base:
            section = file.get_section(section_start,file_seg_size)
            encrypted_section, iv = symmetric_encrypy(section, conn.enc_key)
            end = section_start + len(section)
            is_fin = True if end == file.size else False
            hmac = compute_hmac(conn.hmac_key,iv, encrypted_section)
            send_packet = create_encryption_packet(encrypted_section,
                                                   is_fin, iv, hmac)
            flags = TCP_flags.ACK if not is_fin else TCP_flags.ACK | TCP_flags.FIN
            message = create_TCP_header(conn.port, conn.client_ip, conn.address[1], conn.address[0], flags,
                                        conn.next_seq, conn.next_expected_seq, send_packet)
            if random.randint(1, 1000) < 988:
                conn.send_socket.sendto(message, conn.address)
            conn.next_seq = end + 1


def receive_handler(conn, receive_socket):
    """
    thread function to receive the acks

    Parameters:
        conn (Connection): object to manage connection
        receive_socket (socket): the socket that the client binds to receive the acks
    result:
        receive acks and updates the window base using handle ack
    """
    while conn.state == Conn_state.ESTABLISHED:
        try:
            packet, addr = receive_socket.recvfrom(4096)
            s_port, s_ip, d_port, d_ip, flags, seq, ack, checksum, data = parse_TCP_header(packet)
            if not verify_checksum(s_port, s_ip, d_port, d_ip, flags, seq, ack, data, checksum):
                continue

            # ACK only
            if flags & TCP_flags.ACK and len(data) == 0:
                print(f"ACK {ack}")
                conn.handle_ack(ack)

            # FIN from server
            if flags & TCP_flags.FIN:
                print("FIN Received")
                conn.state = Conn_state.CLOSED

        except TimeoutError:
            continue


def retransmit_handler(conn,file):
    """
    thread function to retransmit lost packets

    Parameters:
        conn (Connection): object to manage connection
        file (file_load): object with the file loaded
    result:
        retransmits lost packets
    """
    file_seg_size = 4000
    print(f"file size = {file.size}")
    while conn.state == Conn_state.ESTABLISHED:
        if (conn.duplicate_ACK > 2 or time.time() - conn.last_update > 3) \
                and conn.window_base < file.size:
            print(f"Retransmit {conn.window_base}")
            start = conn.window_base - 1
            section = file.get_section(start, file_seg_size)
            encrypted_section, iv = symmetric_encrypy(section, conn.enc_key)
            end = start + len(section)
            is_fin = True if end == file.size else False
            hmac = compute_hmac(conn.hmac_key, iv, encrypted_section)
            send_packet = create_encryption_packet(encrypted_section,
                                                   is_fin,iv,hmac)
            flags = TCP_flags.ACK if not is_fin else TCP_flags.ACK | TCP_flags.FIN
            message = create_TCP_header(conn.port, conn.client_ip, conn.address[1], conn.address[0], flags,
                                        conn.window_base, conn.next_expected_seq, send_packet)
            conn.send_socket.sendto(message, conn.address)
            conn.last_update = time.time()
            conn.duplicate_ACK = 0
        else:
            time.sleep(0.5)

def main(filename, server_address,client_port=8000):
    start_client(server_address, filename, client_port)


if __name__ == "__main__":
    if len(sys.argv) == 4:
        arg1 = sys.argv[1]
        arg2 = int(sys.argv[2])
        arg3 = sys.argv[3]
        main(arg3, (arg1, arg2))
    elif len(sys.argv) == 5:
        arg1 = sys.argv[1]
        arg2 = int(sys.argv[2])
        arg3 = int(sys.argv[3])
        arg4 = sys.argv[4]
        main(arg4, (arg1, arg2),arg3)
    else:
        print("The correct usage for this is: python client.py [SERVER_IP] [SERVER_PORT] [Optional Client Port] [File "
              "path]")