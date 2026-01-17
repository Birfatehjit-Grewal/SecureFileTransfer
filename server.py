import time
from socket import socket, AF_INET, SOCK_DGRAM,inet_aton, inet_ntoa
from Util.cryptography import get_session_keys, compute_auth, compute_hmac,compare_hmac,symmetric_decrypt
from Util.protocal import verify_checksum,create_TCP_header, create_encryption_packet, parse_TCP_header, parse_encryption_packet, save_file
from Util.protocal import TCP_flags
from Util.connection import Connection, Conn_state, get_local_ip
from Crypto.Random import get_random_bytes
import sys

SERVER_PORT = 8080


def start_server(server_port=8080):
    global SERVER_PORT
    SERVER_PORT = server_port
    connections = {}
    half_connections = {}
    is_running = True
    receive_socket = socket(AF_INET, SOCK_DGRAM)
    receive_socket.settimeout(10)
    receive_socket.bind(('', server_port))
    try:
        with open("key/psk.txt", "rb") as file:
            data = file.read()
            if len(data) == 16:
                psk = data
            else:
                print("psk.txt format is incorrect")
    except FileNotFoundError:
        print("psk.txt file not found")
        exit()

    while is_running:
        try:
            packet, address = receive_socket.recvfrom(4096)
            s_port, s_IP, d_port, d_IP, flags, seq_number, ack, checksum, data = parse_TCP_header(packet)
            is_correct = verify_checksum(s_port, s_IP, d_port, d_IP, flags, seq_number, ack, data, checksum)
            if is_correct:
                connection_id = (inet_ntoa(s_IP), s_port)
                if flags & TCP_flags.END:
                    print("END")
                    is_running = False
                    continue
                if flags & TCP_flags.SYN:
                    print("SYN")
                    nonce_c = data[:32]
                    auth_hmac = data[32:]
                    if auth_hmac == compute_auth(psk, nonce_c, b"Client"):
                        print("Match")
                        half_connections[connection_id] = (get_random_bytes(32),nonce_c)
                        handshake(connection_id, half_connections[connection_id], psk)
                else:
                    fin_flag, hmac, iv, encrypted_section = parse_encryption_packet(data)
                    if connection_id in list(half_connections.keys()):
                        if connection_id not in list(connections.keys()):
                            enc_key, hmac_key = get_session_keys(
                                psk,
                                half_connections[connection_id][1],
                                half_connections[connection_id][0]
                            )
                            if hmac == compute_hmac(hmac_key,iv,encrypted_section):
                                connections[connection_id] = Connection(connection_id, SERVER_PORT)
                                connections[connection_id].state = Conn_state.ESTABLISHED
                                connections[connection_id].next_expected_seq = 1
                                connections[connection_id].next_seq = 1
                                connections[connection_id].nonce_s = half_connections[connection_id][0]
                                connections[connection_id].nonce_c = half_connections[connection_id][1]
                                connections[connection_id].set_keys(enc_key, hmac_key)
                                del half_connections[connection_id]
                    if connection_id in list(connections.keys()):
                        user_conn = connections[connection_id]
                        user_conn.last_update = time.time()
                        if hmac == compute_hmac(user_conn.hmac_key, iv, encrypted_section):
                            if flags & TCP_flags.FIN:
                                user_conn.state = Conn_state.FIN_RECEIVED
                            receive(seq_number, encrypted_section, user_conn,iv)
                            if user_conn.state == Conn_state.CLOSED:
                                save_file(user_conn.file)
                                del connections[connection_id]
        except TimeoutError:
            continue


def receive(seq,encrypted_file_section,conn,iv):
    if seq < conn.next_expected_seq:
        send_ack(conn)
    if seq in list(conn.receive_buffer):
        send_ack(conn)
    if not seq == conn.next_expected_seq:
        if seq < conn.window_size + conn.next_expected_seq:
            conn.receive_buffer[seq] = (encrypted_file_section,iv)
        send_ack(conn)
    else:
        decrypted_file = symmetric_decrypt(encrypted_file_section,iv,conn.enc_key)
        size = len(decrypted_file)
        conn.next_expected_seq += size
        conn.file += decrypted_file
        while conn.next_expected_seq in list(conn.receive_buffer):
            file, iv = conn.receive_buffer[conn.next_expected_seq]
            decrypted_file = symmetric_decrypt(file, iv, conn.enc_key)
            size = len(decrypted_file)
            del conn.receive_buffer[conn.next_expected_seq]
            conn.next_expected_seq += size
            conn.file += decrypted_file
        if conn.state == Conn_state.FIN_RECEIVED and len(conn.receive_buffer) == 0:
            conn.state = Conn_state.CLOSED
        send_ack(conn)


def send_ack(conn):
    print(f"ACK {conn.next_expected_seq}")
    if conn.state == Conn_state.CLOSED:
        send_packet = b""
        flags = TCP_flags.ACK | TCP_flags.FIN
        header = create_TCP_header(conn.port, conn.client_ip, conn.address[1], conn.address[0], flags, conn.next_seq,
                                   conn.next_expected_seq, send_packet)
        conn.send_socket.sendto(header, conn.address)
        conn.next_seq += 1
        conn.state = Conn_state.CLOSED
    else:
        send_packet = b""
        flags = TCP_flags.ACK
        header = create_TCP_header(conn.port, conn.client_ip, conn.address[1], conn.address[0], flags, conn.next_seq,
                                   conn.next_expected_seq, send_packet)
        conn.send_socket.sendto(header, conn.address)


def handshake(conn_id, nonce, psk):
    global SERVER_PORT
    send_socket = socket(AF_INET, SOCK_DGRAM)
    send_packet = nonce[0] + compute_auth(psk, nonce[1], nonce[0])
    flags = TCP_flags.SYN | TCP_flags.ACK
    message = create_TCP_header(SERVER_PORT, get_local_ip(), conn_id[1], conn_id[0], flags,
                                0, 1, send_packet)
    send_socket.sendto(message, conn_id)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        arg1 = int(sys.argv[1])
        start_server(arg1)
    elif len(sys.argv) == 1:
        start_server()
    else:
        print("The correct usage for this is: python server.py [Optional SERVER_PORT]")
