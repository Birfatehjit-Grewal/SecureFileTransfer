import time
from socket import socket, AF_INET,SOCK_DGRAM, gethostbyname, gethostname
from Crypto.Random import get_random_bytes

class Conn_state:
    """
    Class for connection  states
    """
    CLOSED = 0
    SYN_SENT = 1
    SYN_RECEIVED = 2
    ESTABLISHED = 3
    FIN_RECEIVED = 4


def get_local_ip():
    """
    Returns the local ip address

    Returns:
        ip_address (string): the local ip address (ex: 192.168.1.45)
    """
    hostname = gethostname()
    ip_address = gethostbyname(hostname)
    return ip_address
class Connection:
    """
        Class for connection management

        holds the objects needed for TCP like the buffer and window
        while also tracking the seq and ack numbers
        The session keys are also stored in the connection object
    """
    def __init__(self,address,client_port):
        self.receive_buffer = {}
        self.next_expected_seq = 0

        self.next_seq = 0
        self.last_update = time.time()
        self.file = b""
        self.address = address
        self.port = client_port
        self.client_ip = get_local_ip()
        self.window_base = 0
        self.window_size = 32768

        self.send_socket = socket(AF_INET, SOCK_DGRAM)

        self.state = Conn_state.CLOSED
        self.duplicate_ACK = 0

        self.enc_key = b""
        self.hmac_key = b""
        self.nonce_c = get_random_bytes(32)
        self.nonce_s = get_random_bytes(32)
        try:
            with open("key/psk.txt","rb") as file:
                data = file.read()
                if len(data) == 16:
                    self.psk = data
                else:
                    print("psk.txt format is incorrect")
        except FileNotFoundError:
            print("psk.txt file not found")

    def handle_ack(self, ack):
        """
        updated the connection object after an ack is received

        Parameters:
            ack (int): the ack number received

        result:
            updated window base or duplicate ack
            """
        if ack == self.window_base:
            self.duplicate_ACK += 1
        elif ack > self.window_base:
            self.window_base = ack
            self.duplicate_ACK = 0
            self.last_update = time.time()


    def set_keys(self,enc_key, hmac_key):
        """
        updated the session keys

        Parameters:
            enc_key (bytes): 16 bytes
            hmac_key (bytes): 32 bytes
        result:
            updated session keys
        """
        self.enc_key = enc_key
        self.hmac_key = hmac_key

