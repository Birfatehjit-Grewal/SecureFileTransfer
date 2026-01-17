from socket import socket, AF_INET, SOCK_DGRAM, inet_ntoa, inet_aton
import struct
import os

BASE_DIR = "backup_files"


class TCP_flags:
    """
    Class containing the bit locations for each TCP flag
    """
    SYN = 0x02
    FIN = 0x01
    ACK = 0x08
    END = 0x04

def create_TCP_header(s_port, s_IP, d_port, d_IP, flags, seq_number, ack, data):
    """
    Constructs the packet using the custom TCP header format

    The TCP header format is:
    First 2 byte: Source Port
    4 bytes: Source IP
    2 bytes: Destination Port
    4 bytes: Destination IP
    2 bytes: TCP flags
    4 bytes: Sequence Number
    4 bytes: ACK Number
    2 bytes: Checksum
    Remaining bytes: The contents of the encryption header and encrypted file segment

    The header uses network byte order

    Parameters:
        s_port (int): source port
        s_IP (bytes): source IP
        d_port (int): destination port
        d_IP (bytes): destination IP
        flags (int): TCP flags
        seq_number (int): Sequence Number
        ack (int): ACK Number
        data (bytes): Encryption header + encrypted file segment

    Returns:
        result (bytes): The completed packet that is ready to send (TCP header + data)
    """
    sIP = inet_aton(s_IP)
    dIP = inet_aton(d_IP)
    header = struct.pack(
        "!H4sH4sHIIH",
        s_port,
        sIP,
        d_port,
        dIP,
        flags,
        seq_number,
        ack,
        0
    )
    full_packet = header + data
    checksum = 0
    for i in range(0, len(full_packet), 2):
        word = full_packet[i:i + 2]
        if len(word) == 2:
            checksum += (word[0] << 8) + word[1]
        else:
            checksum += (word[0] << 8)

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    header_complete = struct.pack(
        "!H4sH4sHIIH",
        s_port,
        sIP,
        d_port,
        dIP,
        flags,
        seq_number,
        ack,
        checksum
    )
    send_packet = header_complete+data
    return send_packet

def verify_checksum(s_port,s_IP,d_port,d_IP,flags, seq_number,ack,data, checksum_received):
    """
    verifies the packet using the checksum received and calculating the checksum itself in case of bit flips

    The TCP header format is:
    First 2 byte: Source Port
    4 bytes: Source IP
    2 bytes: Destination Port
    4 bytes: Destination IP
    2 bytes: TCP flags
    4 bytes: Sequence Number
    4 bytes: ACK Number
    2 bytes: Checksum
    Remaining bytes: The contents of the encryption header and encrypted file segment

    The header uses network byte order

    Parameters:
        s_port (int): source port
        s_IP (bytes): source IP
        d_port (int): destination port
        d_IP (bytes): destination IP
        flags (int): TCP flags
        seq_number (int): Sequence Number
        ack (int): ACK Number
        data (bytes): Encryption header + encrypted file segment
        checksum_received (int): checksum

    Returns:
        result (bool): true if the calculated checksum matches the received checksum
    """
    sIP = s_IP
    dIP = d_IP
    header = struct.pack(
        "!H4sH4sHIIH",
        s_port,
        sIP,
        d_port,
        dIP,
        flags,
        seq_number,
        ack,
        0
    )
    full_packet = header + data
    checksum = 0
    for i in range(0, len(full_packet), 2):
        word = full_packet[i:i + 2]
        if len(word) == 2:
            checksum += (word[0] << 8) + word[1]
        else:
            checksum += (word[0] << 8)

    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum == checksum_received


def parse_TCP_header(packetMessage):
    """
    Parses the packet according to the custom TCP header format

    The TCP header format is:
    First 2 byte: Source Port
    4 bytes: Source IP
    2 bytes: Destination Port
    4 bytes: Destination IP
    2 bytes: TCP flags
    4 bytes: Sequence Number
    4 bytes: ACK Number
    2 bytes: Checksum
    Remaining bytes: The contents of the encryption header and encrypted file segment

    The header uses network byte order

    Parameters:
        packetMessage (bytes): The received packet

    Returns:
        s_port (int): source port
        s_IP (bytes): source IP
        d_port (int): destination port
        d_IP (bytes): destination IP
        flags (int): TCP flags
        seq_number (int): Sequence Number
        ack (int): ACK Number
        checksum (int): checksum
        data (bytes): Encryption header + encrypted file segment
    """
    s_port,s_IP,d_port,d_IP,flags, seq_number,ack,checksum = struct.unpack(
        '!H4sH4sHIIH', packetMessage[:24])
    data = packetMessage[24:]
    return s_port,s_IP,d_port,d_IP,flags, seq_number,ack,checksum, data


def create_encryption_packet(data, fin_flag, iv, hmac):
    """
    Constructs the packet according to the encryption header format

    The encryption header format is:
    First byte: Fin flag representing if this is the last packet
    32 bytes: The HMAC used to verify the integrity of the data
    16 bytes: The IV used for encryption in the AES-CBC (128-bit key version)
    Remaining bytes: The contents of the file segment being transferred

    Parameters:
        data (bytes): The encrypted file segment
        fin_flag (bool): A flag to signify if this is the last file segment
        IV (bytes): 16 bytes that were used to encrypt the file segment
        HMAC (bytes): 32 bytes used to ensure data integrity

    Returns:
        encryption_payload (bytes): Encryption Header prepended to the encrypted file segment
    """
    flag = b"\x00" if fin_flag else b"\x01"
    encryption_payload = flag + hmac + iv + data
    return encryption_payload


def parse_encryption_packet(data):
    """
    Parses the packet according to the encryption header format

    The encryption header format is:
        First byte: Fin flag representing if this is the last packet
        32 bytes: The HMAC used to verify the integrity of the data
        16 bytes: The IV used for encryption in the AES-CBC (128-bit key version)
        Remaining bytes: The contents of the file segment being transferred

    Parameters:
        data (bytes): the encryption header along with the file segment

    Returns:
        tuple[bool, bytes, bytes, bytes]:
            fin_flag (bool): A flag to signify if this is the last file segment
            HMAC (bytes): 32 bytes used to ensure data integrity
            IV (bytes): 16 bytes that were used to encrypt the file segment
            file_contents (bytes): contents of the encrypted file segment
    """
    isFin = data[:1]
    fin_flag = True if isFin == b"\x00" else False
    hmac = data[1:33]
    iv = data[33:49]
    encrypted_section = data[49:]

    return fin_flag, hmac, iv, encrypted_section


def pack_file_name(file_name, file):
    """
    Packs the file name and file contents into a payload along with the length of the file name.

    The payload format is:
        First 4 bytes: unsigned int indicating file name length
        Next N bytes: file name (N = the value from the first 4 bytes)
        Remaining bytes: file contents

    Parameters:
        file_name (string): String containing the name of the file.
        file (bytes): bytes containing the content of the file.

    Returns:
        payload (bytes): The packed payload with name length, file name and file contents.
    """
    length = len(file_name)
    length_bytes = struct.pack(
        "I",
        length
    )
    return length_bytes + file_name.encode() + file


def unpack_file_name(data):
    """
    Extracts the file name and file contents from a packed payload.

    The payload format is:
        First 4 bytes: unsigned int indicating file name length
        Next N bytes: file name
        Remaining bytes: file contents

    Parameters:
        data (bytes): Payload containing file name length, file name, and file bytes.

    Returns:
        tuple[str, bytes]: The decoded file name and the raw file bytes.
    """
    length_bytes = data[:4]
    length = struct.unpack(
        "I",
        length_bytes
    )
    end = length[0] + 4
    file_name = data[4:end]
    file = data[end:]

    return file_name.decode(), file


def get_file_name(file_path):
    """
    parses the file path to obtain the file name

    Parameters:
        file_path (string): The path to the file being transferred

    Returns:
        file_name (string): The name of the file
    """
    return os.path.basename(file_path)


def save_file(payload):
    """
    Saves the file with the correct file name

    Parameters:
        payload (bytes): The packed payload with name length, file name and file contents.

    Returns:
        NULL: Has no return value

    Output:
        A file in the tmp directory
    """
    file_name, file_data = unpack_file_name(payload)
    os.makedirs(BASE_DIR, exist_ok=True)
    safe_name = os.path.basename(file_name)
    path = os.path.join(BASE_DIR, safe_name)
    try:
        with open(path, "wb") as f:
            f.write(file_data)
        print(f"Saved file to {path}")
    except OSError as e:
        print(f"Save failed: {e}")