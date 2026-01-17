import os
import tempfile
from Util import protocal


# ----------------------------
# TCP HEADER + CHECKSUM TESTS
# ----------------------------

def test_create_and_parse_tcp_header():
    data = b"hello world"

    packet_bytes = protocal.create_TCP_header(
        s_port=1234,
        s_IP="127.0.0.1",
        d_port=4321,
        d_IP="127.0.0.1",
        flags=protocal.TCP_flags.SYN | protocal.TCP_flags.ACK,
        seq_number=10,
        ack=5,
        data=data
    )

    s_port, s_ip, d_port, d_ip, flags, seq, ack, checksum, payload = (
        protocal.parse_TCP_header(packet_bytes)
    )

    assert s_port == 1234
    assert d_port == 4321
    assert flags & protocal.TCP_flags.SYN
    assert flags & protocal.TCP_flags.ACK
    assert seq == 10
    assert ack == 5
    assert payload == data


def test_checksum_verification():
    data = b"testing checksum"

    pkt = protocal.create_TCP_header(
        1111, "127.0.0.1",
        2222, "127.0.0.1",
        protocal.TCP_flags.ACK,
        1, 0, data
    )

    s_port, s_ip, d_port, d_ip, flags, seq, ack, checksum, payload = (
        protocal.parse_TCP_header(pkt)
    )

    assert protocal.verify_checksum(
        s_port, s_ip, d_port, d_ip,
        flags, seq, ack, payload, checksum
    )


def test_checksum_detects_corruption():
    data = b"valid data"

    pkt = protocal.create_TCP_header(
        1111, "127.0.0.1",
        2222, "127.0.0.1",
        protocal.TCP_flags.ACK,
        1, 0, data
    )

    corrupted = pkt[:-1] + b"\x00"  # flip last byte

    s_port, s_ip, d_port, d_ip, flags, seq, ack, checksum, payload = (
        protocal.parse_TCP_header(corrupted)
    )

    assert not protocal.verify_checksum(
        s_port, s_ip, d_port, d_ip,
        flags, seq, ack, payload, checksum
    )


# ----------------------------
# ENCRYPTION PACKET TESTS
# ----------------------------

def test_encryption_packet_roundtrip():
    encrypted_data = b"ciphertext"
    iv = b"A" * 16
    hmac = b"B" * 32

    payload = protocal.create_encryption_packet(
        encrypted_data,
        fin_flag=True,
        iv=iv,
        hmac=hmac
    )

    fin, parsed_hmac, parsed_iv, parsed_data = (
        protocal.parse_encryption_packet(payload)
    )

    assert fin is True
    assert parsed_hmac == hmac
    assert parsed_iv == iv
    assert parsed_data == encrypted_data


def test_encryption_packet_fin_false():
    payload = protocal.create_encryption_packet(
        b"x", False, b"A"*16, b"B"*32
    )

    fin, _, _, _ = protocal.parse_encryption_packet(payload)
    assert fin is False


# ----------------------------
# FILE NAME PACKING TESTS
# ----------------------------

def test_pack_unpack_file_name():
    name = "test.txt"
    data = b"file contents"

    payload = protocal.pack_file_name(name, data)
    unpacked_name, unpacked_data = protocal.unpack_file_name(payload)

    assert unpacked_name == name
    assert unpacked_data == data


def test_get_file_name():
    path = "/home/user/docs/report.pdf"
    assert protocal.get_file_name(path) == "report.pdf"


# ----------------------------
# FILE SAVING TEST
# ----------------------------

def test_save_file(tmp_path, monkeypatch):
    # Redirect BASE_DIR to temp directory
    monkeypatch.setattr(protocal, "BASE_DIR", tmp_path)

    name = "saved.txt"
    contents = b"saved file contents"
    payload = protocal.pack_file_name(name, contents)

    protocal.save_file(payload)

    saved_path = tmp_path / name
    assert saved_path.exists()

    with open(saved_path, "rb") as f:
        assert f.read() == contents
