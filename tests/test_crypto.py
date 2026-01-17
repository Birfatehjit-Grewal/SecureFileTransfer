import Util.cryptography as crypto
from Crypto.Random import get_random_bytes


def test_encrypt_decrypt():
    plain_data = b"This is a test"
    key = get_random_bytes(16)
    cipher_text, iv = crypto.symmetric_encrypy(plain_data, key)
    plain_text = crypto.symmetric_decrypt(cipher_text,iv,key)
    assert plain_data == plain_text


def test_key_length():
    psk = get_random_bytes(32)
    nonce_c = get_random_bytes(32)
    nonce_s = get_random_bytes(32)
    enc_key, hmac_key = crypto.get_session_keys(psk,nonce_c,nonce_s)
    assert len(enc_key) == 16
    assert len(hmac_key) == 32


def test_different_hmac():
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    ct = b"This is a test"
    hmac = crypto.compute_hmac(key,iv,ct)
    assert not crypto.compare_hmac(hmac,key,iv,b"This is a different ct")


def test_compute_auth():
    psk = get_random_bytes(32)
    nonce_c = get_random_bytes(32)
    nonce_s = get_random_bytes(32)
    auth = crypto.compute_auth(psk,nonce_c,nonce_s)
    assert len(auth) == 32
