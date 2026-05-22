import struct
import socket
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

SHA256_DIGEST_SIZE = 32

def sha256_digest(data: bytes) -> bytes:
    h = SHA256.new()
    h.update(data)
    return h.digest()

def generate_des_key_iv():
    return get_random_bytes(8), get_random_bytes(8)

def encrypt_des_cbc(plaintext: bytes, key: bytes, iv: bytes):
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long.")
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded_data)
    return key, iv, iv + ciphertext

def decrypt_des_cbc(key: bytes, iv_plus_ciphertext: bytes) -> bytes:
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long.")
    if len(iv_plus_ciphertext) < 8:
        raise ValueError("Ciphertext too short to contain IV.")
    iv = iv_plus_ciphertext[:8]
    actual_ciphertext = iv_plus_ciphertext[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(actual_ciphertext), 8)

def encrypt_des_key_rsa(des_key: bytes, rsa_public_key) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_public_key)
    return cipher.encrypt(des_key)

def decrypt_des_key_rsa(encrypted_key: bytes, rsa_private_key) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_private_key)
    return cipher.decrypt(encrypted_key)

def build_secure_packet(encrypted_key: bytes, ciphertext: bytes, digest: bytes) -> bytes:
    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"Digest size must be exactly {SHA256_DIGEST_SIZE} bytes.")
    key_len = len(encrypted_key)
    cipher_len = len(ciphertext)
    return struct.pack("!I", key_len) + encrypted_key + struct.pack("!I", cipher_len) + ciphertext + digest

def parse_secure_packet(packet: bytes):
    if len(packet) < 8:
        raise ValueError("Packet is too short.")
    key_len = struct.unpack("!I", packet[:4])[0]
    offset = 4 + key_len
    if len(packet) < offset + 4:
        raise ValueError("Packet truncated.")
    cipher_len = struct.unpack("!I", packet[offset : offset + 4])[0]
    cipher_start = offset + 4
    cipher_end = cipher_start + cipher_len
    digest_end = cipher_end + SHA256_DIGEST_SIZE
    if len(packet) != digest_end:
        raise ValueError("Packet length mismatch or extra bytes.")
    return packet[4:offset], packet[cipher_start:cipher_end], packet[cipher_end:digest_end]

def _recv_all(sock: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed.")
        data += chunk
    return data

def recv_secure_packet(sock: socket.socket) -> bytes:
    key_len_bytes = _recv_all(sock, 4)
    key_len = struct.unpack("!I", key_len_bytes)[0]
    encrypted_key = _recv_all(sock, key_len)
    cipher_len_bytes = _recv_all(sock, 4)
    cipher_len = struct.unpack("!I", cipher_len_bytes)[0]
    ciphertext = _recv_all(sock, cipher_len)
    digest = _recv_all(sock, SHA256_DIGEST_SIZE)
    return key_len_bytes + encrypted_key + cipher_len_bytes + ciphertext + digest
