import struct
import socket
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Kích thước cố định của mã băm SHA-256
SHA256_DIGEST_SIZE = 32

def sha256_digest(data: bytes) -> bytes:
    """Trả về mã băm SHA-256 (32 bytes) của dữ liệu."""
    h = SHA256.new()
    h.update(data)
    return h.digest()

def generate_des_key_iv():
    """Tạo khóa DES (8 bytes) và IV (8 bytes)."""
    return get_random_bytes(8), get_random_bytes(8)

def encrypt_des_cbc(plaintext: bytes, key: bytes, iv: bytes):
    """Mã hóa DES-CBC và trả về iv ghép chung với ciphertext ở đầu."""
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long.")
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded_data)
    return key, iv, iv + ciphertext

def decrypt_des_cbc(key: bytes, iv_plus_ciphertext: bytes) -> bytes:
    """Giải mã DES-CBC với 8 byte đầu là IV."""
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long.")
    if len(iv_plus_ciphertext) < 8:
        raise ValueError("Ciphertext too short to contain IV.")
    
    iv = iv_plus_ciphertext[:8]
    actual_ciphertext = iv_plus_ciphertext[8:]
    
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(actual_ciphertext), 8)

def encrypt_des_key_rsa(des_key: bytes, rsa_public_key) -> bytes:
    """Mã hóa khóa mã đối xứng DES bằng khóa công khai RSA."""
    cipher = PKCS1_OAEP.new(rsa_public_key)
    return cipher.encrypt(des_key)

def decrypt_des_key_rsa(encrypted_key: bytes, rsa_private_key) -> bytes:
    """Giải mã khóa DES bằng khóa bí mật RSA."""
    cipher = PKCS1_OAEP.new(rsa_private_key)
    return cipher.decrypt(encrypted_key)

def build_secure_packet(encrypted_key: bytes, ciphertext: bytes, digest: bytes) -> bytes:
    """Đóng gói gói tin theo đúng cấu trúc khung của Lab 8."""
    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"Digest size must be exactly {SHA256_DIGEST_SIZE} bytes.")
        
    key_len = len(encrypted_key)
    cipher_len = len(ciphertext)
    
    # Định dạng gói tin dùng !I (4 bytes, Big-Endian unsigned int)
    return struct.pack("!I", key_len) + encrypted_key + struct.pack("!I", cipher_len) + ciphertext + digest

def parse_secure_packet(packet: bytes):
    """Bóc tách gói tin và kiểm tra nghiêm ngặt dữ liệu thừa/thiếu."""
    if len(packet) < 8:
        raise ValueError("Packet is too short to contain basic headers.")
        
    # Đọc độ dài encrypted_key
    key_len = struct.unpack("!I", packet[:4])[0]
    offset = 4 + key_len
    
    if len(packet) < offset + 4:
        raise ValueError("Packet is truncated inside key data or cipher header.")
        
    # Đọc độ dài ciphertext
    cipher_len = struct.unpack("!I", packet[offset : offset + 4])[0]
    
    cipher_start = offset + 4
    cipher_end = cipher_start + cipher_len
    digest_end = cipher_end + SHA256_DIGEST_SIZE
    
    # Chặn đứng trường hợp packet bị chèn dữ liệu thừa (pass test_packet_rejects_extra_bytes)
    if len(packet) != digest_end:
        raise ValueError("Packet layout error: length mismatch or extra bytes detected.")
        
    parsed_key = packet[4:offset]
    parsed_ciphertext = packet[cipher_start:cipher_end]
    parsed_digest = packet[cipher_end:digest_end]
    
    return parsed_key, parsed_ciphertext, parsed_digest

def _recv_all(sock: socket.socket, length: int) -> bytes:
    """Hàm bổ trợ gom đủ số lượng byte từ socket để tránh phân mảnh dữ liệu."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket unexpectedly closed before finishing data transfer.")
        data += chunk
    return data

def recv_secure_packet(sock: socket.socket) -> bytes:
    """Đọc dữ liệu từ socket theo luồng tuần tự dựa trên header độ dài."""
    # Nhận độ dài key và dữ liệu key
    key_len_bytes = _recv_all(sock, 4)
    key_len = struct.unpack("!I", key_len_bytes)[0]
    encrypted_key = _recv_all(sock, key_len)
    
    # Nhận độ dài cipher và dữ liệu cipher
    cipher_len_bytes = _recv_all(sock, 4)
    cipher_len = struct.unpack("!I", cipher_len_bytes)[0]
    ciphertext = _recv_all(sock, cipher_len)
    
    # Nhận phần digest cuối cùng
    digest = _recv_all(sock, SHA256_DIGEST_SIZE)
    
    return key_len_bytes + encrypted_key + cipher_len_bytes + ciphertext + digest
