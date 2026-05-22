import struct
from Crypto.Hash import SHA256

# Định nghĩa hằng số độ dài như test case yêu cầu
SHA256_DIGEST_SIZE = 32

def sha256_digest(data: bytes) -> bytes:
    """Trả về mã băm SHA-256 (32 bytes) của dữ liệu đầu vào."""
    h = SHA256.new()
    h.update(data)
    return h.digest()

def build_secure_packet(encrypted_key: bytes, ciphertext: bytes, digest: bytes) -> bytes:
    """
    Đóng gói các thành phần theo cấu trúc định sẵn:
    - 4 bytes: Độ dài encrypted_key (Big-endian)
    - X bytes: Dữ liệu encrypted_key
    - 4 bytes: Độ dài ciphertext (Big-endian)
    - Y bytes: Dữ liệu ciphertext
    - 32 bytes: Dữ liệu mã băm digest
    """
    # Kiểm tra kích thước hash bắt buộc phải là 32 bytes
    if len(digest) != SHA256_DIGEST_SIZE:
        raise ValueError(f"Digest size must be exactly {SHA256_DIGEST_SIZE} bytes.")
        
    # Lấy độ dài của key và ciphertext
    key_len = len(encrypted_key)
    cipher_len = len(ciphertext)
    
    # Sử dụng struct pack với '!I' để đảm bảo định dạng 4 bytes Big-Endian (unsigned int)
    header_key = struct.pack("!I", key_len)
    header_cipher = struct.pack("!I", cipher_len)
    
    return header_key + encrypted_key + header_cipher + ciphertext + digest

def parse_secure_packet(packet: bytes):
    """
    Giải mã cấu trúc gói tin và bóc tách các thành phần ra lại.
    Ném lỗi ValueError nếu cấu trúc gói tin bị thiếu hoặc thừa dữ liệu thừa.
    """
    if len(packet) < 8:
        raise ValueError("Packet is too short to contain headers.")
        
    # 1. Đọc độ dài encrypted_key từ 4 byte đầu
    key_len = struct.unpack("!I", packet[:4])[0]
    
    # Xác định offset sau khi lấy xong encrypted_key
    offset = 4 + key_len
    if len(packet) < offset + 4:
        raise ValueError("Packet truncated while reading key or cipher header.")
        
    encrypted_key = packet[4:offset]
    
    # 2. Đọc độ dài ciphertext từ 4 byte tiếp theo
    cipher_len = struct.unpack("!I", packet[offset : offset + 4])[0]
    
    # 3. Tính toán vị trí bóc tách
    cipher_start = offset + 4
    cipher_end = cipher_start + cipher_len
    digest_end = cipher_end + SHA256_DIGEST_SIZE
    
    # Kiểm tra xem độ dài thực tế của gói có khớp hoàn toàn với cấu trúc tính toán không
    # test_packet_rejects_extra_bytes yêu cầu strict matching (không được thừa byte)
    if len(packet) != digest_end:
        raise ValueError("Packet structure invalid: length mismatch or extra bytes detected.")
        
    ciphertext = packet[cipher_start:cipher_end]
    digest = packet[cipher_end:digest_end]
    
    return encrypted_key, ciphertext, digest
