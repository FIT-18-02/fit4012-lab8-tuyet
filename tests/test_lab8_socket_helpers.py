import struct
import socket
from Crypto.Hash import SHA256

SHA256_DIGEST_SIZE = 32

def _recv_all(sock: socket.socket, length: int) -> bytes:
    """Hàm bổ trợ đảm bảo nhận đủ chính xác 'length' bytes từ socket."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket bị đóng bất ngờ trước khi nhận đủ dữ liệu.")
        data += chunk
    return data

def recv_secure_packet(sock: socket.socket) -> bytes:
    """
    Đọc và khôi phục nguyên vẹn gói tin bảo mật từ socket TCP.
    Hàm này tính toán kích thước dựa trên cấu trúc header để nhận đủ byte,
    tránh lỗi mất dữ liệu do phân mảnh socket.
    """
    # 1. Đọc 4 byte đầu tiên để biết độ dài của encrypted_key
    key_len_bytes = _recv_all(sock, 4)
    key_len = struct.unpack("!I", key_len_bytes)[0]
    
    # 2. Đọc tiếp X bytes dữ liệu của encrypted_key
    encrypted_key = _recv_all(sock, key_len)
    
    # 3. Đọc 4 byte tiếp theo để biết độ dài của ciphertext
    cipher_len_bytes = _recv_all(sock, 4)
    cipher_len = struct.unpack("!I", cipher_len_bytes)[0]
    
    # 4. Đọc tiếp Y bytes dữ liệu của ciphertext
    ciphertext = _recv_all(sock, cipher_len)
    
    # 5. Đọc nốt 32 bytes của phần mã băm digest
    digest = _recv_all(sock, SHA256_DIGEST_SIZE)
    
    # Ghép tất cả các mảnh lại theo đúng cấu trúc ban đầu để trả về nguyên gói packet
    return key_len_bytes + encrypted_key + cipher_len_bytes + ciphertext + digest

# Đặt các hàm build_secure_packet và parse_secure_packet của bạn ở đây...
