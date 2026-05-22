import struct
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

def sha256_digest(data: bytes) -> bytes:
    """Returns the 32-byte SHA-256 hash of the data."""
    h = SHA256.new()
    h.update(data)
    return h.digest()

def generate_des_key_iv():
    """Generates an 8-byte DES key and an 8-byte Initialization Vector (IV)."""
    return get_random_bytes(8), get_random_bytes(8)

def encrypt_des_cbc(plaintext: bytes, key: bytes, iv: bytes):
    """
    Encrypts plaintext using DES in CBC mode.
    Returns: (key, iv, iv + ciphertext)
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long.")
    
    cipher = DES.new(key, DES.MODE_CBC, iv)
    # DES blocks are 8 bytes
    padded_data = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded_data)
    
    # Per test_des_cbc_roundtrip, the ciphertext must start with the IV
    return key, iv, iv + ciphertext

def decrypt_des_cbc(key: bytes, iv_plus_ciphertext: bytes) -> bytes:
    """
    Decrypts DES-CBC ciphertext where the first 8 bytes are the IV.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes long.")
    if len(iv_plus_ciphertext) < 8:
        raise ValueError("Ciphertext too short to contain IV.")
        
    iv = iv_plus_ciphertext[:8]
    actual_ciphertext = iv_plus_ciphertext[8:]
    
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(actual_ciphertext)
    
    return unpad(decrypted_padded, 8)

def encrypt_des_key_rsa(des_key: bytes, rsa_public_key) -> bytes:
    """Encrypts the symmetric DES key using RSA-OAEP."""
    cipher = PKCS1_OAEP.new(rsa_public_key)
    return cipher.encrypt(des_key)

def decrypt_des_key_rsa(encrypted_key: bytes, rsa_private_key) -> bytes:
    """Decrypts the symmetric DES key using RSA-OAEP."""
    cipher = PKCS1_OAEP.new(rsa_private_key)
    return cipher.decrypt(encrypted_key)

def build_sender_payload(plaintext: bytes, rsa_public_key):
    """
    Constructs the binary packet structure to send to the receiver.
    
    Packet structure layout:
    - 4 bytes: length of encrypted RSA key (integer)
    - X bytes: encrypted RSA key
    - 32 bytes: SHA-256 hash of the plaintext
    - Y bytes: DES ciphertext (which includes the 8-byte IV at the start)
    """
    des_key, iv = generate_des_key_iv()
    _, _, full_ciphertext = encrypt_des_cbc(plaintext, des_key, iv)
    
    encrypted_key = encrypt_des_key_rsa(des_key, rsa_public_key)
    digest = sha256_digest(plaintext)
    
    # Package into a single byte stream using struct packing for the length header
    header = struct.pack("!I", len(encrypted_key))
    packet = header + encrypted_key + digest + full_ciphertext
    
    return packet, des_key, full_ciphertext, digest

def open_receiver_payload(packet: bytes, rsa_private_key):
    """
    Unpacks the payload, decrypts it, and verifies data integrity.
    Returns: (plaintext, integrity_ok)
    """
    # 1. Unpack the length header of the RSA-encrypted key
    if len(packet) < 4:
        raise ValueError("Packet is too short.")
    
    rsa_key_len = struct.unpack("!I", packet[:4])[0]
    
    # 2. Slice out components based on the layout offsets
    offset = 4
    encrypted_key = packet[offset : offset + rsa_key_len]
    offset += rsa_key_len
    
    expected_digest = packet[offset : offset + 32]
    offset += 32
    
    ciphertext = packet[offset:]
    
    # 3. Decrypt key and data
    des_key = decrypt_des_key_rsa(encrypted_key, rsa_private_key)
    
    try:
        plaintext = decrypt_des_cbc(des_key, ciphertext)
    except (ValueError, KeyError):
        # In case padding check fails during tampering tests
        raise ValueError("Decryption failed due to corrupted padding or bad block sizes.")
    
    # 4. Check integrity
    actual_digest = sha256_digest(plaintext)
    integrity_ok = (actual_digest == expected_digest)
    
    return plaintext, integrity_ok
