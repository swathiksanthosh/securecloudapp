"""
encrypt_decrypt.py

Provides:
- AES (CBC) encrypt/decrypt
- DES (CBC) encrypt/decrypt
- RC6 (CBC) encrypt/decrypt (pure-Python implementation)
- PKCS7 padding helpers
- Simple file/data helpers

Dependencies:
    pip install pycryptodome
"""

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import struct
import math

# -------------------------
# Padding (PKCS7)
# -------------------------
def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("Invalid padding (empty input)")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

# -------------------------
# AES (CBC, 128-bit key)
# -------------------------
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Returns: iv + ciphertext
    key: 16 bytes (128-bit)
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16/24/32 bytes")
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))
    return iv + ct

def aes_decrypt(key: bytes, iv_and_ciphertext: bytes) -> bytes:
    if len(iv_and_ciphertext) < 16:
        raise ValueError("ciphertext too short")
    iv = iv_and_ciphertext[:16]
    ct = iv_and_ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return pkcs7_unpad(pt_padded)

# -------------------------
# DES (CBC, 8-byte key)
# PyCryptodome's DES expects 8-byte key
# -------------------------
def des_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Returns: iv + ciphertext
    key: 8 bytes (DES key)
    """
    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")
    iv = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs7_pad(plaintext, DES.block_size))
    return iv + ct

def des_decrypt(key: bytes, iv_and_ciphertext: bytes) -> bytes:
    if len(iv_and_ciphertext) < 8:
        raise ValueError("ciphertext too short")
    iv = iv_and_ciphertext[:8]
    ct = iv_and_ciphertext[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt_padded = cipher.decrypt(ct)
    return pkcs7_unpad(pt_padded)

# -------------------------
# RC6 (pure Python)
# Reference parameters: w=32, r=20, b = key bytes length
# This is a straightforward implementation of RC6-32/20/16 style.
# -------------------------
def _rotl(x, n, w=32):
    n %= w
    return ((x << n) & ((1 << w) - 1)) | (x >> (w - n))

def _rotr(x, n, w=32):
    n %= w
    return (x >> n) | ((x << (w - n)) & ((1 << w) - 1))

def _bytes_to_words_le(b):
    # convert bytes to list of 32-bit little-endian words
    words = []
    for i in range(0, len(b), 4):
        chunk = b[i:i+4]
        words.append(int.from_bytes(chunk.ljust(4, b'\x00'), 'little'))
    return words

def _words_to_bytes_le(words):
    return b''.join(w.to_bytes(4, 'little') for w in words)

class RC6:
    def __init__(self, key: bytes, w=32, r=20):
        self.w = w
        self.r = r
        self.mod = 1 << w
        self.Pw = 0xB7E15163 & (self.mod - 1)
        self.Qw = 0x9E3779B9 & (self.mod - 1)
        self._key_schedule(key)

    def _key_schedule(self, K: bytes):
        # Convert key bytes to c words of u = w/8 bytes
        u = self.w // 8
        c = max(1, math.ceil(len(K) / u))
        L = _bytes_to_words_le(K.ljust(c * u, b'\x00'))
        t = 2 * self.r + 4
        S = [0] * t
        S[0] = self.Pw
        for i in range(1, t):
            S[i] = (S[i-1] + self.Qw) & (self.mod - 1)
        # Mixing
        i = j = 0
        A = B = 0
        n = 3 * max(t, c)
        for _ in range(n):
            A = S[i] = _rotl((S[i] + A + B) & (self.mod - 1), 3, self.w)
            B = L[j] = _rotl((L[j] + A + B) & (self.mod - 1), (A + B) & (self.w - 1), self.w)
            i = (i + 1) % t
            j = (j + 1) % c
        self.S = S

    def encrypt_block(self, plaintext_block: bytes) -> bytes:
        if len(plaintext_block) != 16:
            raise ValueError("RC6 block must be 16 bytes")
        A = int.from_bytes(plaintext_block[0:4], 'little')
        B = int.from_bytes(plaintext_block[4:8], 'little')
        C = int.from_bytes(plaintext_block[8:12], 'little')
        D = int.from_bytes(plaintext_block[12:16], 'little')

        B = (B + self.S[0]) & (self.mod - 1)
        D = (D + self.S[1]) & (self.mod - 1)
        for i in range(1, self.r + 1):
            t = _rotl((B * ((2 * B + 1) & (self.mod - 1))) & (self.mod - 1), 5, self.w)
            u = _rotl((D * ((2 * D + 1) & (self.mod - 1))) & (self.mod - 1), 5, self.w)
            A = (_rotl((A ^ t) & (self.mod - 1), u & (self.w - 1), self.w) + self.S[2 * i]) & (self.mod - 1)
            C = (_rotl((C ^ u) & (self.mod - 1), t & (self.w - 1), self.w) + self.S[2 * i + 1]) & (self.mod - 1)
            A, B, C, D = B, C, D, A  # rotate registers
        A = (A + self.S[2 * self.r + 2]) & (self.mod - 1)
        C = (C + self.S[2 * self.r + 3]) & (self.mod - 1)

        out = (A.to_bytes(4, 'little') + B.to_bytes(4, 'little') +
               C.to_bytes(4, 'little') + D.to_bytes(4, 'little'))
        return out

    def decrypt_block(self, cipher_block: bytes) -> bytes:
        if len(cipher_block) != 16:
            raise ValueError("RC6 block must be 16 bytes")
        A = int.from_bytes(cipher_block[0:4], 'little')
        B = int.from_bytes(cipher_block[4:8], 'little')
        C = int.from_bytes(cipher_block[8:12], 'little')
        D = int.from_bytes(cipher_block[12:16], 'little')

        C = (C - self.S[2 * self.r + 3]) & (self.mod - 1)
        A = (A - self.S[2 * self.r + 2]) & (self.mod - 1)
        for i in range(self.r, 0, -1):
            A, B, C, D = D, A, B, C  # inverse rotate
            t = _rotl((B * ((2 * B + 1) & (self.mod - 1))) & (self.mod - 1), 5, self.w)
            u = _rotl((D * ((2 * D + 1) & (self.mod - 1))) & (self.mod - 1), 5, self.w)
            C = (_rotr((C - self.S[2 * i + 1]) & (self.mod - 1), t & (self.w - 1), self.w) ^ u) & (self.mod - 1)
            A = (_rotr((A - self.S[2 * i]) & (self.mod - 1), u & (self.w - 1), self.w) ^ t) & (self.mod - 1)
        D = (D - self.S[1]) & (self.mod - 1)
        B = (B - self.S[0]) & (self.mod - 1)

        out = (A.to_bytes(4, 'little') + B.to_bytes(4, 'little') +
               C.to_bytes(4, 'little') + D.to_bytes(4, 'little'))
        return out

# RC6 CBC-mode helpers
def rc6_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Return iv + ciphertext. IV is 16 bytes.
    key length can be up to 32 bytes (we will pad/truncate as needed).
    """
    # RC6 uses 16-byte block. We'll use IV of 16 bytes.
    if len(key) == 0:
        raise ValueError("RC6 key cannot be empty")
    iv = get_random_bytes(16)
    rc6 = RC6(key)
    bs = 16
    padded = pkcs7_pad(plaintext, bs)
    ciphertext_blocks = []
    prev = iv
    for i in range(0, len(padded), bs):
        block = padded[i:i+bs]
        # CBC: XOR with prev ciphertext (prev)
        xored = bytes(a ^ b for a,b in zip(block, prev))
        enc = rc6.encrypt_block(xored)
        ciphertext_blocks.append(enc)
        prev = enc
    return iv + b''.join(ciphertext_blocks)

def rc6_decrypt(key: bytes, iv_and_ciphertext: bytes) -> bytes:
    if len(iv_and_ciphertext) < 16:
        raise ValueError("ciphertext too short")
    iv = iv_and_ciphertext[:16]
    ct = iv_and_ciphertext[16:]
    if len(ct) % 16 != 0:
        raise ValueError("invalid ciphertext length for RC6")
    rc6 = RC6(key)
    plaintext_blocks = []
    prev = iv
    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        dec = rc6.decrypt_block(block)
        xored = bytes(a ^ b for a,b in zip(dec, prev))
        plaintext_blocks.append(xored)
        prev = block
    padded = b''.join(plaintext_blocks)
    return pkcs7_unpad(padded)

# -------------------------
# Unified API
# -------------------------
def encrypt_data(algorithm: str, key: bytes, plaintext: bytes) -> bytes:
    """
    algorithm: 'AES', 'DES', 'RC6' (case-insensitive)
    returns: iv + ciphertext
    """
    algo = algorithm.strip().lower()
    if algo == 'aes':
        return aes_encrypt(key, plaintext)
    elif algo == 'des':
        return des_encrypt(key, plaintext)
    elif algo == 'rc6':
        return rc6_encrypt(key, plaintext)
    else:
        raise ValueError("Unsupported algorithm. Choose AES, DES, or RC6.")

def decrypt_data(algorithm: str, key: bytes, iv_and_ciphertext: bytes) -> bytes:
    algo = algorithm.strip().lower()
    if algo == 'aes':
        return aes_decrypt(key, iv_and_ciphertext)
    elif algo == 'des':
        return des_decrypt(key, iv_and_ciphertext)
    elif algo == 'rc6':
        return rc6_decrypt(key, iv_and_ciphertext)
    else:
        raise ValueError("Unsupported algorithm. Choose AES, DES, or RC6.")

# -------------------------
# Example CLI / quick test
# -------------------------
if __name__ == '__main__':
    # Quick test for all three algorithms
    msg = b"Hello - this is a test message for encryption. Keep it secret!"
    print("Plain:", msg)

    # AES (16-byte key)
    aes_key = b'0123456789ABCDEF'  # 16 bytes
    aes_ct = encrypt_data('AES', aes_key, msg)
    aes_pt = decrypt_data('AES', aes_key, aes_ct)
    print("AES OK:", aes_pt == msg)

    # DES (8-byte key)
    des_key = b'8bytekey'
    des_ct = encrypt_data('DES', des_key, msg)
    des_pt = decrypt_data('DES', des_key, des_ct)
    print("DES OK:", des_pt == msg)

    # RC6 (use 16-byte key here)
    rc6_key = b'rc6secretkey1234'  # 16 bytes
    rc6_ct = encrypt_data('RC6', rc6_key, msg)
    rc6_pt = decrypt_data('RC6', rc6_key, rc6_ct)
    print("RC6 OK:", rc6_pt == msg)

    print("Lengths: AES:", len(aes_ct), "DES:", len(des_ct), "RC6:", len(rc6_ct))
