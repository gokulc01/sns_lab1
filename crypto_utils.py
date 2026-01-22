import os
import hmac
import hashlib
from Crypto.Cipher import AES

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if data is None:
        data = b""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if len(padded) == 0 or len(padded) % block_size != 0:
        raise ValueError("Invalid padding length")
    pad_len = padded[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding bytes")
    if padded[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding")
    return padded[:-pad_len]


def generate_iv() -> bytes:
    return os.urandom(BLOCK_SIZE)


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext_padded: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext_padded)


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(ciphertext)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def secure_random(n: int) -> bytes:
    return os.urandom(n)
