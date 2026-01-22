import os
from crypto_utils import (
    pkcs7_pad,
    pkcs7_unpad,
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    hmac_sha256,
    generate_iv,
)


def test_padding():
    print("--- Testing PKCS#7 Padding ---")
    block_size = 16

    # Case 1: Data needs some padding
    data1 = b"HelloIIIT"  # 9 bytes
    padded1 = pkcs7_pad(data1, block_size)
    assert len(padded1) == 16
    assert padded1[-1] == 7  # Should add 7 bytes of 0x07
    assert pkcs7_unpad(padded1, block_size) == data1
    print("Test 1 (Partial block) Passed")

    # Case 2: Data is exactly one block (Must add full block of padding)
    data2 = b"A" * 16
    padded2 = pkcs7_pad(data2, block_size)
    assert len(padded2) == 32
    assert padded2[-1] == 16  # Should add 16 bytes of 0x10
    assert pkcs7_unpad(padded2, block_size) == data2
    print("Test 2 (Full block) Passed")

    # Case 3: Invalid padding detection
    invalid_padded = b"SomethingWrong\x05\x05\x05\x01\x05"
    try:
        pkcs7_unpad(invalid_padded, block_size)
    except ValueError:
        print("Test 3 (Tamper Detection) Passed")


def test_encryption_decryption():
    print("\n--- Testing AES-128-CBC ---")
    key = os.urandom(16)  # AES-128 requirement [cite: 55]
    iv = generate_iv()
    plaintext = b"Secure communication lab assignment 1"

    # Encryption flow [cite: 60-64]
    padded_pt = pkcs7_pad(plaintext)
    ciphertext = aes_cbc_encrypt(key, iv, padded_pt)

    # Decryption flow [cite: 72-73]
    decrypted_padded = aes_cbc_decrypt(key, iv, ciphertext)
    result = pkcs7_unpad(decrypted_padded)

    assert result == plaintext
    print("Encryption/Decryption cycle Passed")


def test_hmac():
    print("\n--- Testing HMAC-SHA256 ---")
    key = b"secret_mac_key_0"
    data = b"header_data_and_ciphertext"

    mac1 = hmac_sha256(key, data)
    mac2 = hmac_sha256(key, data)

    assert mac1 == mac2
    assert len(mac1) == 32  # SHA256 produces 32 bytes [cite: 110]

    # Test integrity check failure
    mac_tampered = hmac_sha256(key, data + b"extra")
    assert mac1 != mac_tampered
    print("HMAC verification Passed")


if __name__ == "__main__":
    try:
        test_padding()
        test_encryption_decryption()
        test_hmac()
        print("\nAll cryptographic primitives verified successfully!")
    except AssertionError as e:
        print(f"\nTest failed! Check your logic.")
