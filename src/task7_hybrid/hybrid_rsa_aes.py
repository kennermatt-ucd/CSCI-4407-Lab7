"""
Task 7 — Hybrid Encryption (RSA + AES)
Generates a random AES session key, encrypts the message with AES-CBC,
then encrypts the AES key with RSA. Decryption reverses the process.
This is how real-world protocols (TLS, PGP) handle large messages.
Run from the src/ directory: python task7_hybrid/hybrid_rsa_aes.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rsa_core import generate_keys, encrypt, decrypt

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

MESSAGES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "messages")


def aes_encrypt(aes_key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-CBC. Returns (iv, ciphertext)."""
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(plaintext, AES.block_size))


def aes_decrypt(aes_key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """Decrypt AES-CBC ciphertext."""
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)


def hybrid_encrypt(plaintext: bytes, pub_key: tuple) -> tuple[int, bytes, bytes]:
    """Encrypt plaintext using hybrid RSA + AES.

    1. Generate a random 256-bit AES session key.
    2. Encrypt the plaintext with AES-CBC.
    3. Encrypt the AES key with RSA.

    Returns:
        (encrypted_aes_key, iv, aes_ciphertext)
    """
    aes_key = get_random_bytes(32)  # AES-256
    iv, aes_ciphertext = aes_encrypt(aes_key, plaintext)

    # Encrypt the AES key as an integer under RSA
    key_as_int = int.from_bytes(aes_key, byteorder="big")
    encrypted_aes_key = encrypt(key_as_int, pub_key)

    return encrypted_aes_key, iv, aes_ciphertext


def hybrid_decrypt(encrypted_aes_key: int, iv: bytes, aes_ciphertext: bytes,
                   priv_key: tuple) -> bytes:
    """Decrypt a hybrid-encrypted message.

    1. Decrypt the AES key using RSA.
    2. Decrypt the ciphertext using the recovered AES key.
    """
    key_as_int = decrypt(encrypted_aes_key, priv_key)
    aes_key = key_as_int.to_bytes(32, byteorder="big")
    return aes_decrypt(aes_key, iv, aes_ciphertext)


def main():
    pub, priv = generate_keys(bits=512)

    print("\n=== Task 7: Hybrid Encryption (RSA + AES) ===\n")

    for filename in sorted(os.listdir(MESSAGES_DIR)):
        if not filename.endswith(".txt"):
            continue

        path = os.path.join(MESSAGES_DIR, filename)
        with open(path, "rb") as f:
            plaintext = f.read().strip()

        enc_key, iv, aes_ct = hybrid_encrypt(plaintext, pub)
        recovered = hybrid_decrypt(enc_key, iv, aes_ct, priv)

        print(f"--- {filename} ---")
        print(f"Plaintext        : {plaintext.decode()}")
        print(f"AES ciphertext   : {aes_ct.hex()}")
        print(f"Encrypted AES key: {enc_key}")
        print(f"IV               : {iv.hex()}")
        print(f"Recovered        : {recovered.decode()}")
        print(f"Match            : {'✓' if recovered == plaintext else '✗ MISMATCH'}\n")


if __name__ == "__main__":
    main()
