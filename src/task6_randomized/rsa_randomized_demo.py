"""
Task 6 — Randomized Encryption Demo
Prepends a random nonce to the message before encryption so that the same
plaintext produces a different ciphertext each time, defeating the guessing
attack from Task 5.
Run from the src/ directory: python task6_randomized/rsa_randomized_demo.py
"""

import sys
import os
import random
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rsa_core import generate_keys, encrypt, decrypt, msg_to_int, int_to_msg

NONCE_BITS = 64  # bits of random padding prepended to each message


def randomized_encrypt(message: str, pub_key: tuple) -> tuple[int, int]:
    """Encrypt message with a fresh random nonce prepended.

    Returns:
        (ciphertext, nonce) — nonce is needed for decryption demo only;
        in a real scheme the nonce would be included in the ciphertext.
    """
    nonce = random.getrandbits(NONCE_BITS)
    # Encode as: nonce (64 bits) || message bytes
    msg_bytes = message.encode("utf-8")
    nonce_bytes = nonce.to_bytes(NONCE_BITS // 8, byteorder="big")
    combined = int.from_bytes(nonce_bytes + msg_bytes, byteorder="big")
    return encrypt(combined, pub_key), nonce


def randomized_decrypt(ciphertext: int, priv_key: tuple, msg_len: int) -> str:
    """Decrypt and strip the nonce prefix to recover the original message."""
    combined_int = decrypt(ciphertext, priv_key)
    nonce_bytes = NONCE_BITS // 8
    total_bytes = nonce_bytes + msg_len
    combined_bytes = combined_int.to_bytes(total_bytes, byteorder="big")
    return combined_bytes[nonce_bytes:].decode("utf-8")


def main():
    pub, priv = generate_keys(bits=512)
    message = "Transfer 100 dollars to Bob"

    c1, _ = randomized_encrypt(message, pub)
    c2, _ = randomized_encrypt(message, pub)

    print("\n=== Task 6: Randomized Encryption ===\n")
    print(f"Message       : {message}")
    print(f"Ciphertext 1  : {c1}")
    print(f"Ciphertext 2  : {c2}")
    print(f"Equal         : {c1 == c2}")
    print("\nObservation: the same message now produces different ciphertexts each time.")
    print("An observer can no longer determine whether two ciphertexts encode the same message.")


if __name__ == "__main__":
    main()
