"""
Task 4 — Determinism Problem
Encrypts the same message twice and shows the ciphertexts are identical,
demonstrating that plain RSA leaks equality information.
Run from the src/ directory: python task4_deterministic/rsa_deterministic.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rsa_core import generate_keys, encrypt, msg_to_int


def main():
    pub, _ = generate_keys(bits=512)

    message = "Transfer 100 dollars to Bob"
    m = msg_to_int(message)

    c1 = encrypt(m, pub)
    c2 = encrypt(m, pub)

    print("\n=== Task 4: Determinism Problem ===\n")
    print(f"Message     : {message}")
    print(f"Ciphertext 1: {c1}")
    print(f"Ciphertext 2: {c2}")
    print(f"Equal       : {c1 == c2}")
    print("\nObservation: encrypting the same message twice always produces the same ciphertext.")
    print("An observer who sees two identical ciphertexts knows the same message was sent twice.")


if __name__ == "__main__":
    main()
