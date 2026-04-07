"""
Task 3 — Plain RSA Encryption and Decryption
Encrypts each message file with RSA and decrypts it, verifying correctness.
Run from the src/ directory: python task3_basic/rsa_basic.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rsa_core import generate_keys, encrypt, decrypt, msg_to_int, int_to_msg

MESSAGES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "messages")


def main():
    pub, priv = generate_keys(bits=512)
    e, n = pub

    print("\n=== Task 3: Plain RSA Encrypt / Decrypt ===\n")

    for filename in sorted(os.listdir(MESSAGES_DIR)):
        if not filename.endswith(".txt"):
            continue

        path = os.path.join(MESSAGES_DIR, filename)
        with open(path, "r") as f:
            plaintext = f.read().strip()

        m = msg_to_int(plaintext)
        c = encrypt(m, pub)
        recovered_int = decrypt(c, priv)
        recovered = int_to_msg(recovered_int)

        print(f"--- {filename} ---")
        print(f"Plaintext  : {plaintext}")
        print(f"m (int)    : {m}")
        print(f"Ciphertext : {c}")
        print(f"Decrypted  : {recovered}")
        print(f"Match       : {'✓' if recovered == plaintext else '✗ MISMATCH'}\n")


if __name__ == "__main__":
    main()
