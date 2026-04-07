"""
Task 2 — RSA Key Generation
Generates an RSA key pair and prints all parameters with verification.
Run from the src/ directory: python task2_keygen/rsa_keygen.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rsa_core import generate_keys


def main():
    print("Generating 512-bit RSA key pair...\n")
    pub, priv = generate_keys(bits=512)
    print("\nPublic key  (e, n):", pub)
    print("Private key (d, n):", priv)


if __name__ == "__main__":
    main()
