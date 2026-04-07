"""
Task 5 — Guessing Attack
Demonstrates that when the plaintext space is small (e.g., YES / NO),
an attacker can encrypt every candidate and match against the observed
ciphertext to recover the plaintext — without knowing the private key.
Run from the src/ directory: python task5_attack/rsa_guess_attack.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from rsa_core import generate_keys, encrypt, msg_to_int


CANDIDATES = ["YES", "NO"]


def guessing_attack(target_ciphertext: int, pub_key: tuple, candidates: list) -> str | None:
    """Encrypt every candidate and compare to the target ciphertext."""
    for candidate in candidates:
        m = msg_to_int(candidate)
        c = encrypt(m, pub_key)
        if c == target_ciphertext:
            return candidate
    return None


def main():
    pub, priv = generate_keys(bits=512)

    # Sender encrypts one of the two candidates
    secret_message = "YES"
    m = msg_to_int(secret_message)
    observed_ciphertext = encrypt(m, pub)

    print("\n=== Task 5: Guessing Attack ===\n")
    print(f"Known candidate space : {CANDIDATES}")
    print(f"Observed ciphertext   : {observed_ciphertext}")

    recovered = guessing_attack(observed_ciphertext, pub, CANDIDATES)

    print(f"\nAttacker's result     : {recovered}")
    print(f"Correct               : {'✓' if recovered == secret_message else '✗'}")
    print("\nExplanation: because RSA is deterministic, the attacker only needs to")
    print("encrypt each candidate and compare — no private key required.")


if __name__ == "__main__":
    main()
