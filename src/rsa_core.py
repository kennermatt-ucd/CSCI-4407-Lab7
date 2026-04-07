"""
rsa_core.py — Shared RSA primitives for Lab 7.

All task scripts import from this module so that keys and crypto logic
are implemented once and reused consistently across the lab.
"""

import random
import math


# ---------------------------------------------------------------------------
# Primality and prime generation
# ---------------------------------------------------------------------------

def is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin primality test with k rounds.

    Returns True if n is (probably) prime, False if definitely composite.
    k=20 gives a false-positive probability of at most 4^(-20) ≈ 10^(-12).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d with d odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False  # composite

    return True  # probably prime


def generate_prime(bits: int = 512) -> int:
    """Return a random prime with the given bit length."""
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1  # odd, top bit set
        if is_prime(candidate):
            return candidate


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keys(bits: int = 512):
    """Generate an RSA key pair.

    Args:
        bits: Bit length for each prime p and q (n will be ~2*bits).

    Returns:
        (public_key, private_key) where:
            public_key  = (e, n)
            private_key = (d, n)

    Also prints p, q, n, phi(n), e, d and verifies ed ≡ 1 (mod phi(n)).
    """
    # Step 1: choose two distinct primes p and q
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)

    # Step 2: compute modulus and Euler's totient
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Step 3: choose public exponent e coprime with phi(n)
    # 65537 is the standard choice: prime, small Hamming weight, fast exponentiation
    e = 65537
    if math.gcd(e, phi_n) != 1:
        # Fallback: search for a valid e (rare with 512-bit primes)
        e = 3
        while math.gcd(e, phi_n) != 1:
            e += 2

    # Step 4: compute private exponent d = e^(-1) mod phi(n)
    d = pow(e, -1, phi_n)  # Python 3.8+ modular inverse

    # Verification
    assert (e * d) % phi_n == 1, "Key generation failed: ed ≢ 1 (mod phi(n))"

    print("=== RSA Key Generation ===\n")
    print(f"p     = {p}")
    print(f"q     = {q}")
    print(f"n     = {n}")
    print(f"phi(n)= {phi_n}")
    print(f"e     = {e}")
    print(f"d     = {d}")
    print(f"\ned mod phi(n) = {(e * d) % phi_n}  (must be 1 ✓)")

    return (e, n), (d, n)


# ---------------------------------------------------------------------------
# Encryption and decryption
# ---------------------------------------------------------------------------

def msg_to_int(message: str) -> int:
    """Convert a UTF-8 string to a non-negative integer."""
    return int.from_bytes(message.encode("utf-8"), byteorder="big")


def int_to_msg(value: int) -> str:
    """Convert a non-negative integer back to a UTF-8 string."""
    byte_length = (value.bit_length() + 7) // 8
    return value.to_bytes(byte_length, byteorder="big").decode("utf-8")


def encrypt(m: int, pub_key: tuple) -> int:
    """RSA encryption: c = m^e mod n.

    Args:
        m:       plaintext as a non-negative integer (must be < n)
        pub_key: (e, n)

    Returns:
        ciphertext integer c
    """
    e, n = pub_key
    assert m < n, "Message integer must be smaller than modulus n"
    return pow(m, e, n)


def decrypt(c: int, priv_key: tuple) -> int:
    """RSA decryption: m = c^d mod n.

    Args:
        c:        ciphertext integer
        priv_key: (d, n)

    Returns:
        plaintext integer m
    """
    d, n = priv_key
    return pow(c, d, n)
