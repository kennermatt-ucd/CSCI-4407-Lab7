# Lab 7 — Group 10 — Public-Key Encryption (RSA, IND-CPA, Hybrid)

**Course:** CSCI/CSCY 4407 — Security & Cryptography
**Semester:** Spring 2026
**Group Members:** Cassius Kemp, Matthew Kenner, Jonathan Le

---

## Task 1 — Setup & Messages

### Overview

This task creates the working directory structure and three plaintext message files used
throughout the lab. SHA-256 hashes are computed to establish a baseline fingerprint for
each file, confirming integrity before any encryption is performed.

### Steps

**Step 1 — Create directory and message files**

```bash
mkdir RSA_Lab
cd RSA_Lab
echo "Transfer 100 dollars to Bob" > msg1.txt
echo "Launch satellite at 06:00" > msg2.txt
echo "Approve access request for server room" > msg3.txt
```

**Step 2 — Verify contents and SHA-256 hashes**

```bash
cat *.txt
sha256sum *.txt
```

### Screenshots

**Screenshot 1 — Directory listing and file contents**

<!-- Insert screenshot: terminal showing ls and cat *.txt output -->

**Screenshot 2 — SHA-256 hashes**

<!-- Insert screenshot: terminal showing sha256sum *.txt output -->

### Results

| File    | Contents                                | SHA-256 |
|---------|-----------------------------------------|---------|
| msg1.txt | Transfer 100 dollars to Bob            | <!-- paste --> |
| msg2.txt | Launch satellite at 06:00              | <!-- paste --> |
| msg3.txt | Approve access request for server room | <!-- paste --> |

### Explanation

Three distinct messages are chosen to represent realistic high-stakes communications.
Hashing them upfront establishes a verifiable reference so that any modification during
encryption experiments can be detected. All subsequent tasks read from these files.

---

## Task 2 — RSA Key Generation

### Overview

RSA security depends on the difficulty of factoring the product of two large primes.
This task generates the full key pair from scratch: primes p and q, modulus n,
Euler's totient φ(n), public exponent e, and private exponent d, then verifies
that `ed ≡ 1 (mod φ(n))`.

### Source Code

```python
# src/rsa_core.py — generate_keys()  (see full file in submission)

def generate_keys(bits: int = 512):
    p = generate_prime(bits)
    q = generate_prime(bits)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = pow(e, -1, phi_n)
    assert (e * d) % phi_n == 1
    return (e, n), (d, n)
```

### Steps

**Step 1 — Run the key generation script**

```bash
cd src
python task2_keygen/rsa_keygen.py
```

### Screenshots

**Screenshot 1 — `rsa_keygen.py` terminal output**

<!-- Insert screenshot: showing p, q, n, phi(n), e, d, and the ed mod phi(n) = 1 verification -->

### Results

| Parameter | Value |
|-----------|-------|
| p         | <!-- paste --> |
| q         | <!-- paste --> |
| n         | <!-- paste --> |
| φ(n)      | <!-- paste --> |
| e         | 65537 |
| d         | <!-- paste --> |
| ed mod φ(n) | 1 ✓ |

### Explanation

Two distinct 512-bit primes are generated using the Miller-Rabin primality test. Their
product n forms the RSA modulus; factoring n is computationally infeasible at this bit
length. The public exponent e = 65537 is the industry-standard choice — it is prime,
has low Hamming weight (binary `10000000000000001`), and makes modular exponentiation
fast without compromising security. The private exponent d is computed as the modular
inverse of e modulo φ(n) using Python's built-in `pow(e, -1, phi_n)`. The assertion
`ed ≡ 1 (mod φ(n))` confirms that encryption and decryption are exact inverses.

---

## Task 3 — Plain RSA Encryption and Decryption

### Overview

Each message file is converted to an integer, encrypted with the public key
(`c = m^e mod n`), decrypted with the private key (`m = c^d mod n`), and
the recovered text is verified against the original.

### Source Code

```python
# src/task3_basic/rsa_basic.py  (see full file in submission)

m = msg_to_int(plaintext)   # UTF-8 bytes → integer
c = encrypt(m, pub)         # c = m^e mod n
recovered_int = decrypt(c, priv)  # m = c^d mod n
recovered = int_to_msg(recovered_int)
```

### Steps

**Step 1 — Run the basic RSA script**

```bash
python task3_basic/rsa_basic.py
```

### Screenshots

**Screenshot 1 — `rsa_basic.py` terminal output**

<!-- Insert screenshot: showing plaintext, m (int), ciphertext, decrypted text, and ✓ match for each message -->

### Results

| File     | Plaintext                               | Ciphertext (truncated) | Match |
|----------|-----------------------------------------|------------------------|-------|
| msg1.txt | Transfer 100 dollars to Bob            | <!-- paste first 20 chars... --> | ✓ |
| msg2.txt | Launch satellite at 06:00              | <!-- paste --> | ✓ |
| msg3.txt | Approve access request for server room | <!-- paste --> | ✓ |

### Explanation

The message string is converted to an integer by treating its UTF-8 bytes as a
big-endian integer. `pow(m, e, n)` performs modular exponentiation efficiently
using Python's built-in fast exponentiation — this is the only computation needed
for encryption. Decryption is identical in structure (`pow(c, d, n)`), exploiting
the mathematical relationship `(m^e)^d ≡ m (mod n)` guaranteed by Euler's theorem.
All three messages decrypt correctly, confirming the implementation is correct.
However, Task 4 will show that this scheme provides no security guarantee because
it is deterministic.

---

## Task 4 — Determinism Problem

### Overview

Plain RSA is a deterministic function: given the same key and message, it always
produces the same ciphertext. This task demonstrates the problem by encrypting the
same message twice and showing the outputs are identical.

### Source Code

```python
# src/task4_deterministic/rsa_deterministic.py  (see full file in submission)

c1 = encrypt(m, pub)
c2 = encrypt(m, pub)
print(c1 == c2)  # True
```

### Steps

**Step 1 — Run the determinism script**

```bash
python task4_deterministic/rsa_deterministic.py
```

### Screenshots

**Screenshot 1 — `rsa_deterministic.py` terminal output**

<!-- Insert screenshot: showing both ciphertexts are identical and Equal: True -->

### Explanation

Because `c = m^e mod n` is a pure function of m and the public key, identical inputs
always yield identical outputs. An attacker observing network traffic who sees the same
ciphertext appear twice immediately knows the same plaintext was sent twice, even without
breaking RSA. More dangerously, if the plaintext space is small (e.g., YES/NO, approved/denied),
the attacker can pre-compute ciphertexts for all candidates and look up any observed
ciphertext — this is the guessing attack demonstrated in Task 5.

---

## Task 5 — Guessing Attack

### Overview

When the set of possible plaintexts is small and known, an attacker with only the
public key can recover any ciphertext by encrypting every candidate and comparing.

### Source Code

```python
# src/task5_attack/rsa_guess_attack.py  (see full file in submission)

def guessing_attack(target_ciphertext, pub_key, candidates):
    for candidate in candidates:
        m = msg_to_int(candidate)
        if encrypt(m, pub_key) == target_ciphertext:
            return candidate
    return None
```

### Steps

**Step 1 — Run the guessing attack script**

```bash
python task5_attack/rsa_guess_attack.py
```

### Screenshots

**Screenshot 1 — `rsa_guess_attack.py` terminal output**

<!-- Insert screenshot: showing candidate space, observed ciphertext, and attacker's recovered plaintext -->

### Explanation

The attacker knows the public key (e, n) — it is public by definition — and knows
the candidate space {YES, NO}. By computing `encrypt("YES", pub)` and `encrypt("NO", pub)`
and comparing each to the observed ciphertext, the attacker recovers the plaintext in
at most two operations. No private key, no factoring, no cryptanalysis required. This
attack generalises to any small or predictable message space (e.g., binary decisions,
short status codes), and is a direct consequence of the determinism shown in Task 4.

---

## Task 6 — Randomized Encryption

### Overview

Prepending a random nonce to the message before encryption ensures the same plaintext
produces a different ciphertext every time, defeating the guessing attack.

### Source Code

```python
# src/task6_randomized/rsa_randomized_demo.py  (see full file in submission)

nonce = random.getrandbits(64)
combined = nonce_bytes + message_bytes  # nonce || message
c = encrypt(combined_as_int, pub)
```

### Steps

**Step 1 — Run the randomized encryption script**

```bash
python task6_randomized/rsa_randomized_demo.py
```

### Screenshots

**Screenshot 1 — `rsa_randomized_demo.py` terminal output**

<!-- Insert screenshot: showing same message producing two different ciphertexts, Equal: False -->

### Explanation

By prepending a fresh 64-bit random nonce before encryption, two encryptions of the same
message produce different integers, and therefore different ciphertexts. The attacker's
guessing attack from Task 5 fails because pre-computing `encrypt("YES", pub)` now produces
a value that will almost certainly never match any observed ciphertext — each encryption
uses a fresh nonce. This is the intuition behind IND-CPA (indistinguishability under chosen
plaintext attack): an adversary who sees a ciphertext cannot tell which of two candidate
messages it encodes. Note that this nonce-based approach is a simplified demonstration;
in practice, RSA-OAEP (Optimal Asymmetric Encryption Padding) provides the standardised,
provably-secure randomised padding scheme.

---

## Task 7 — Hybrid Encryption (RSA + AES)

### Overview

Direct RSA encryption is limited to messages smaller than the modulus (~64 bytes for
512-bit RSA). Hybrid encryption solves this: encrypt the message with AES using a
random session key, then encrypt only the session key with RSA.

### Source Code

```python
# src/task7_hybrid/hybrid_rsa_aes.py  (see full file in submission)

# Encrypt
aes_key = get_random_bytes(32)         # random AES-256 session key
iv, aes_ciphertext = aes_encrypt(aes_key, plaintext)
encrypted_aes_key = encrypt(key_as_int, pub)

# Decrypt
aes_key = decrypt(encrypted_aes_key, priv)  # RSA unwraps the session key
plaintext = aes_decrypt(aes_key, iv, aes_ciphertext)
```

### Steps

**Step 1 — Run the hybrid encryption script**

```bash
python task7_hybrid/hybrid_rsa_aes.py
```

### Screenshots

**Screenshot 1 — `hybrid_rsa_aes.py` terminal output**

<!-- Insert screenshot: showing plaintext, AES ciphertext (hex), encrypted AES key, IV, recovered plaintext, and ✓ match for each message -->

### Explanation

A 256-bit AES session key is generated fresh for each message. The message is encrypted
with AES-CBC — fast, symmetric, and suitable for arbitrary-length data. The 32-byte AES key
is then encrypted with RSA, which acts as a secure key transport mechanism. The recipient
uses their RSA private key to recover the AES key, then uses it to decrypt the message.
This construction is used in virtually all real-world asymmetric cryptography: TLS uses RSA
or ECDH to exchange a symmetric key, then AES for the actual data channel. PGP does the same.
Hybrid encryption combines the key management advantages of asymmetric crypto with the speed
and flexibility of symmetric crypto.

---

## Task 8 — Security Comparison

### Overview

A summary of all four encryption approaches evaluated in this lab.

### Steps

*(No script required — analysis only.)*

### Results Table

| Method | Randomized? | Equality Leakage | Practical for Large Data? | Secure? | Recommendation |
|---|:---:|:---:|:---:|:---:|---|
| Plain RSA | No | Yes — identical CT for identical PT | No (size limit) | No | Never use directly |
| Deterministic RSA | No | Yes | No | No | Demonstrates the problem only |
| Randomized RSA (nonce demo) | Yes | No | No (size limit) | Partial | Better, but use OAEP in practice |
| Hybrid (RSA + AES) | Yes (AES key + IV) | No | Yes | Yes | Standard practice |

### Explanation

Plain and deterministic RSA are identical in this context — both produce the same ciphertext
for the same input and are vulnerable to the guessing attack. The nonce-based randomisation
from Task 6 eliminates equality leakage but does not solve the size limitation of RSA.
Hybrid encryption addresses both problems: AES handles arbitrary-length messages efficiently,
and the fresh AES key per session provides randomness, meaning two encryptions of the same
message produce different ciphertexts. The only standardised, production-ready approach is
hybrid encryption using RSA-OAEP for key wrapping and AES-GCM (or AES-CBC with HMAC) for
the message.

---

## Task 9 — Reflection

Deterministic encryption fails because it is a pure function of the plaintext and the public
key: the same input always produces the same output. An attacker who can observe ciphertexts
and knows (or can guess) the plaintext space can recover messages without touching the private
key, simply by encrypting candidates and comparing — as shown in Task 5. IND-CPA requires that
no computationally bounded adversary can distinguish the encryption of one message from another
with better than 50% probability; deterministic encryption trivially fails this because the
adversary only needs to encrypt the challenge messages themselves and compare. Randomness fixes
this by making ciphertext a function of both the plaintext and a fresh unpredictable value,
so no pre-computation is possible. Hybrid encryption is used in practice because RSA can only
encrypt data smaller than its modulus, is orders of magnitude slower than AES, and requires
carefully designed padding (OAEP) to be secure. By using RSA purely for key transport and AES
for the data, we get the key management benefits of asymmetric cryptography combined with the
speed and flexibility of symmetric encryption — the model used by TLS, PGP, and SSH.

---

## References

- Rivest, R., Shamir, A., & Adleman, L. (1978). *A Method for Obtaining Digital Signatures and Public-Key Cryptosystems.* CACM 21(2).
- Bellare, M. & Rogaway, P. (1994). *Optimal Asymmetric Encryption.* EUROCRYPT 1994.
- NIST FIPS 197 — Advanced Encryption Standard (AES).
- Python `pycryptodome` library documentation: https://pycryptodome.readthedocs.io
