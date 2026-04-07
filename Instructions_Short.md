
---

# Lab 7: Public-Key Encryption (RSA, IND-CPA, Hybrid)

## Overview

This lab explores **public-key encryption (PKE)** through:

* RSA implementation
* Security weaknesses of deterministic encryption
* Randomization for security (IND-CPA intuition)
* Hybrid encryption (RSA + AES)

You will implement, test, and analyze these concepts using Python in a Linux environment.

---

## Objectives

By completing this lab, you will:

* Implement RSA key generation, encryption, and decryption
* Understand roles of **p, q, n, φ(n), e, d**
* Demonstrate why **deterministic encryption is insecure**
* Perform a **guessing attack on RSA**
* Show why **randomness is required**
* Implement **hybrid encryption (RSA + AES)**
* Compare encryption methods and explain **real-world usage**

---

## Environment Setup

* OS: Linux (Ubuntu, Kali, VM, or lab machine)
* Tools:

  * Python 3
  * `pycryptodome`
* Install:

```bash
sudo apt update
sudo apt install python3 python3-pip
pip3 install pycryptodome
```

---

## Project Setup

```bash
mkdir RSA_Lab
cd RSA_Lab
```

Create test messages:

```bash
echo "Transfer 100 dollars to Bob" > msg1.txt
echo "Launch satellite at 06:00" > msg2.txt
echo "Approve access request for server room" > msg3.txt
```

Verify:

```bash
cat *.txt
sha256sum *.txt
```

---

## Tasks Summary

### Task 1: Setup & Messages

* Create working directory + 3 plaintext files
* Verify contents and SHA-256 hashes
* **Submit:** screenshots

---

### Task 2: RSA Key Generation

* Generate:

  * p, q
  * n = pq
  * φ(n)
  * e (coprime with φ(n))
  * d (mod inverse of e)
* Verify: `ed ≡ 1 mod φ(n)`
* **Submit:**

  * `rsa_keygen.py`
  * screenshot + explanation

---

### Task 3: Plain RSA

* Convert message → integer
* Encrypt: `c = m^e mod n`
* Decrypt: `m = c^d mod n`
* Verify correctness
* **Submit:**

  * `rsa_basic.py`
  * screenshot + explanation

---

### Task 4: Determinism Problem

* Encrypt same message twice
* Show ciphertexts are identical
* Explain why this breaks security
* **Submit:**

  * `rsa_deterministic.py`
  * screenshot + explanation

---

### Task 5: Guessing Attack

* Use small message space (e.g., YES/NO)
* Match ciphertexts to recover plaintext
* **Submit:**

  * `rsa_guess_attack.py`
  * screenshot + explanation

---

### Task 6: Randomized Encryption

* Add randomness (nonce) before encryption
* Show same message → different ciphertexts
* **Submit:**

  * `rsa_randomized_demo.py`
  * screenshot + explanation

---

### Task 7: Hybrid Encryption (RSA + AES)

* Generate AES session key
* Encrypt:

  * Message → AES
  * Key → RSA
* Decrypt and verify recovery
* **Submit:**

  * `hybrid_rsa_aes.py`
  * screenshot + explanation

---

### Task 8: Security Comparison

Create a table comparing:

* Plain RSA
* Deterministic RSA
* Randomized RSA (demo)
* Hybrid encryption

Include:

* Randomization
* Equality leakage
* Practicality
* Recommendation

---

### Task 9: Reflection

Write ~1 paragraph:

* Why deterministic encryption fails
* IND-CPA intuition
* Role of randomness
* Why hybrid encryption is used
* Key takeaways

---

## Deliverables

Submit **ONE PDF** containing:

* All tasks (1–9) clearly labeled
* Screenshots (terminal + outputs)
* Code (embedded or attached)
* Explanations + analysis

⚠️ Results must be **your own** (no sharing code, keys, outputs, or answers). 

---

## Grading Breakdown (100 pts)

* Task 1: 8
* Task 2: 12
* Task 3: 10
* Task 4: 10
* Task 5: 10
* Task 6: 10
* Task 7: 15
* Task 8: 8
* Task 9: 7
* Report Quality: 10

---

## Key Takeaways (What They Care About)

* You **implemented everything yourself**
* You **proved RSA is insecure without randomness**
* You **understand why hybrid encryption is used in practice**
* You **explain results clearly (not just screenshots)**

---
