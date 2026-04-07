
---

# Team Work Split (3 People)

## 👤 Person 1 — Setup + Core RSA

**Focus: Foundation + correctness**

### Tasks

* Task 1: Setup & Messages
* Task 2: RSA Key Generation
* Task 3: Plain RSA

### Responsibilities

* Build **core RSA logic** (everyone else depends on this)
* Ensure:

  * `rsa_keygen.py` works correctly
  * keys can be reused by other scripts
* Export reusable functions:

```python
generate_keys()
encrypt(m, pub_key)
decrypt(c, priv_key)
```

### Deliverables

* `rsa_keygen.py`
* `rsa_basic.py`
* Screenshots + explanations for Tasks 1–3

---

## 👤 Person 2 — Attacks + Randomness

**Focus: Breaking RSA + showing insecurity**

### Tasks

* Task 4: Determinism
* Task 5: Guessing Attack
* Task 6: Randomized Encryption

### Responsibilities

* Reuse Person 1’s RSA functions
* Show:

  * identical ciphertexts (Task 4)
  * successful guessing attack (Task 5)
  * different ciphertexts with randomness (Task 6)

### Deliverables

* `rsa_deterministic.py`
* `rsa_guess_attack.py`
* `rsa_randomized_demo.py`
* Screenshots + explanations

---

## 👤 Person 3 — Hybrid + Analysis + Report Lead

**Focus: Real-world encryption + final report**

### Tasks

* Task 7: Hybrid Encryption (RSA + AES)
* Task 8: Comparison Table
* Task 9: Reflection

### Responsibilities

* Implement AES (use `pycryptodome`)
* Combine with RSA (from Person 1)
* Build:

  * comparison table
  * final write-up structure

### Deliverables

* `hybrid_rsa_aes.py`
* Comparison table
* Reflection paragraph
* Final report assembly (PDF)

---

# GitHub Setup (Do This FIRST)

## Repo Creation

One person creates repo:

```
rsa-lab-4407
```

### Structure

```
rsa-lab-4407/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── src/
│   ├── rsa_core.py          # shared RSA functions
│   ├── task1_setup/         # optional notes
│   ├── task2_keygen/
│   ├── task3_basic/
│   ├── task4_deterministic/
│   ├── task5_attack/
│   ├── task6_randomized/
│   ├── task7_hybrid/
│
├── messages/
│   ├── msg1.txt
│   ├── msg2.txt
│   ├── msg3.txt
│
├── screenshots/
│
└── report/
    └── final_report.pdf
```

---

## Branch Strategy (IMPORTANT)

Each person works on their own branch:

* Person 1 → `feature/rsa-core`
* Person 2 → `feature/attacks`
* Person 3 → `feature/hybrid-report`

Workflow:

```bash
git checkout -b feature/rsa-core
git add .
git commit -m "Task 2: RSA keygen complete"
git push origin feature/rsa-core
```

Then:

* Open PR → merge into `main`

---

# Shared Code Skeleton (CRITICAL)

Create this FIRST → **everyone imports from it**

## `src/rsa_core.py`

```python
def generate_keys():
    # return (public_key, private_key)
    pass

def encrypt(m, pub_key):
    pass

def decrypt(c, priv_key):
    pass
```

---

## Task Script Template

Each script should follow this structure:

```python
from rsa_core import generate_keys, encrypt, decrypt

def main():
    pub, priv = generate_keys()

    message = "example"
    # convert message → int

    c = encrypt(message, pub)
    m = decrypt(c, priv)

    print("Cipher:", c)
    print("Recovered:", m)

if __name__ == "__main__":
    main()
```

---

# Report Split (to save time)

## Person 1 writes:

* Task 1–3 explanations

## Person 2 writes:

* Task 4–6 explanations

## Person 3 writes:

* Task 7–9 + intro + conclusion
* Combines everything into final PDF

---

# Timeline (Recommended)

### Day 1

* GitHub setup + skeleton
* Person 1 finishes RSA core

### Day 2

* Person 2 finishes Tasks 4–6
* Person 3 starts hybrid

### Day 3

* Finish hybrid
* Build comparison table
* Write report

---

# Key Coordination Rules (IMPORTANT)

* ✅ Everyone uses **same RSA core file**
* ✅ No duplicate implementations
* ✅ Test scripts early (don’t wait)
* ✅ Keep screenshots as you go

---

# Quick Reality Check (What gets you points)

* RSA works ✔
* You show **it’s insecure** ✔
* You fix it with randomness ✔
* You implement hybrid ✔
* You **explain everything clearly** ✔

---
