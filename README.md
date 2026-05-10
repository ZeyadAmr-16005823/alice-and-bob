<div align="center">

# 🔐 alice-and-bob

**A secure file transmission system combining Diffie-Hellman key exchange with RSA digital signatures.**

Modelled after real-world protocols like HTTPS — built as part of a Network Security course.

<br/>

![Python](https://img.shields.io/badge/Python-3.x-3776AB?style=for-the-badge&logo=python&logoColor=white)
![VSCode](https://img.shields.io/badge/VSCode-Editor-007ACC?style=for-the-badge&logo=visualstudiocode&logoColor=white)
![Cryptography](https://img.shields.io/badge/Crypto-RSA%20%2B%20DH%20%2B%20AES-6A0DAD?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow?style=for-the-badge)

</div>

---

## 📖 Overview

**Alice** is a mobile banking client. **Bob** is a bank server. Alice needs to transmit sensitive financial data to Bob over a public, untrusted network — where attackers may intercept, modify, or impersonate messages.

This system guarantees:

- 🔑 &nbsp;A shared secret key established **without prior exchange** — via Diffie-Hellman
- 🪪 &nbsp;**Mutual authentication** against man-in-the-middle attacks — via RSA signatures
- 🔒 &nbsp;**Encrypted and integrity-protected** data transmission — via AES + RSA signing

---

## 🔄 Protocol Flow

```
Alice (Client)                                    Bob (Server)
     │                                                 │
     │  ◄──── Bob's DH public value + RSA sig ───────  │
     │  ✔ Verify Bob's signature                       │
     │                                                 │
     │  ────  Alice's DH public value + RSA sig ──────►│
     │                         ✔ Verify Alice's sig    │
     │                                                 │
     │       ══ Both derive shared session key ══      │
     │              via KDF(DH shared secret)          │
     │                                                 │
     │  ────  Encrypted file + RSA signature  ────────►│
     │                         ✔ Verify & Decrypt      │
```

<details>
<summary><b>📋 Step-by-step breakdown</b></summary>
<br/>

| Step | Actor | Action |
|:----:|-------|--------|
| 1 | Alice & Bob | Perform **Diffie-Hellman key exchange** — agree on public parameters `p` and `g`, compute public values |
| 2 | Bob | Signs his DH public value with his **RSA private key**, sends it to Alice |
| 3 | Alice | Verifies Bob's signature using **Bob's RSA public key** |
| 4 | Alice | Signs her DH public value with her **RSA private key**, sends it to Bob |
| 5 | Bob | Verifies Alice's signature using **Alice's RSA public key** |
| 6 | Both | Pass the DH shared secret through a **KDF** to derive a symmetric AES session key |
| 7 | Alice | Encrypts the transactions file with **AES**, signs the ciphertext with her RSA key, sends both |
| 8 | Bob | Verifies Alice's signature, **decrypts the file** |

</details>

---

## 🛠️ Cryptographic Techniques

| Technique | Role |
|-----------|------|
| ![DH](https://img.shields.io/badge/Diffie--Hellman-Key%20Exchange-0F6E56?style=flat-square) | Establishes a shared secret over a public channel without transmitting the secret |
| ![RSA](https://img.shields.io/badge/RSA-Digital%20Signatures-534AB7?style=flat-square) | Authenticates both parties and prevents man-in-the-middle attacks |
| ![AES](https://img.shields.io/badge/AES-Symmetric%20Encryption-D85A30?style=flat-square) | Encrypts the transactions file using the derived session key |
| ![KDF](https://img.shields.io/badge/KDF-Key%20Derivation-185FA5?style=flat-square) | Derives a valid, correctly-sized key from the raw DH shared secret |

---

## 📁 Project Structure

```
alice-and-bob/
│
├── 📂 src/
│   ├── rsa_encrypt.py          # Ziad   — RSA key generation & signing
│   ├── rsa_decrypt.py          # Ahmed  — RSA verification & AES decryption
│   ├── diffie_hellman.py       # Youssef — DH exchange, KDF & AES encryption
│   └── key_manager.py          # Marawan — key serialization & exchange
│
├── 📂 output/
│   ├── transactions.enc        # Encrypted transactions file
│   └── transactions.dec        # Decrypted transactions file
│
├── main.py                     # Entry point — runs the full protocol
└── 📄 README.md
```

---

## ⚙️ Setup

**Prerequisites:** Python 3.x

This project uses **`pycryptodome`** — it provides dedicated, easy-to-use classes for everything needed: RSA, AES, DH, and KDF.

```bash
pip install pycryptodome
```

> [!WARNING]
> Install `pycryptodome`, **not** `pycrypto` — that package is outdated, unmaintained, and incompatible.

> [!NOTE]
> All team members must use the same library to ensure compatibility. Do **not** mix `pycryptodome` with the `cryptography` package.

### Key modules used

| Module | Purpose |
|--------|---------|
| `Crypto.PublicKey.RSA` | RSA key generation |
| `Crypto.Signature.pkcs1_15` | RSA signing & verification |
| `Crypto.Cipher.AES` | Symmetric encryption/decryption |
| `Crypto.Protocol.KDF` | Key derivation from DH shared secret |
| `Crypto.Hash.SHA256` | Hashing |

---

## 🚀 Usage

Clone the repo and run the main script:

```bash
git clone https://github.com/your-team/alice-and-bob.git
cd alice-and-bob
python main.py
```

> The script runs the full protocol end-to-end — key generation, DH exchange, signing, encryption, verification, and decryption — printing the result of each step.

---

## 👥 Team

| Member | Area | Responsibilities |
|--------|------|-----------------|
| Ziad Amr | RSA — Encryption | RSA key pair generation, `sign()` method |
| Ahmed Bahaa | RSA — Decryption | `verify()` method, AES decryption, final decrypted file |
| Youssef Hassan | Diffie-Hellman | DH exchange, KDF, AES encryption, encrypted file |
| Marawan Elgendy | Key Management & Integration | RSA key serialization, Alice/Bob key exchange, notebook assembly & submission |

---

## 📚 Assignment

> **Course:** Network Security  
> **Assignment:** #2 — Diffie-Hellman with RSA Authentication  
> **Deadline:** Monday, 11th May 2026

---

<div align="center">

*Built with 🔐 by the alice-and-bob team*

</div>
