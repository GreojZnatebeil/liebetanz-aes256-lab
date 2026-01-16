# AES-256-Lab (Lazarus / FreePascal)

English | [Deutsch](README.de.md)

## Important note: This is a German project
Most explanations inside the source code and the documentation are written in **German**.
For the main documentation, please start here: **[README.de.md](README.de.md)**.

## Purpose (read first)
**AES-256-Lab** is a learning and teaching project. It demonstrates an AES-256 implementation in **Pascal (Lazarus/FreePascal)** with a strong focus on **transparency and readability**.

✅ Focus: didactics, traceability, readable code  
❌ Not a product: **do not use this as a production security solution**

## What does “not secure / not for production” mean here?
This warning does **not automatically** mean that the AES-256 core is “broken”.
AES-256 is considered very strong when implemented correctly, and brute-forcing a truly random 256-bit key is infeasible.

The “not for production” statement mainly refers to the **overall system** around AES:
- password→key derivation (a fast hash like 1× SHA-256 makes weak passwords easy to guess offline; real systems use PBKDF2/Argon2/scrypt + salt)
- lack of authentication/integrity (CBC without a tag/MAC does not reliably detect tampering; real systems prefer AEAD like AES-GCM)
- correct IV/nonce handling and secure randomness
- side-channels and key handling in memory
- protocol/file-format design and error handling
- audits, test vectors, fuzzing, maintenance

This repository is a **learning lab**, not a hardened security product.

## Quick start
1. Clone or download this repository
2. Open `src/aes_256.lpi` in Lazarus
3. Build & Run

Main application form:
- `Application.CreateForm(TAES_256_Lab, AES_256_Lab)`

Project structure (main units):
- `AES_256_Lab_Main` (GUI / entry point)
- `uAES256` (AES core building blocks)
- `uAES256_ECB` (ECB mode – educational)
- `uAES256_CBC` (CBC mode – educational)
- `uAES256_Container` (container/file format helpers)
- `uSHA256` (SHA-256 used for learning/derivations in this project)

Documentation / learning path (German): see `docs/`

## Verification (NIST test vectors)
This project includes GUI buttons for **NIST Known Answer Tests (KAT)** (AES-256 single-block and AES-256 CBC with IV).
They allow anyone to quickly verify correctness against official reference values and to run a simple regression check after code changes.


## Goals
- Transparent, readable AES-256 implementation for learning
- Minimal “magic” and clear code structure
- Step-by-step explanations in code and `docs/`

## License
**GNU Affero General Public License v3 (AGPL-3.0).**  
See `LICENSE`.

## Contact
jl-software@online.de

