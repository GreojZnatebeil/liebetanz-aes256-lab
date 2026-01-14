# AES-256-Lab (Lazarus / FreePascal)

English | [Deutsch](README.de.md)

## Purpose (read first)
**AES-256-Lab** is a learning and teaching project. It demonstrates an AES-256 implementation in Pascal (Lazarus/FreePascal) with a strong focus on **transparency and readability**.

✅ Focus: didactics, traceability, readable code  
❌ Not a product: **do not use this to protect real data**

## Why this is NOT “secure encryption”
Correct AES code is only a small part of secure cryptography in real-world systems. Secure implementations require, among other things:
- authenticated encryption (AEAD, e.g. AES-GCM) and correct mode selection
- secure RNG and IV/nonce rules (uniqueness, reuse prevention)
- side-channel considerations (timing/cache)
- key handling (storage, memory zeroization, swap, lifecycle)
- file/protocol format design (metadata, versioning, integrity)
- extensive test vectors, reviews, fuzzing, maintenance

This repository intentionally keeps things simple to make the core concepts understandable.

## Quick start
- Open the project in Lazarus
- Build & run
- See `docs/` for the learning path

## Project goals
- No “magic” dependencies: focus on understanding the code
- Step-by-step explanations and test vectors

## License / Disclaimer
Provided “as is”, without warranty. Use at your own risk.

## Kontakt
Fragen/Feedback gerne per Mail: jl-software@online.de
