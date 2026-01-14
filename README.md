# AES-256-Lab (Lazarus / FreePascal)
Transparent AES-256 learning implementation in Lazarus/FreePascal (German project, educational only).

English | [Deutsch](README.de.md)

## Important note: This is a German project
Most explanations inside the source code and the documentation are written in **German**.
If you are looking for the main documentation, please start here: **[README.de.md](README.de.md)**.

## Purpose (read first)
**AES-256-Lab** is a learning and teaching project. It demonstrates how an AES-256 implementation can be built step by step in **Pascal (Lazarus/FreePascal)** with a strong focus on **transparency and readability**.

✅ Focus: didactics, traceability, readable code  
❌ Not a product: **do not use this to protect real data**

## Why this is NOT “secure encryption”
Even if the AES core looks correct, real-world secure encryption requires much more than implementing AES:
- correct and safe modes of operation (prefer **authenticated encryption / AEAD**, e.g. AES-GCM)
- secure random number generation and correct IV/nonce handling (uniqueness, no reuse)
- side-channel considerations (timing/cache/power)
- key handling (secure storage, lifecycle, memory zeroization, avoiding swapping)
- protocol/file format design (metadata, versioning, integrity/authentication)
- extensive test vectors, reviews, fuzzing, and long-term maintenance

This repository intentionally keeps things simple to make the core concepts understandable.

## Quick start
- Open the project in Lazarus
- Build & run
- Follow the learning path in `docs/` (German)

## Goals
- Transparent, readable AES-256 implementation for learning
- Minimal dependencies (avoid “magic” wherever possible)
- Documentation and step-by-step explanations

## License / Disclaimer
MIT License. Provided “as is”, without warranty. Use at your own risk.

## Contact
jl-software@online.de
