# AES-256-Lab (Lazarus / FreePascal)

[English](README.md) | Deutsch

## Zweck (bitte zuerst lesen)
**AES-256-Lab** ist ein Lern- und Lehrprojekt. Es zeigt eine AES-256-Implementierung in Pascal (Lazarus/FreePascal) – mit Fokus auf **Transparenz und Verständlichkeit**.

✅ Fokus: Didaktik, Nachvollziehbarkeit, lesbarer Code  
❌ Kein Produkt: **nicht** zum Schutz realer Daten verwenden

## Warum das hier keine „sichere Verschlüsselung“ ist
Ein korrekter AES-Kern ist nur ein kleiner Teil von echter, sicherer Kryptografie. In der Praxis braucht es u.a.:
- Authenticated Encryption (AEAD, z.B. AES-GCM) und passende Betriebsarten
- sichere Zufallszahlen + IV/Nonce-Regeln (Einzigartigkeit, kein Reuse)
- Side-Channel-Themen (Timing/Cache)
- Schlüsselhandling (Speicher, Zeroization, Swap, Lebenszyklus)
- Dateiformate/Protokolle (Metadaten, Versionierung, Integrität)
- Testvektoren, Reviews, Fuzzing, Wartung

Dieses Repo ist bewusst „einfach“ gehalten, damit die Grundlagen verständlich bleiben.

## Quick Start
- Projekt in Lazarus öffnen
- Build & Run
- Lernpfad siehe `docs/`

## Lizenz / Haftung
Bereitgestellt „wie gesehen“, ohne Garantie oder Haftung. Nutzung auf eigenes Risiko.

## Kontakt
Fragen/Feedback gerne per Mail: jl-software@online.de
