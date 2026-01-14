# AES-256-Lab (Lazarus / FreePascal)

[English](README.md) | Deutsch

## Zweck (bitte zuerst lesen)
**AES-256-Lab** ist ein Lern- und Lehrprojekt. Es zeigt Schritt für Schritt, wie man AES-256 in **Pascal (Lazarus/FreePascal)** nachvollziehbar implementieren kann – mit dem Schwerpunkt auf **Transparenz und Verständlichkeit**.

✅ Fokus: Didaktik, Nachvollziehbarkeit, lesbarer Code  
❌ Kein Produkt: **nicht** zum Schutz realer Daten verwenden

## Warum das hier keine „sichere Verschlüsselung“ ist
Ein korrekter AES-Kern ist nur ein kleiner Teil von echter, sicherer Kryptografie. In der Praxis braucht es u.a.:
- sichere Betriebsarten und **Authentifizierung** (AEAD, z.B. AES-GCM statt „nur AES“)
- sichere Zufallszahlen und korrektes IV/Nonce-Handling (Einzigartigkeit, kein Reuse)
- Side-Channel-Themen (Timing/Cache/Power)
- Schlüsselhandling (sichere Speicherung, Lebenszyklus, Zeroization, Swap vermeiden)
- Protokoll-/Dateiformatdesign (Metadaten, Versionierung, Integrität/Authentizität)
- Testvektoren, Reviews, Fuzzing und Wartung

Dieses Repo hält viele Punkte bewusst einfach, damit man die Grundlagen gut verstehen kann.

## Quick Start
- Projekt in Lazarus öffnen
- Build & Run
- Lernpfad siehe `docs/`

## Ziele
- Transparente, lesbare AES-256-Implementierung zum Lernen
- Möglichst wenig „Magie“ durch zusätzliche Abhängigkeiten
- Schritt-für-Schritt-Erklärungen (Code + `docs/`)

## Lizenz / Haftung
MIT-Lizenz. Bereitgestellt „wie gesehen“, ohne Garantie oder Haftung. Nutzung auf eigenes Risiko.

## Kontakt
jl-software@online.de
