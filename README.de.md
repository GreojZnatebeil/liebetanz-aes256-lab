# AES256 Lab (Pascal/Lazarus) — Lernprojekt mit transparenter Implementierung

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Status: Lernprojekt](https://img.shields.io/badge/Status-Lernprojekt-informational.svg)](#)

⚠️ **Wichtiger Hinweis: Lernprojekt — NICHT für produktive Verschlüsselung!**

Dieses Repository ist ein **Lehr- und Transparenzprojekt**: AES-256 wird **von Grund auf** in **Pascal/Lazarus** implementiert – bewusst **ohne externe Kryptografie-Units oder Packages**, damit jeder Schritt nachvollziehbar bleibt.

**Bitte verwende diesen Code nicht, um echte Daten zu schützen.**  
In der Praxis ist „sichere Verschlüsselung“ deutlich mehr als „AES läuft“:

- sichere **Schlüsselableitung** aus Passwörtern (KDF wie Argon2/PBKDF2, Salt, Iterationen)
- korrekte Nutzung von **IV/Nonce** und sicheren Betriebsmodi
- **Integrität & Authentizität** (AEAD/MAC) – nicht nur Vertraulichkeit
- sichere Zufallszahlen (CSPRNG), Key-/IV-Management, Fehlerbehandlung
- Side-Channel-Themen (Timing), Secure Wipe, sinnvolle Defaults
- umfangreiche Tests, Review, Interoperabilität (Testvektoren)

Wenn du „echte“ Verschlüsselung brauchst: **nutze etablierte, geprüfte Bibliotheken** (z.B. libsodium, OpenSSL, Botan oder Crypto-APIs der Plattform).

---

## Ziel dieses Repos

- **Verstehen**, wie AES-256 intern funktioniert (Round-Structure, SubBytes, ShiftRows, MixColumns, Key Schedule)
- typische Betriebsarten kennenlernen (z.B. ECB/CBC – inkl. ihrer Risiken)
- Testen mit bekannten Vektoren / nachvollziehbaren Beispielen
- saubere, didaktische Struktur für Lernende, die sich sonst in Projekten „verlieren“

---

## Quick Start (Lazarus)

1. Lazarus öffnen
2. Projekt laden: `src/aes_256.lpi`
3. Build & Run
4. Im GUI Verschlüsselung/Entschlüsselung ausprobieren und ggf. vorhandene Tests ausführen

> Hinweis: Build-Ausgaben landen typischerweise in `lib/` und gehören nicht ins Git (siehe `.gitignore`).

---
### Screenshot

![AES256 Lab GUI](assets/GUI.png)

Im Ordner `docs/` findest du eine schrittweise Einführung:

- `docs/00_Project_Map.md`
- `docs/10_AES_Introduction.md`
- `docs/20_AES_Key_Schedule.md`
- `docs/30_AES_Block_Operations.md`
- `docs/40_AES_Modes_ECB_CBC.md`
- `docs/50_Security_Notes.md`

Zusätzliche Referenzen:

- `docs/60_How_to_verify_with_test_vectors.md`
- `docs/70_Unit_Reference.md`
- `docs/80_Glossary.md`


## Projektstruktur

- `src/` — Lazarus-Projekt + Pascal-Quellcode
  - `aes_256.lpr / aes_256.lpi` — Einstieg / Projektdateien
  - `aes_256_lab_main.pas/.lfm` — GUI (Main Form)
  - `uAES256.pas` — AES-Blockfunktionen (Kern)
  - `uAES256_ECB.pas` — ECB-Modus (didaktisch, aber unsicher für reale Daten!)
  - `uAES256_CBC.pas` — CBC-Modus (didaktisch; ohne Authentizität weiterhin problematisch)
  - `uSHA256.pas` — SHA-256 (hier u.a. für einfache, didaktische Schlüsselableitung genutzt)
  - `uAES256_Container.pas` — Hilfslogik/Container (je nach Projektstand)
- `docs/` — Dokumentation / Lernpfad
- `.github/` — Issue-/PR-Templates

---

## Warum „ohne externe Crypto-Units“?

Viele Crypto-Projekte nutzen Bibliotheken, die intern sehr komplex sind (und das ist auch richtig so).  
Für Lernzwecke ist es jedoch hilfreich, eine **vollständig lesbare** Implementierung zu haben, um:

- Round-Operationen Schritt für Schritt zu verstehen
- Testvektoren nachzuvollziehen
- typische Fehler (IV/Nonce, Padding, ECB-Fallen) bewusst zu sehen
- über „Algorithmus vs. echte Sicherheit“ zu lernen

---

## Lizenz

Lizenziert unter der **GNU Affero General Public License v3.0 (AGPL-3.0)**.  
Siehe [`LICENSE`](LICENSE).

---

## Mitmachen / Contributions

Beiträge sind willkommen – besonders:
- bessere Erklärungen/Diagramme
- zusätzliche Testvektoren & Tests
- Anfängerfreundliche Verbesserungen (Quick Start, Screenshots, Glossar)

Siehe [`CONTRIBUTING.md`](CONTRIBUTING.md).

