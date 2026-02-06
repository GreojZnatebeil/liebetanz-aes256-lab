# Contributing Guide

Danke, dass du helfen möchtest! Dieses Projekt ist ein **Lernprojekt**: Lesbarkeit, Nachvollziehbarkeit und didaktische Qualität sind wichtiger als “maximaler Optimierungs-Fetisch”.

## 1) Wie du lokal startest (Lazarus)

1. Repo klonen
2. Lazarus öffnen
3. Projekt laden: `src/aes_256.lpi`
4. Build & Run

Wenn Lazarus neue Build-Ordner erzeugt: diese gehören **nicht** ins Repo (siehe `.gitignore`, typischerweise `lib/`, `backup/`, `*.ppu`, `*.o` etc.).

## 2) Welche Beiträge sind besonders willkommen?

- Verbesserungen an der **Dokumentation** (`docs/`, README)
- zusätzliche **Testvektoren / Known-Answer-Tests**
- kleine Refactorings, die **Lesbarkeit** erhöhen (ohne die Didaktik zu zerstören)
- Fixes für reproduzierbare Fehler (falsche Ergebnisse, Crashes, falsche GUI-Abläufe)
- Screenshots/Diagramme, die Zusammenhänge besser erklären

## 3) Prinzipien (wichtig für dieses Repo)

- **Keine externen Crypto-Libraries/Units** hinzufügen (USP des Projekts)
- Änderungen sollen **didaktisch nachvollziehbar** bleiben
- Keine “magischen” Tricks ohne Erklärung
- Wenn du Verhalten änderst: bitte kurz dokumentieren (README oder `docs/`)

## 4) Pull Requests

Bitte achte auf Folgendes:
- Code baut unter Lazarus/FPC (wenn möglich)
- keine Build-Artefakte oder IDE-Session-Dateien committen (z.B. `*.lps`)
- PR-Beschreibung enthält:
  - **Was** wurde geändert?
  - **Warum** (Lernziel / Bugfix / Klarheit)?
  - **Wie** kann man es testen/nachstellen?

## 5) Issues

Wenn du ein Issue erstellst, hilft es sehr, wenn du dazu schreibst:
- Lazarus/FPC Version (falls bekannt)
- Betriebssystem
- Schritte zum Reproduzieren
- Erwartetes Ergebnis vs. tatsächliches Ergebnis

Danke! 🙂

