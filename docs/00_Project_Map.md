# 00 — Projektlandkarte (Project Map)

Diese Seite ist die **Landkarte** zum Repo: Wo finde ich was, und womit starte ich?

## Empfohlener Einstieg

1. **GUI starten**: `src/aes_256.lpi` in Lazarus öffnen → Build & Run  
2. **Code-Einstieg**: `src/aes_256_lab_main.pas` (GUI-Logik, Buttons, Tests)
3. **AES-Kern verstehen**: `src/uAES256.pas` (Blockfunktionen + Key Schedule)
4. **Betriebsmodi**:
   - `src/uAES256_ECB.pas` — ECB (didaktisch, aber unsicher)
   - `src/uAES256_CBC.pas` — CBC (didaktisch; ohne Authentizität weiterhin problematisch)
5. **Hash**: `src/uSHA256.pas` (SHA-256, u.a. für didaktische Schlüsselableitung)

## Datei- und Unit-Übersicht

### `aes_256_lab_main.pas/.lfm`
- GUI (Main Form), Benutzeraktionen, Anzeige von Ergebnissen
- Startpunkt für “Wie bediene ich das Projekt?”

### `uAES256.pas`
- AES-Blockalgorithmus (AES-256): Round-Operationen und Key Schedule
- Kernlogik: hier passiert die eigentliche AES-Transformation

### `uAES256_ECB.pas`
- ECB-Modus (Electronic Codebook)
- Lernziel: warum ECB für reale Daten ungeeignet ist (Muster bleiben sichtbar)

### `uAES256_CBC.pas`
- CBC-Modus (Cipher Block Chaining)
- Lernziel: Verkettung über IV und vorherigen Block, aber ohne MAC/AEAD fehlt Integrität

### `uSHA256.pas`
- SHA-256 Implementierung
- Hinweis: Für echte Systeme ist Passwort→Key per SHA-256 zu simpel; KDF wäre nötig (siehe Security Notes)

### `uAES256_Container.pas`
- Hilfslogik/Container (projektabhängig)
- Hier sammeln sich oft “Glue Code” und gemeinsame Strukturen

## Wie der Lernpfad in `docs/` zu lesen ist

- `01...05` erklären die Konzepte (AES, Key Schedule, Rounds, Modi, Security Notes)
- Diese Datei (`00`) hilft dir dabei, die Konzepte direkt im Quellcode wiederzufinden

## Hinweis zur Sicherheit

Dieses Repo ist ein Lernprojekt. Details, was für echte Sicherheit zusätzlich nötig wäre,
stehen in `05_Security_Notes.md`.

