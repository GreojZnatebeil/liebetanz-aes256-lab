# src — Lazarus/FreePascal Sources

Dieser Ordner enthält das Lazarus-Projekt und den kompletten Pascal-Quellcode.

## Quick Start

1. Lazarus öffnen
2. Projekt laden: `aes_256.lpi`
3. Build & Run

## Wichtige Dateien

- `aes_256.lpi` / `aes_256.lpr` — Lazarus-Projekt / Einstieg
- `aes_256_lab_main.pas/.lfm` — GUI (Main Form)
- `uAES256.pas` — AES-Kern (Blockalgorithmus + Key Schedule)
- `uAES256_ECB.pas` — ECB-Modus (didaktisch, aber unsicher)
- `uAES256_CBC.pas` — CBC-Modus (didaktisch)
- `uSHA256.pas` — SHA-256 (Lernzwecke, z.B. einfache Schlüsselableitung)

## Hinweis

Build-Ausgaben (z.B. `lib/`, `*.ppu`, `*.o`) gehören nicht ins Repo. Siehe `.gitignore` im Projektroot.

