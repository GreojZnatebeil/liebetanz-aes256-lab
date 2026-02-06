# 02 — Key Schedule (Round Keys)

## Warum überhaupt “Key Schedule”?

AES verschlüsselt nicht mit dem Schlüssel “einfach so” in jeder Runde.
Stattdessen erzeugt AES aus dem ursprünglichen Schlüssel viele **Rundenschlüssel (Round Keys)**.

Warum?
- Jede AES-Runde braucht einen eigenen Schlüsselanteil (AddRoundKey).
- Dadurch wird verhindert, dass alle Runden “gleich” aussehen.
- Die Struktur bleibt effizient, aber kryptografisch stark.

## Begriffe (einmal klarziehen)

- **Key (AES-256):** 256 Bit = 32 Bytes
- **Round Key:** 16 Bytes (weil der AES-State 16 Bytes hat)
- **Words:** AES arbeitet intern oft in 32-bit Einheiten (“Words” = 4 Bytes)

Bei AES-256 gilt typischerweise:
- `Nk = 8` (8 Words Schlüsselmaterial = 32 Bytes)
- `Nb = 4` (4 Words pro Block = 16 Bytes)
- `Nr = 14` (14 Runden)

> Die exakten Konstanten findest du im Code in `uAES256.pas`.

## Was passiert im Key Schedule grob?

Aus den 8 Start-Words (AES-256) werden viele weitere Words erzeugt.
Dabei gibt es typische Bausteine:

- **RotWord**: Bytes im Word zyklisch rotieren
- **SubWord**: S-Box auf jedes Byte anwenden
- **Rcon**: Rundkonstante einmischen (pro bestimmtem Schritt)
- **XOR**: Neues Word entsteht aus XOR von vorherigem Material

Für AES-256 gibt es eine Besonderheit:
- Neben dem “Rcon-Schritt” (wie bei AES-128) gibt es zusätzliche SubWord-Schritte an anderer Stelle.
Das ist einer der Gründe, warum AES-256 Key Schedule etwas “anders” aussieht als AES-128.

## Woran erkenne ich es im Code?

Suche in `src/uAES256.pas` nach Funktionen/Prozeduren, die in diese Richtung gehen:
- Key Expansion / Key Schedule
- RotWord, SubWord
- Rcon Tabelle / Konstanten
- Schleifen, die aus `Nk` Start-Words die restlichen Words erzeugen

**Praktischer Tipp:**  
Wenn du verstehen willst, ob du gerade “Key Schedule” liest:  
Du siehst fast immer:
- Verarbeitung in 4-Byte Words
- Rotation + S-Box + Rcon (oder SubWord-only Schritte)
- XOR mit einem früheren Word

## Warum das sicherheitsrelevant ist (kurz)

Der Key Schedule sorgt dafür, dass jede Runde “frisches” Schlüsselmaterial bekommt.
Fehler im Key Schedule führen fast immer dazu, dass:
- AES-Testvektoren nicht passen
- Verschlüsselung/Entschlüsselung nicht zueinander passen
- die Siche

