# 01 — AES Einführung

## Was ist AES?

**AES (Advanced Encryption Standard)** ist eine symmetrische Blockchiffre.
Symmetrisch bedeutet: **derselbe Schlüssel** wird zum Verschlüsseln und Entschlüsseln benutzt.

AES wurde von **Joan Daemen** und **Vincent Rijmen** entwickelt (Rijndael) und später als Standard veröffentlicht.

## Was bedeutet “Blockchiffre”?

AES arbeitet nicht byteweise beliebig, sondern in **festen Blöcken**:

- **AES-Blockgröße:** 128 Bit = **16 Bytes**
- Der Algorithmus transformiert immer genau **16 Bytes Klartext → 16 Bytes Chiffretext** (pro Block)

Wenn man mehr als 16 Bytes verschlüsseln möchte, braucht man einen **Betriebsmodus** (z.B. CBC/CTR/GCM) und meist auch **Padding**.

## Was bedeutet “AES-256”?

AES gibt es mit unterschiedlichen Schlüssellängen:

- AES-128 → 128-bit Schlüssel
- AES-192 → 192-bit Schlüssel
- **AES-256 → 256-bit Schlüssel** (32 Bytes)

Wichtig: **Die Blockgröße bleibt immer 128 Bit**, nur die Schlüssellänge ändert sich.
Bei AES-256 gibt es außerdem mehr Runden (Rounds) als bei AES-128.

## Warum gibt es Betriebsmodi?

Wenn du einfach Block für Block verschlüsselst, bekommst du ohne zusätzlichen Modus oft gefährliche Effekte:
Gleiche Klartextblöcke erzeugen gleiche Chiffretextblöcke → Muster bleiben sichtbar.

Darum gibt es Betriebsmodi, die Blöcke “verknüpfen” oder “mischen”, z.B.:

- **ECB** (einfach, aber unsicher bei strukturierten Daten)
- **CBC** (verkettet Blöcke über ein IV)
- **CTR/GCM** (stream-artig / AEAD)

Dieses Projekt zeigt ECB/CBC als Lernbeispiele (mit klaren Hinweisen zu den Grenzen).

## Was dieses Projekt bewusst NICHT ist

Dieses Repo ist ein **Lernprojekt**. Es zeigt den Algorithmus transparent.
Es ersetzt **keine** geprüfte Security-Library.

Für echte Sicherheit braucht man zusätzlich u.a.:
- KDF statt “Passwort → Hash → Key”
- Authentizität/Integrität (AEAD/MAC)
- korrekte IV/Nonce-Regeln
- sichere Zufallszahlen und Schlüsselmanagement

Siehe dazu später: **05 — Security Notes**.

## Wo im Code?

- GUI / Einstieg: `src/aes_256_lab_main.pas`
- AES-Kern: `src/uAES256.pas`
- Modi: `src/uAES256_ECB.pas`, `src/uAES256_CBC.pas`
- SHA-256: `src/uSHA256.pas`

