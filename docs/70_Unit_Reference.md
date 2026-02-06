# Unit Reference (Code-Navigation)

Diese Seite beschreibt die wichtigsten Units im Ordner `src/` und hilft dir, schnell die richtige Stelle im Code zu finden.

> Hinweis: Funktionsnamen können je nach Projektstand leicht abweichen. Nutze bei Bedarf die Suche im Editor (`Ctrl+F`) nach den genannten Begriffen.

---

## `aes_256_lab_main.pas` (GUI / Einstieg)

**Rolle:** Main Form (GUI), Benutzeraktionen, Anzeige von Ergebnissen, Startpunkt für Tests.  
**Hier starten, wenn du das Projekt “benutzen” willst.**

Typische Inhalte:
- Button-Handler (Encrypt/Decrypt/Test)
- Ein-/Ausgabe (Hex, Text, Statusmeldungen)
- Aufruf der Funktionen aus `uAES256*` und `uSHA256`

**Suchen nach:**
- `OnClick`
- `Encrypt`
- `Decrypt`
- `Test`
- `NIST` (falls Testvektoren eingebaut sind)

---

## `uAES256.pas` (AES-Kern / Blockalgorithmus)

**Rolle:** Herzstück: AES-256 Blockverschlüsselung und -entschlüsselung (16 Byte Block), Key Schedule.  
**Hier starten, wenn du AES wirklich verstehen willst.**

Typische Inhalte:
- AES Konstanten (z.B. `Nr`, S-Box Tabellen)
- Key Expansion / Key Schedule
- Blockfunktionen (EncryptBlock / DecryptBlock)
- Round-Operationen:
  - `SubBytes` / `InvSubBytes`
  - `ShiftRows` / `InvShiftRows`
  - `MixColumns` / `InvMixColumns`
  - `AddRoundKey`

**Suchen nach:**
- `SBox`, `InvSBox`
- `KeySchedule`, `KeyExpansion`, `ExpandKey`
- `EncryptBlock`, `DecryptBlock`
- `MixColumns`, `ShiftRows`

---

## `uAES256_ECB.pas` (Betriebsmodus: ECB)

**Rolle:** ECB-Modus als didaktisches Beispiel (Block für Block).  
**Wichtig:** ECB ist für reale Daten unsicher (Muster bleiben sichtbar).

Typische Inhalte:
- Schleife über 16-Byte Blöcke
- ggf. Padding/Unpadding (abhängig von deinem Stand)
- Aufrufe von AES Blockfunktionen aus `uAES256.pas`

**Suchen nach:**
- `ECB`
- `Pad`, `Unpad`, `Padding`
- `Block`, `NumBlocks`

---

## `uAES256_CBC.pas` (Betriebsmodus: CBC)

**Rolle:** CBC-Modus als didaktisches Beispiel (Verkettung).  
CBC nutzt ein **IV (16 Bytes)** und verknüpft Blöcke per XOR.

Typische Inhalte:
- XOR mit IV bzw. vorherigem Cipherblock
- Blockweise Verarbeitung
- IV-Handling (Generierung/Übergabe/Anzeige)
- ggf. Padding/Unpadding

**Suchen nach:**
- `CBC`
- `IV`
- `Xor` / `XOR`
- `PrevBlock`
- `Pad`, `Unpad`

---

## `uSHA256.pas` (SHA-256)

**Rolle:**

