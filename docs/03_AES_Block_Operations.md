# 03 — AES Block Operationen (State & Rounds)

## Der AES “State” (16 Bytes)

AES arbeitet intern mit einem **State** aus 16 Bytes (128 Bit).
Man kann ihn sich als 4×4 Byte-Matrix vorstellen:

- 16 Bytes werden in eine Matrix “einsortiert”
- Operationen arbeiten auf Bytes, Zeilen oder Spalten

Wichtig: Im Code siehst du das oft als:
- Array[0..15] (lineare Darstellung)
- oder als 4×4 Struktur / Umrechnung zwischen beiden

## Die Round-Struktur (grob)

AES besteht aus:
1. **Initial AddRoundKey**
2. **(Nr-1) Standard-Rounds**
3. **Final Round** (ohne MixColumns)

Bei AES-256 ist `Nr = 14`.

## Die vier Kernoperationen

### 1) SubBytes
Jedes Byte wird durch die **S-Box** ersetzt.
- Nichtlinearität (wichtig gegen viele Angriffe)
- Im Code erkennbar: Lookup-Tabelle (SBox) und Schleife über 16 Bytes

### 2) ShiftRows
Die “Zeilen” im State werden zyklisch verschoben.
- sorgt für Diffusion zwischen Spalten
- Im Code erkennbar: Byte-Umordnungen, oft harte Indizes/Swaps

### 3) MixColumns
Die “Spalten” werden in GF(2^8) gemischt.
- starke Diffusion
- Im Code erkennbar: Multiplikationen/Operationen mit Konstanten (z.B. 2,3) in einem endlichen Feld

**Hinweis:** In der Final Round fehlt MixColumns absichtlich.

### 4) AddRoundKey
State wird mit Round Key XOR-verknüpft.
- sehr schnell, aber extrem wichtig
- Im Code erkennbar: XOR Schleife über 16 Bytes

## Warum fehlt MixColumns in der letzten Runde?

Das gehört zur AES-Definition:
- Final Round: SubBytes → ShiftRows → AddRoundKey
- Dadurch bleibt die Entschlüsselung strukturell passend und effizient

## Wo ist das im Code?

In `src/uAES256.pas` findest du typischerweise:
- S-Box Tabellen (SBox / InvSBox)
- Prozeduren wie `SubBytes`, `ShiftRows`, `MixColumns`, `AddRoundKey`
- Eine zentrale Funktion wie `EncryptBlock` / `DecryptBlock`, die die Runden aufruft

**Pro-Tipp zum Lesen:**
- Suche zuerst nach der Blockfunktion (Encrypt/Decrypt)
- Dann springe in die aufgerufenen Round-Operationen
- Notiere dir: welche Operationen in welcher Reihenfolge kommen
- Prüfe, ob die letzte Runde MixColumns überspringt

## Mini-Übung (optional)

1. Finde im Code die Blockverschlüsselung.
2. Zähle, wie viele Runden durchlaufen werden (sollte bei AES-256 = 14 sein).
3. Prüfe, ob die Reihenfolge pro Runde stimmt:
   - SubBytes
   - ShiftRows
   - MixColumns (außer final)
   - AddRoundKey

Im nächsten Kapitel (04) schauen wir uns an, warum man **Betriebsmodi** braucht und was ECB/CBC konkret tun.

