# Glossary (Begriffe)

Kurzes Glossar zu den wichtigsten Begriffen im AES256 Lab.

---

## AEAD
**Authenticated Encryption with Associated Data**: Verschlüsselung, die gleichzeitig **Vertraulichkeit und Integrität** liefert (z.B. AES-GCM, ChaCha20-Poly1305).

## Block
Feste Datenmenge, die eine Blockchiffre in einem Schritt verarbeitet.  
Bei AES: **16 Bytes (128 Bit)**.

## Blockchiffre
Verschlüsselt Daten blockweise mit einem Schlüssel (AES ist eine Blockchiffre).

## CBC
**Cipher Block Chaining**: Modus, der Blöcke verkettet (`P XOR prev`), startet mit einem **IV**.

## Ciphertext
Der verschlüsselte Text (Ausgabe der Verschlüsselung).

## CSPRNG
Kryptografisch sicherer Zufallszahlengenerator (wichtig für IV/Nonce/Salt).

## ECB
**Electronic Codebook**: Modus, der jeden Block unabhängig verschlüsselt.  
Unsicher, weil Muster sichtbar bleiben.

## Integrität
Schutz davor, dass Daten unbemerkt verändert werden können.  
Ohne Integrität kann Ciphertext manipuliert werden.

## IV
**Initialization Vector**: Startwert (meist 16 Bytes bei AES), der in Modi wie CBC genutzt wird.  
Muss je nach Modus neu/zufällig/unikat sein.

## KAT
**Known-Answer Test**: Test mit festen Eingaben und erwarteten Ausgaben zur Korrektheitsprüfung.

## KDF
**Key Derivation Function**: Wandelt ein Passwort in einen Schlüssel um (z.B. PBKDF2, Argon2, scrypt).  
Besser als “Passwort → SHA-256 → Key”.

## Key Schedule / Key Expansion
Prozess, der aus dem AES-Schlüssel die **Round Keys** erzeugt.

## Klartext (Plaintext)
Unverschlüsselte Eingabedaten.

## MAC
**Message Authentication Code**: Prüfsumme zur Integrität/Authentizität (z.B. HMAC).  
Oft genutzt als “Encrypt-then-MAC”.

## Nonce
“Number used once”. Wert, der **nicht wiederverwendet** werden darf (je nach Modus).  
Bei AEAD/CTR/GCM kritisch.

## Padding
Auffüllen von Daten, wenn die Länge kein Vielfaches der Blockgröße ist (bei AES: 16 Bytes).  
Fehler hier können zu Sicherheitsproblemen führen (Padding Oracles).

## Round
Eine AES-Runde ist eine Folge fester Operationen (SubBytes, ShiftRows, MixColumns, AddRoundKey).  
AES-256 hat **14 Runden**.

## Round Key
16-Byte Schlüsselmaterial, das pro Runde per AddRoundKey eingemischt wird.

## S-Box
Substitutionstabelle in AES, sorgt für Nichtlinearität (wichtig für Sicherheit).

## State
Der interne 16-Byte Zustand (oft als 4×4 Byte-Matrix beschrieben), der pro Round transformiert wird.

