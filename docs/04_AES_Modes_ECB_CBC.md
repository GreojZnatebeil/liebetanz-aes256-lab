# 04 — Betriebsmodi: ECB und CBC

## Warum brauchen wir Betriebsmodi?

AES verschlüsselt immer nur **16 Bytes** (1 Block).  
Für längere Daten (Texte, Dateien, Streams) braucht man Regeln, *wie* mehrere Blöcke verarbeitet werden.

Ohne geeigneten Modus entstehen schnell gravierende Sicherheitsprobleme.

---

## ECB (Electronic Codebook)

### Prinzip
Jeder Block wird **für sich** verschlüsselt:

- Klartextblock 1 → Cipherblock 1
- Klartextblock 2 → Cipherblock 2
- usw.

### Problem
**Gleiche Klartextblöcke erzeugen gleiche Chiffretextblöcke.**  
Das bedeutet: Muster bleiben sichtbar.

ECB ist deshalb für reale Daten praktisch immer ungeeignet (Bilder/Strukturen/Formatdaten).

### Lernziel in diesem Repo
ECB ist didaktisch nützlich, weil man:
- den reinen Blockalgorithmus “pur” sieht
- die Musterproblematik sehr leicht demonstrieren kann

### Im Code
- `src/uAES256_ECB.pas` enthält die ECB-Verarbeitung (Block für Block).

---

## CBC (Cipher Block Chaining)

### Prinzip (Verschlüsselung)
CBC verknüpft jeden Klartextblock mit dem vorherigen Chiffreblock:

1. `C0 = AES( P0 XOR IV )`
2. `C1 = AES( P1 XOR C0 )`
3. `C2 = AES( P2 XOR C1 )`
4. ...

Das **IV (Initialization Vector)** ist ein zusätzlicher 16-Byte Startwert.

### Entschlüsselung
1. `P0 = AES_DEC(C0) XOR IV`
2. `P1 = AES_DEC(C1) XOR C0`
3. `P2 = AES_DEC(C2) XOR C1`
4. ...

### Was CBC besser macht als ECB
- Gleiche Klartextblöcke führen nicht mehr automatisch zu gleichen Cipherblöcken,
  weil der “Kontext” (IV/previous block) unterschiedlich ist.

### Typische CBC-Fallen
CBC löst **nicht** alles:

- **Integrität fehlt:**  
  CBC alleine schützt nicht davor, dass Ciphertext manipuliert wird.
  Ohne MAC/AEAD kann man Daten verändern, ohne dass es sofort auffällt.

- **IV-Regel:**  
  Das IV muss für jede Verschlüsselung **neu** und **unvorhersehbar** sein.
  Ein wiederverwendetes oder vorhersagbares IV kann Sicherheit massiv schwächen.

- **Padding & Padding-Oracles:**  
  Wenn man Padding falsch behandelt und Fehlermeldungen “verräterisch” sind,
  können bestimmte Angriffe möglich werden.

### Lernziel in diesem Repo
CBC zeigt:
- Verkettung über IV / vorherigen Block
- warum IV-Handling wichtig ist
- warum “Verschlüsselung ≠ Sicherheit” (Integrität/Authentizität fehlt)

### Im Code
- `src/uAES256_CBC.pas` enthält die CBC-Verarbeitung.
- Achte dort auf:
  - XOR mit IV / vorherigem Cipherblock
  - Blockweise Verarbeitung in 16-Byte Schritten
  - w

