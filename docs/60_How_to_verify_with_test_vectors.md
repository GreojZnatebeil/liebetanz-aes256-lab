# How to verify with test vectors (Known-Answer Tests)

Diese Seite beschreibt, wie man die Korrektheit einer AES-Implementierung überprüft.
In der Kryptografie sind **Known-Answer-Tests (KATs)** üblich: Für vorgegebene Eingaben muss exakt die vorgegebene Ausgabe entstehen.

> Wichtig: Testvektoren beweisen nicht “Sicherheit”, aber sie sind ein sehr starkes Signal für **Korrektheit**.

---

## 1) Was sind Testvektoren?

Ein Testvektor besteht typischerweise aus:

- Schlüssel (Key)
- Klartext (Plaintext)
- ggf. IV/Nonce (bei Betriebsmodi)
- erwarteter Chiffretext (Ciphertext)

Wenn dein Ergebnis abweicht, ist irgendwo ein Fehler:
- Key Schedule
- Round-Operationen
- Byte-Reihenfolge / State-Mapping
- Modus-Logik (XOR/IV/Chaining)
- Padding/Unpadding

---

## 2) Wo findet man offizielle AES-Testvektoren?

- **NIST** stellt umfangreiche Testdaten für AES bereit (KATs für verschiedene Modi).
- Für AES-Blocktests sind außerdem die bekannten AES-Beispielwerte aus Standard-Dokumenten verbreitet.

> Tipp: Wenn du “AES-256 Known Answer Test” oder “NIST AES KAT” suchst, findest du die offiziellen Dateien schnell.
> (Wir halten die README bewusst URL-frei kurz; wichtige Begriffe: *NIST CAVP*, *AES KAT*, *Known Answer Tests*.)

---

## 3) Was sollte dieses Repo testen?

### A) Blocktest (am wichtigsten)
- AES-256: **Key + 16-Byte Plaintext → erwarteter 16-Byte Ciphertext**
- Zusätzlich: Entschlüsselung muss wieder exakt den ursprünglichen Plaintext liefern.

Das prüft:
- Key Schedule
- Round-Implementation
- Byte-Handling / State-Mapping

### B) Mode Tests (ECB/CBC)
- Für ECB/CBC sollten vordefinierte Daten mit erwarteten Outputs getestet werden.
- Für CBC gehört ein IV dazu.

Das prüft:
- Blockkette/IV Handling
- XOR-Logik
- Block-Schleifen / Offsets

---

## 4) Wie gehe ich praktisch vor?

### Schritt 1: Testdaten vorbereiten
- Key als Hex (bei AES-256: 32 Bytes)
- Plaintext als Hex (16 Bytes)
- (CBC) IV als Hex (16 Bytes)
- erwarteter Ciphertext als Hex

### Schritt 2: Im Programm testen
Je nach GUI-Stand gibt es:
- einen “Test”-Button (z.B. “NIST Test”)
- oder die Möglichkeit, Werte einzutragen und Ergebnisse als Hex zu vergleichen

**Wichtig:**
- Vergleiche immer exakt Byte für Byte (Hex-String-Länge prüfen)
- Achte auf Groß-/Kleinschreibung nur optisch – inhaltlich ist Hex gleich

### Schritt 3: Verschlüsselung UND Entschlüsselung prüfen
- Encrypt(Key, Plain) → Cipher muss exakt passen
- Decrypt(Key, Cipher) → Plain muss exakt passen

---

## 5) Typische Fehlerbi

