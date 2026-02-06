# 05 — Security Notes (Warum das kein Produktiv-Crypto ist)

Diese Seite erklärt, warum dieses Repository ein **Lernprojekt** ist und warum man so etwas **nicht 1:1** als echtes Verschlüsselungsprogramm verwenden sollte.

AES als Algorithmus ist stark – aber **Sicherheit im echten Leben** ist viel mehr als “AES funktioniert”.

---

## 1) Algorithmus vs. System-Sicherheit

Eine Verschlüsselungslösung besteht nicht nur aus dem Blockalgorithmus (AES), sondern aus einem ganzen System:

- Schlüssel entstehen irgendwo (Passwort? Datei? Hardware?)
- Daten haben Struktur (Header, Formate, Wiederholungen)
- Angreifer können manipulieren, wiederholen, ausprobieren
- Fehlerbehandlung verrät oft Informationen
- Zufallszahlen müssen wirklich gut sein

Ein einzelner korrekter AES-Blockcode macht noch kein sicheres Produkt.

---

## 2) Passwort → Schlüssel: SHA-256 reicht nicht

In Lernprojekten ist “Passwort → SHA-256 → Key” leicht zu verstehen, aber für echte Systeme ist das zu schwach:

- Passwörter sind oft kurz / erratbar
- Angreifer nutzen GPU/ASIC und testen Milliarden Hashes pro Sekunde

**In echten Systemen nutzt man KDFs (Key Derivation Functions)**:
- PBKDF2 (weit verbreitet)
- Argon2 (modern, memory-hard)
- scrypt (memory-hard)

Und immer mit:
- **Salt** (gegen Rainbow Tables)
- sinnvollen Parametern (Iterationen/Memory/Time)

---

## 3) Vertraulichkeit ohne Integrität ist gefährlich

Viele denken: “Verschlüsselt = sicher”.  
Aber ohne **Integrität/Authentizität** kann ein Angreifer den Ciphertext manipulieren.

Beispiele:
- Bitflips in CBC können gezielt Klartextbits beeinflussen
- Fehlermeldungen bei Padding können Informationen leaken (Padding Oracle)

**Moderne Empfehlung:** AEAD (Authenticated Encryption with Associated Data)
- AES-GCM
- ChaCha20-Poly1305

AEAD liefert:
- Vertraulichkeit **und** Integrität in einem Verfahren

---

## 4) IV/Nonce Regeln (häufigste Fehlerquelle)

Viele Modi benötigen ein IV/Nonce. Fehler hier sind extrem häufig:

- **IV/Nonce wiederverwenden** kann Sicherheit brechen
- IV/Nonce muss je nach Modus:
  - zufällig und unvorhersehbar sein (z.B. CBC)
  - oder einzigartig/never-repeat (z.B. CTR/GCM)

Ein “konstantes IV” ist fast immer falsch (außer in klar definierten Testfällen).

---

## 5) Zufallszahlen (CSPRNG)

Für IVs/Nonces/Salts braucht man einen **kryptografisch sicheren Zufallszahlengenerator** (CSPRNG).

Typische Probleme:
- normale PRNGs (oder “Random()”) sind nicht sicher
- zu wenig Entropie / falsche Initialisierung
- Plattform-Unterschiede

---

## 6) Side-Channels & Implementierungsdetails

Selbst wenn mathematisch alles korrekt ist, kann die Implementierung leaken:

- Timing-Unterschiede
- Speicherzugriffsmuster
- Debug-Ausgaben / Logs
- Compiler-Optimierungen

Professionelle Libraries investieren sehr viel Aufwand, um solche Effekte zu reduzieren.

---

## 7) Tests sind Pflicht (und “funktioniert bei mir” reicht nicht)

Für Kryptocode sind **Known-Answer-Tests** (z.B. NIST-Testvektoren) entscheidend:

- prüfen, ob AES wirklich korrekt implementiert ist
- verhindern “fast richtig” (was in Crypto oft komplett falsch ist)

Dieses Repo nutzt/zeigt Tests zu Lernzwecken.

---

## Fazit

Dieses Projekt ist ideal, um **AES zu verstehen**.  
Es ist nicht geeignet als Basis für “echte Sicherheit”.

Wenn du echte Verschlüsselung brauchst:
- nutze etablierte Bibliotheken
- nutze AEAD-Verfahren
- nutze KDFs für Passwörter
- nutze sichere Randomness und sauberes Key-Management

