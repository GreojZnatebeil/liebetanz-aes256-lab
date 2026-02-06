# Roadmap — AES256 Lab (Educational)

Dieses Projekt ist ein Lernprojekt. Die Roadmap priorisiert daher:
1) **Verständlichkeit**
2) **Reproduzierbarkeit (Tests)**
3) **Einsteigerfreundlichkeit (Docs/Struktur)**
… vor Micro-Optimierungen.

## Near-term (Next)

- [ ] **Docs polish**
  - [ ] Glossar (Begriffe wie Block, Round, IV/Nonce, Padding, AEAD)
  - [ ] 1–2 GUI-Screenshots ins README (unter `assets/`)
  - [ ] Diagramm: AES Round-Flow (optional)

- [ ] **Testing / Correctness**
  - [ ] Mehr Known-Answer-Tests (NIST Testvektoren) dokumentieren
  - [ ] “How to verify” Abschnitt in den Docs (wie man Ergebnisse gegen Referenzen prüft)

- [ ] **Beginner-friendly Issues**
  - [ ] 5–10 kleine Issues als `good first issue` definieren (Docs, Screenshots, kleine Tests)
  - [ ] Kurze “Definition of Done” für PRs in CONTRIBUTING (bereits enthalten, ggf. ergänzen)

## Mid-term

- [ ] **Mode coverage (educational)**
  - [ ] Klarer Vergleich: ECB vs CBC (inkl. typische Fehlerbilder)
  - [ ] Optional: CTR-Modus als Lernbeispiel (mit deutlichen Security Notes)

- [ ] **Security Notes erweitern (ohne falsche Sicherheit zu suggerieren)**
  - [ ] KDF-Vertiefung (Salt/Iteration/Memory-hard)
  - [ ] Warum “Encrypt-then-MAC” / AEAD wichtig ist
  - [ ] IV/Nonce Wiederverwendung: Beispiele, warum das kaputt geht

## Long-term (Optional)

- [ ] **Interop / Cross-checks**
  - [ ] Vergleich gegen bekannte Bibliotheken (nur als Validierung, nicht als Abhängigkeit)
  - [ ] Dokument: “Welche Teile sind absichtlich vereinfacht?”

- [ ] **Code readability**
  - [ ] Einheitliche Kommentarstruktur (didaktischer Stil)
  - [ ] Kleine Refactorings, wenn sie Lesbarkeit verbessern (keine “Magic Optimizations”)

---

## Contribution ideas

Wenn du helfen willst, aber nicht weißt womit:
- Screenshots & Docs sind extrem wertvoll
- Tests/Testvektoren erhöhen Vertrauen in die Korrektheit
- Kleine Verbesserungen an Texten machen das Projekt für Lernende “lebendig”

