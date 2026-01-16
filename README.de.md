# AES-256-Lab (Lazarus / FreePascal)

[English](README.md) | Deutsch

## Zweck (bitte zuerst lesen)
**AES-256-Lab** ist ein Lern- und Lehrprojekt. Es zeigt Schritt für Schritt, wie man AES-256 in **Pascal (Lazarus/FreePascal)** nachvollziehbar implementieren kann – mit dem Schwerpunkt auf **Transparenz und Verständlichkeit**.

✅ Fokus: Didaktik, Nachvollziehbarkeit, lesbarer Code  
❌ Kein Produkt: **nicht als „Sicherheitslösung“ in Produktion verwenden**

## Was bedeutet „nicht sicher“ in diesem Projekt?
Wichtig: Die Aussage „nicht sicher / nicht für Produktion“ bezieht sich in diesem Repository **nicht automatisch** darauf, dass AES-256 „kaputt“ oder „fehlerhaft“ wäre.

### AES-256 und Brute-Force
AES-256 gilt (bei korrekter Implementierung) als sehr stark.  
Mit einem **wirklich zufälligen 256-Bit Schlüssel** ist Brute-Force praktisch unmöglich (astronomische Zeiträume).

Auch mit einem **starken, zufälligen Passwort** kann ein Offline-Angriff unrealistisch werden – die Angriffszeit hängt dann fast vollständig von der Passwort-Entropie ab.

### Wo die „Unsicherheit“ in Lern-/Eigenbauprojekten typischerweise herkommt
In realen Systemen entscheidet nicht nur der AES-Kern, sondern das Gesamtpaket. Typische Punkte sind:
- **Passwort→Key Ableitung (KDF):** Einfache/“schnelle” Ableitungen (z.B. 1× SHA-256) machen schwache Passwörter schnell erratbar. In der Praxis nutzt man PBKDF2/Argon2/scrypt mit Salt und vielen Iterationen.
- **Keine Authentifizierung/Integrität:** Reine Verschlüsselung (z.B. AES-CBC ohne Tag/MAC) erkennt Manipulation nicht zuverlässig. Praxis: AEAD (z.B. AES-GCM) oder mindestens MAC/Tag.
- **IV/Nonce-Regeln & Zufallszahlen:** IV/Nonce müssen korrekt erzeugt und korrekt verwendet werden (z.B. nie wiederverwenden, wo es verboten ist). RNG-Qualität ist entscheidend.
- **Side-Channels & Memory Handling:** Timing/Cache-Effekte, Schlüssel im RAM, Swap/Crashdumps, Logging, UI-Kopierpuffer usw.
- **Protokoll-/Dateiformatdesign:** Metadaten, Versionierung, Fehlerbehandlung – hier entstehen oft echte Sicherheitslücken.
- **Audits, Tests, Wartung:** Produktionscode braucht Reviews, Testvektoren, Fuzzing, Updates.

### Fazit
Dieses Projekt ist ein **Lernlabor**: Transparenz und Verständnis stehen im Vordergrund.  
Die Warnung „nicht für Produktion“ bedeutet: **Nicht als Sicherheitsprodukt verwenden**, selbst wenn der AES-Kern korrekt ist.

## Quick Start
1. Repository klonen oder als ZIP herunterladen
2. In Lazarus `src/aes_256.lpi` öffnen
3. Build & Run

Hauptformular:
- `Application.CreateForm(TAES_256_Lab, AES_256_Lab)`

Projektstruktur (wichtige Units):
- `AES_256_Lab_Main` (GUI / Einstieg)
- `uAES256` (AES-Kernbausteine)
- `uAES256_ECB` (ECB-Modus – didaktisch)
- `uAES256_CBC` (CBC-Modus – didaktisch)
- `uAES256_Container` (Container-/Dateiformat-Helfer)
- `uSHA256` (SHA-256 für Lernzwecke/Herleitungen im Projekt)

Doku / Lernpfad: siehe `docs/`

## Verifikation (NIST Testvektoren)
Das Projekt enthält GUI-Buttons für **NIST Known Answer Tests (KAT)** (AES-256 Single-Block und AES-256 CBC mit IV).
Damit kann jeder schnell überprüfen, ob die Implementierung für offizielle Referenzwerte korrekt arbeitet – und nach Änderungen am Code sofort einen Regressions-Test machen.

## Ziele
- Transparente, lesbare AES-256-Implementierung zum Lernen
- Möglichst wenig „Magie“ durch zusätzliche Abhängigkeiten
- Schritt-für-Schritt-Erklärungen (Code + `docs/`)

## Lizenz
**GNU Affero General Public License v3 (AGPL-3.0).**  
Siehe `LICENSE`.

## Kontakt
jl-software@online.de

