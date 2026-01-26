unit uAES256_ECB;

{$mode objfpc}{$H+}

interface
   (*
  ----------------------------------------------------------------------------
  AES-Projekt / Lazarus / FreePascal – ECB-Modus (separierte Unit)
  ----------------------------------------------------------------------------
  Diese Unit enthält ausschließlich ECB-spezifische Funktionen.
  Der Code wurde aus uAES256 ausgelagert, um das Projekt für Lehrzwecke
  übersichtlicher zu machen.

  Teile dieses Codes wurden unter Verwendung eines KI-basierten Assistenten
  (ChatGPT – Modell GPT-5.1) generiert und anschließend von
      Jörg Liebetanz
  überprüft, angepasst, erweitert und getestet.

  Datum der letzten Erstellung/Überarbeitung: 2025-11-20
  ----------------------------------------------------------------------------
*)

uses
  SysUtils,
  uAES256;                              // Core-Unit: Typen + Blockfunktionen

function AES256EncryptECB(const PlainData: TBytes; const Context: TAES256Context): TBytes;
  // Verschlüsselt beliebige Daten im ECB-Modus (Daten müssen vorher gepaddet werden)

function AES256DecryptECB(const CipherData: TBytes; const Context: TAES256Context): TBytes;
  // Entschlüsselt Daten im ECB-Modus. CipherData-Länge muss Vielfaches von 16 sein.

implementation

function AES256EncryptECB(const PlainData: TBytes; const Context: TAES256Context): TBytes;

{
  ============================================================================
  AES256EncryptECB - Verschlüsselt Daten im ECB-Modus (Electronic Codebook)
  ============================================================================

  ZWECK:
  Verschlüsselt beliebig viele Daten im ECB-Modus (Electronic Codebook Mode).
  Dies ist der einfachste Betriebsmodus für Blockchiffren, bei dem jeder
  16-Byte-Block unabhängig verschlüsselt wird.

  PARAMETER:
  - PlainData: Die zu verschlüsselnden Daten als Byte-Array (muss vorher gepaddet sein!)
  - Context: Der AES-256 Kontext mit allen vorberechneten Rundenschlüsseln

  RÜCKGABEWERT:
  - TBytes: Die verschlüsselten Daten (gleiche Länge wie PlainData)

  FEHLERBEHANDLUNG:
  - Wirft Exception, wenn PlainData leer ist
  - Wirft Exception, wenn Länge kein Vielfaches von 16 ist (Padding fehlt!)

  HINTERGRUND - Was ist ECB-Modus?

  ECB (Electronic Codebook) ist der grundlegendste Betriebsmodus:
  - Jeder 16-Byte-Block wird UNABHÄNGIG verschlüsselt
  - Gleicher Plaintext-Block → Immer gleicher Ciphertext-Block
  - Keine Verkettung zwischen Blöcken
  - Deterministisch und zustandslos

  FUNKTIONSWEISE:

  Die Daten werden in 16-Byte-Blöcke aufgeteilt:
  PlainData = [Block0, Block1, Block2, Block3, ...]

  Jeder Block wird einzeln verschlüsselt:
  CipherBlock0 = AES_Encrypt(Block0, Key)
  CipherBlock1 = AES_Encrypt(Block1, Key)
  CipherBlock2 = AES_Encrypt(Block2, Key)
  ...

  Keine Abhängigkeiten zwischen Blöcken:
  → Block1 beeinflusst nicht Block2
  → Blöcke können parallel verschlüsselt werden
  → Sehr schnell in Hardware

  VISUAL - ECB vs CBC:

  ECB:
  Plain[0] → [Encrypt] → Cipher[0]
  Plain[1] → [Encrypt] → Cipher[1]    ← Unabhängig!
  Plain[2] → [Encrypt] → Cipher[2]

  CBC (zum Vergleich):
  Plain[0] ⊕ IV → [Encrypt] → Cipher[0]
  Plain[1] ⊕ Cipher[0] → [Encrypt] → Cipher[1]    ← Abhängig!
  Plain[2] ⊕ Cipher[1] → [Encrypt] → Cipher[2]

  WARUM ECB PROBLEMATISCH IST - Die berühmte ECB-Pinguin:

  ECB hat ein FUNDAMENTALES SICHERHEITSPROBLEM:

  Gleicher Plaintext-Block → Gleicher Ciphertext-Block

  Dies führt zu:
  1. MUSTERERKENNUNG:
     → Wiederholende Muster im Plaintext bleiben sichtbar
     → Angreifer können Struktur erkennen

  2. KEINE DIFFUSION ZWISCHEN BLÖCKEN:
     → Änderung in Block 1 beeinflusst Block 2 nicht
     → Schwächere Sicherheit als verkettete Modi

  3. REPLAY-ANGRIFFE:
     → Angreifer können Blöcke kopieren und neu anordnen
     → Blöcke können ersetzt werden

  Das berühmte "ECB-Pinguin"-Bild demonstriert dies:
  → Ein Bild eines Pinguins (z.B. Tux, das Linux-Maskottchen)
  → Mit ECB verschlüsselt
  → Die Silhouette des Pinguins bleibt erkennbar!
  → Weil gleiche Farb-Blöcke gleich verschlüsselt werden

  NIST warnt explizit: "ECB sollte NICHT für allgemeine Zwecke verwendet werden"

  WANN IST ECB AKZEPTABEL?

  ECB ist NUR sicher in sehr speziellen Fällen:

  1. EINZELNE BLÖCKE:
     → Verschlüsselung von genau 16 Bytes
     → Z.B. Verschlüsselung eines Schlüssels
     → Keine Muster möglich bei einem Block

  2. ZUFÄLLIGE DATEN:
     → Wenn Plaintext garantiert keine Muster hat
     → Z.B. bereits verschlüsselte oder komprimierte Daten
     → Aber: Warum dann nochmal verschlüsseln?

  3. LEHR-ZWECKE:
     → Zum Verstehen von AES-Grundlagen
     → Einfachste Implementierung
     → Dieser Code ist für Lehrzwecke!

  FÜR PRODUKTIVSYSTEME: CBC, CTR, GCM verwenden!

  VORAUSSETZUNG - PKCS#7 PADDING:

  PlainData MUSS vorher auf ein Vielfaches von 16 Bytes gepaddet werden:
```pascal
  PlainBytes := StringToBytesUTF8('Hallo Welt');  // 10 Bytes
  PaddedBytes := PKCS7Pad(PlainBytes, 16);        // 16 Bytes (6 Bytes Padding)
  CipherBytes := AES256EncryptECB(PaddedBytes, Ctx);
```

  Ohne Padding → Exception!

  FUNKTIONSWEISE - Die Implementierung:

  1. VALIDIERUNG:
     - Prüfen, dass Daten nicht leer sind
     - Prüfen, dass Länge Vielfaches von 16 ist

  2. BERECHNUNG:
     - Anzahl der Blöcke = DataLen div 16
     - Ergebnis-Array allokieren (gleiche Größe)

  3. SCHLEIFE über alle Blöcke:
     - Block aus PlainData extrahieren (16 Bytes)
     - AES256EncryptBlock aufrufen
     - Verschlüsselten Block ins Ergebnis kopieren

  4. RÜCKGABE:
     - Komplett verschlüsselte Daten zurückgeben

  BEISPIEL MIT 3 BLÖCKEN:

  PlainData (48 Bytes = 3 Blöcke):
  [00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF]  ← Block 0
  [00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF]  ← Block 1 (identisch!)
  [FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00]  ← Block 2

  Nach ECB-Verschlüsselung:
  [7A 3F 2E D1 9C B4 8A 5E ...]  ← Cipher 0
  [7A 3F 2E D1 9C B4 8A 5E ...]  ← Cipher 1 (identisch! ECB-Problem!)
  [B3 C8 91 4A 6F D2 E5 73 ...]  ← Cipher 2

  → Block 0 und 1 waren gleich → Cipher 0 und 1 sind gleich
  → ECB-Schwäche sichtbar!

  PERFORMANCE:

  ECB ist der schnellste Betriebsmodus:
  - Keine zusätzlichen XOR-Operationen (wie bei CBC)
  - Blöcke können PARALLEL verarbeitet werden
  - Optimal für Hardware-Beschleunigung
  - In Multi-Core CPUs: Perfekte Parallelisierung möglich

  Typisch: 10-20% schneller als CBC

  PARALLELISIERUNG:

  Da Blöcke unabhängig sind, kann man sie parallel verschlüsseln:
```pascal
  // Pseudo-Code für parallele Verschlüsselung
  ParallelFor BlockIndex := 0 to NumBlocks - 1 do
    AES256EncryptBlock(PlainBlocks[BlockIndex], CipherBlocks[BlockIndex], Ctx);
```

  Auf 4-Core CPU: Bis zu 4× schneller!
  Auf Grafikkarte (GPU): Bis zu 1000× schneller!

  VERWENDUNG IM PROJEKT:
```pascal
  procedure TForm1.Verschluesseln_ButtonClick(Sender: TObject);
  var
    PlainBytes, PaddedBytes, CipherBytes: TBytes;
    KeyBytes: TBytes;
    Ctx: TAES256Context;
  begin
    // 1. Klartext einlesen
    PlainBytes := StringToBytesUTF8(MemoPlain.Text);

    // 2. WICHTIG: Padding anwenden!
    PaddedBytes := PKCS7Pad(PlainBytes, 16);

    // 3. Schlüssel vorbereiten
    KeyBytes := SHA256(StringToBytesUTF8(Edit2.Text));
    AES256InitKey(KeyBytes, Ctx);

    // 4. ECB-Verschlüsselung
    CipherBytes := AES256EncryptECB(PaddedBytes, Ctx);  // ← HIER

    // 5. Anzeigen (z.B. als Hex)
    MemoCipher.Lines.Add(BytesToHex(CipherBytes));
  end;
```

  FEHLERSZENARIEN:

  1. VERGESSENES PADDING:
```pascal
  PlainBytes := StringToBytesUTF8('Hallo');  // 5 Bytes
  CipherBytes := AES256EncryptECB(PlainBytes, Ctx);  // FEHLER! Exception!
```
  → Immer PKCS7Pad verwenden!

  2. LEERE DATEN:
```pascal
  PlainBytes := nil;
  CipherBytes := AES256EncryptECB(PlainBytes, Ctx);  // Exit, keine Exception
```
  → Gibt leeres Array zurück

  ALTERNATIVEN ZU ECB:

  1. CBC (Cipher Block Chaining):
     → Sicherer, Blöcke sind verkettet
     → Benötigt IV (Initialization Vector)
     → Siehe AES256EncryptCBC

  2. CTR (Counter Mode):
     → Sehr schnell, parallelisierbar
     → Wandelt Blockchiffre in Stromchiffre um
     → Benötigt Nonce

  3. GCM (Galois/Counter Mode):
     → Moderne AEAD (Authenticated Encryption)
     → Verschlüsselung + Authentifizierung
     → Standard für TLS, IPSec

  FÜR NEUE PROJEKTE: GCM oder ChaCha20-Poly1305 empfohlen!

  SICHERHEITSWARNUNG:

  ⚠️ VERWENDE ECB NICHT FÜR PRODUKTIVSYSTEME! ⚠️

  ECB ist für Lernzwecke okay, aber:
  - Zeigt Muster im Plaintext
  - Anfällig für Replay-Angriffe
  - Keine Diffusion zwischen Blöcken
  - Wird von Sicherheitsaudits abgelehnt

  Ausnahme: Verschlüsselung einzelner, zufälliger Werte (z.B. Schlüssel)

  WEITERFÜHRENDE INFORMATIONEN:
  - NIST SP 800-38A: "Modes of Operation", Sektion 6.1 (ECB)
  - "ECB Penguin": Wikipedia "Block cipher mode of operation"
  - NIST Warnung: "ECB mode should not be used in cryptographic applications"
  - "Cryptography Engineering" (Ferguson, Schneier, Kohno): Kapitel über Modi
  - FIPS 197: Erwähnt ECB als einfachsten Modus

  ============================================================================
}
var
  DataLen: Integer;                     // Länge der Eingabedaten in Bytes
  NumBlocks: Integer;                   // Anzahl der 16-Byte-Blöcke
  BlockIndex: Integer;                  // Index des aktuell verarbeiteten Blocks
  Offset: Integer;                      // Offset im Byte-Array für aktuellen Block
  InBlock, OutBlock: TByteArray16;       // Eingabe- und Ausgabe-Block (je 16 Bytes)
  I: Integer;                           // Laufvariable für Byte-Kopieroperationen
begin
  Result := nil;                       // Ergebnis initial auf nil setzen (leeres Array)

  DataLen := Length(PlainData);        // Länge der Eingabedaten ermitteln

  // -------------------------------------------------------------------------
  // VALIDIERUNG 1: Sind überhaupt Daten vorhanden?
  // -------------------------------------------------------------------------

  if DataLen = 0 then                  // Leere Eingabe → Leere Ausgabe, kein Fehler
    Exit;                              // Frühzeitiger Exit spart unnötige Operationen


  // -------------------------------------------------------------------------
  // VALIDIERUNG 2: Ist die Länge ein Vielfaches von 16?
  // -------------------------------------------------------------------------
  // ECB erwartet, dass die Daten bereits gepaddet sind!
  // PlainData muss 16, 32, 48, 64, ... Bytes haben


  if (DataLen mod 16) <> 0 then         // ECB erwartet Datenlänge als Vielfaches von 16
    raise Exception.Create('AES256EncryptECB: Datenlänge muss ein Vielfaches von 16 sein (zuerst PKCS7Pad anwenden).');

   // Nach dieser Prüfung: DataLen ist garantiert durch 16 teilbar
  // Wir können sicher in 16-Byte-Blöcke aufteilen

  // -------------------------------------------------------------------------
  // VORBEREITUNG
  // -------------------------------------------------------------------------

  // Anzahl der 16-Byte-Blöcke berechnen

  NumBlocks := DataLen div 16;          // Anzahl 16-Byte-Blöcke berechnen

  // Ergebnis-Array in gleicher Größe allokieren
  // Verschlüsselung ändert die Länge nicht: Input = Output Länge

  SetLength(Result, DataLen);           // Ergebnis-Array hat die gleiche Länge wie die Eingabedaten

  Offset := 0;                           // Offset startet bei 0 (erstes Byte der Eingabedaten)


  // -------------------------------------------------------------------------
  // HAUPTSCHLEIFE: Verschlüssele jeden Block einzeln
  // -------------------------------------------------------------------------
  // Jeder 16-Byte-Block wird UNABHÄNGIG verschlüsselt
  // Dies ist das charakteristische Merkmal von ECB-Modus

  for BlockIndex := 0 to NumBlocks - 1 do // Schleife über alle Blöcke
  begin
    // -----------------------------------------------------------------------
    // Schritt 1: 16 Bytes aus PlainData in InBlock kopieren
    // -----------------------------------------------------------------------
    // Extrahiere den aktuellen 16-Byte-Block aus den Eingabedaten

    for I := 0 to 15 do InBlock[I] := PlainData[Offset + I];

    // Nach dieser Schleife: InBlock enthält 16 Bytes Plaintext
    // InBlock = PlainData[Offset .. Offset+15]


    // -----------------------------------------------------------------------
    // Schritt 2: Block mit AES-256 verschlüsseln
    // -----------------------------------------------------------------------
    // Dies ist der Kern: Einzelner 16-Byte-Block wird verschlüsselt
    // Verwendet die 14 Runden von AES-256

    // 2. Einzelnen Block mit AES-256 verschlüsseln
    AES256EncryptBlock(InBlock, OutBlock, Context);

    // Nach diesem Aufruf: OutBlock enthält 16 Bytes Ciphertext
    // OutBlock = AES_Encrypt(InBlock, RoundKeys)


    // -----------------------------------------------------------------------
    // Schritt 3: Verschlüsselten Block in Ergebnis kopieren
    // -----------------------------------------------------------------------
    // Kopiere die 16 verschlüsselten Bytes ins Ergebnis-Array

    // 3. Verschlüsselten Block in das Ergebnis-Array kopieren
    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    // Nach dieser Schleife: Result[Offset .. Offset+15] = verschlüsselter Block


    // -----------------------------------------------------------------------
    // Schritt 4: Offset für nächsten Block erhöhen
    // -----------------------------------------------------------------------
    // Springe 16 Bytes weiter zum nächsten Block

    Inc(Offset, 16);                    // Offset für den nächsten Block erhöhen

    // Nach Inc: Offset zeigt auf den Start des nächsten 16-Byte-Blocks

  end;

   // Nach der Schleife:
  // - ALLE Blöcke wurden verschlüsselt
  // - Result enthält DataLen Bytes verschlüsselte Daten
  // - Jeder Block wurde UNABHÄNGIG verschlüsselt (ECB-Charakteristik)

  // WICHTIG FÜR ECB:
  // - Wenn PlainData[0..15] = PlainData[16..31], dann auch Result[0..15] = Result[16..31]
  // - Dies ist die Schwäche von ECB: Muster bleiben erkennbar!
  // - Für Produktion: CBC, CTR oder GCM verwenden!

end;

function AES256DecryptECB(const CipherData: TBytes; const Context: TAES256Context): TBytes;

 {
  ============================================================================
  AES256DecryptECB - Entschlüsselt Daten im ECB-Modus (Electronic Codebook)
  ============================================================================

  ZWECK:
  Entschlüsselt Daten, die zuvor mit AES256EncryptECB verschlüsselt wurden.
  Jeder 16-Byte-Block wird unabhängig entschlüsselt - charakteristisch für
  den ECB-Modus.

  PARAMETER:
  - CipherData: Die zu entschlüsselnden Daten als Byte-Array
  - Context: Der AES-256 Kontext mit allen vorberechneten Rundenschlüsseln
            (GLEICHER Context wie bei Verschlüsselung!)

  RÜCKGABEWERT:
  - TBytes: Die entschlüsselten Daten (gleiche Länge wie CipherData, noch mit Padding!)

  FEHLERBEHANDLUNG:
  - Gibt leeres Array zurück, wenn CipherData leer ist
  - Wirft Exception, wenn Länge kein Vielfaches von 16 ist

  HINTERGRUND - ECB-Entschlüsselung:

  Die ECB-Entschlüsselung ist die exakte Umkehrung der ECB-Verschlüsselung:
  - Jeder 16-Byte-Block wird UNABHÄNGIG entschlüsselt
  - Gleicher Ciphertext-Block → Immer gleicher Plaintext-Block
  - Keine Verkettung zwischen Blöcken
  - Deterministisch und zustandslos

  FUNKTIONSWEISE:

  Die verschlüsselten Daten werden in 16-Byte-Blöcke aufgeteilt:
  CipherData = [CipherBlock0, CipherBlock1, CipherBlock2, ...]

  Jeder Block wird einzeln entschlüsselt:
  PlainBlock0 = AES_Decrypt(CipherBlock0, Key)
  PlainBlock1 = AES_Decrypt(CipherBlock1, Key)
  PlainBlock2 = AES_Decrypt(CipherBlock2, Key)
  ...

  Keine Abhängigkeiten zwischen Blöcken:
  → Fehler in Block 1 beeinflussen Block 2 nicht
  → Blöcke können parallel entschlüsselt werden
  → Sehr schnell in Hardware

  SYMMETRIE ZUR VERSCHLÜSSELUNG:

  Für alle Plaintext-Daten P gilt:
  AES256DecryptECB(AES256EncryptECB(P)) = P

  Dies ist fundamental - ohne perfekte Umkehrbarkeit wären die
  verschlüsselten Daten verloren!

  BEISPIEL - Rückwärts zur Verschlüsselung:

  CipherData (48 Bytes = 3 Blöcke):
  [7A 3F 2E D1 9C B4 8A 5E ...]  ← Cipher 0
  [7A 3F 2E D1 9C B4 8A 5E ...]  ← Cipher 1 (identisch!)
  [B3 C8 91 4A 6F D2 E5 73 ...]  ← Cipher 2

  Nach ECB-Entschlüsselung:
  [00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF]  ← Plain 0
  [00 11 22 33 44 55 66 77 88 99 AA BB CC DD EE FF]  ← Plain 1 (identisch!)
  [FF EE DD CC BB AA 99 88 77 66 55 44 33 22 11 00]  ← Plain 2

  → Die gleichen Ciphertext-Blöcke ergeben gleiche Plaintext-Blöcke
  → ECB-Eigenschaft bleibt erhalten

  NACH DER ENTSCHLÜSSELUNG - PADDING ENTFERNEN:

  WICHTIG: Das Ergebnis enthält noch PKCS#7-Padding!
```pascal
  // Nach Entschlüsselung:
  DecryptedPadded := AES256DecryptECB(CipherData, Ctx);
  // DecryptedPadded enthält noch Padding-Bytes am Ende!

  // Padding entfernen:
  PlainBytes := PKCS7Unpad(DecryptedPadded, 16);
  // JETZT erst haben wir den Original-Plaintext

  // Oder besser (ohne Exception im Debugger):
  if TryGetPKCS7PadLen(DecryptedPadded, PadLen, 16) then
  begin
    OutLen := Length(DecryptedPadded) - PadLen;
    SetLength(PlainBytes, OutLen);
    if OutLen > 0 then
      Move(DecryptedPadded[0], PlainBytes[0], OutLen);
  end
  else
    ShowMessage('Ungültiges Padding - falsches Passwort?');
```

  FEHLERFORTPFLANZUNG IN ECB:

  ECB hat minimale Fehlerfortpflanzung:

  Szenario: Ein Bit-Fehler in Ciphertext (z.B. durch Übertragungsfehler)

  Betroffener Block:
  → ~50% der Bits im entschlüsselten Block sind falsch (Avalanche-Effekt)
  → Der Block ist komplett unleserlich

  Andere Blöcke:
  → NICHT betroffen!
  → Alle anderen Blöcke sind perfekt lesbar

  Vergleich zu CBC:
  → In CBC wären der fehlerhafte Block UND der nächste Block betroffen
  → ECB isoliert Fehler besser

  FALSCHES PASSWORT:

  Wenn mit falschem Passwort entschlüsselt wird:

  1. TECHNISCH FUNKTIONIERT ES:
     → Keine Exception während der Entschlüsselung
     → Jeder Block wird "entschlüsselt"

  2. ERGEBNIS IST MÜLL:
     → Zufällige Bytes statt Plaintext
     → Keine erkennbaren Muster
     → Sieht aus wie Rauschen

  3. PADDING IST UNGÜLTIG:
     → PKCS7Unpad wird fehlschlagen
     → Dies ist oft die erste Erkennung eines falschen Passworts

  Beispiel:
  Richtiges Passwort: "Geheim123"
  Falsches Passwort: "Geheim124"

  → Entschlüsseltes Ergebnis: [F3 8A 91 C2 7D 4E B5 06 ...]
  → Padding-Validierung: FEHLER
  → Rückschluss: Falsches Passwort

  VERWENDUNG IM PROJEKT:
```pascal
  procedure TForm1.entschluesseln_ECBClick(Sender: TObject);
  var
    KeyBytes: TBytes;
    Ctx: TAES256Context;
    DecryptedPadded, PlainBytes: TBytes;
    PlainText: string;
    PadLen, OutLen: Integer;
  begin
    // 1. Schlüssel vorbereiten (gleicher wie bei Verschlüsselung!)
    KeyBytes := StringToBytesUTF8(Edit2.Text);
    KeyBytes := SHA256(KeyBytes);
    AES256InitKey(KeyBytes, Ctx);

    // 2. ECB-Entschlüsselung
    DecryptedPadded := AES256DecryptECB(FCipherBytes, Ctx);  // ← HIER

    // 3. Padding validieren (ohne Exception)
    if not TryGetPKCS7PadLen(DecryptedPadded, PadLen, 16) then
    begin
      StatusMemo.Lines.Add('FEHLER: Padding ungültig.');
      StatusMemo.Lines.Add('→ Falsches Passwort oder korrupte Daten');
      Exit;
    end;

    // 4. Padding entfernen (manuell, ohne Exception)
    OutLen := Length(DecryptedPadded) - PadLen;
    SetLength(PlainBytes, OutLen);
    if OutLen > 0 then
      Move(DecryptedPadded[0], PlainBytes[0], OutLen);

    // 5. Bytes → String
    PlainText := BytesToStringUTF8(PlainBytes);

    // 6. Anzeigen
    decrypted_Memo.Lines.Add(PlainText);
  end;
```

  FUNKTIONSWEISE - Die Implementierung:

  Die Struktur ist IDENTISCH zu AES256EncryptECB:
  1. Validierung (leer? Länge Vielfaches von 16?)
  2. Anzahl Blöcke berechnen
  3. Ergebnis-Array allokieren
  4. Schleife über alle Blöcke:
     - Block extrahieren
     - AES256DecryptBlock aufrufen (statt EncryptBlock!)
     - Entschlüsselten Block ins Ergebnis kopieren
  5. Rückgabe

  Der EINZIGE Unterschied: DecryptBlock statt EncryptBlock

  PARALLELISIERUNG:

  Wie bei der Verschlüsselung können Blöcke parallel entschlüsselt werden:
```pascal
  // Pseudo-Code für parallele Entschlüsselung
  ParallelFor BlockIndex := 0 to NumBlocks - 1 do
    AES256DecryptBlock(CipherBlocks[BlockIndex], PlainBlocks[BlockIndex], Ctx);
```

  Vorteil:
  → Auf Multi-Core CPUs: Fast lineare Beschleunigung
  → Auf GPU: Hunderte Blöcke gleichzeitig

  PERFORMANCE:

  ECB-Entschlüsselung ist etwas langsamer als Verschlüsselung:
  - AES256DecryptBlock ist ~10-20% langsamer (InvMixColumns ist aufwendiger)
  - Aber: Immer noch schneller als CBC-Entschlüsselung
  - Parallelisierung gleicht Performance-Unterschied aus

  Typische Zeiten (ohne Hardware-Beschleunigung):
  - Verschlüsselung: ~700 ns/Block
  - Entschlüsselung: ~800 ns/Block

  Mit AES-NI:
  - Verschlüsselung: ~10 ns/Block
  - Entschlüsselung: ~10 ns/Block (praktisch gleich!)

  BLOCK-MANIPULATION MÖGLICH:

  Ein Angreifer kann bei ECB Blöcke manipulieren:

  1. BLÖCKE VERTAUSCHEN:
     → CipherBlock[0] und CipherBlock[1] tauschen
     → Nach Entschlüsselung: PlainBlock[0] und PlainBlock[1] vertauscht
     → Nachricht wird verändert, ohne dass es erkannt wird!

  2. BLÖCKE KOPIEREN:
     → CipherBlock[1] durch Kopie von CipherBlock[0] ersetzen
     → Nach Entschlüsselung: PlainBlock[1] = PlainBlock[0]
     → Replay-Angriff möglich!

  3. BLÖCKE LÖSCHEN:
     → CipherBlock[2] entfernen
     → Nach Entschlüsselung: PlainBlock[2] fehlt
     → Datenverlust, aber nicht erkennbar (ohne MAC)

  Dies sind fundamentale Schwächen von ECB!

  Lösung: Authenticated Encryption (GCM, ChaCha20-Poly1305)
  → Verschlüsselung + Authentifizierung
  → Manipulation wird erkannt

  VERGLEICH MIT CBC-ENTSCHLÜSSELUNG:

  ECB-Entschlüsselung:
  - Einfacher (keine XOR-Operationen)
  - Schneller (Parallelisierung möglich)
  - Fehler isoliert auf einen Block
  - ABER: Unsicherer (Muster, keine Authentifizierung)

  CBC-Entschlüsselung:
  - Komplexer (XOR mit vorherigem Cipherblock)
  - Langsamer (sequenziell beim Entschlüsseln)
  - Fehler beeinflussen 2 Blöcke
  - ABER: Sicherer (keine Muster)

  FÜR NEUE PROJEKTE: CBC oder besser GCM!

  DEBUGGING-TIPP:

  Test für Korrektheit:
```pascal
  var
    Original, Encrypted, Decrypted: TBytes;
  begin
    // Original-Daten vorbereiten
    Original := StringToBytesUTF8('Test Nachricht 123');
    Original := PKCS7Pad(Original, 16);  // Padding!

    // Verschlüsseln
    Encrypted := AES256EncryptECB(Original, Ctx);

    // Entschlüsseln
    Decrypted := AES256DecryptECB(Encrypted, Ctx);

    // Vergleichen - sollte identisch sein!
    if Length(Decrypted) <> Length(Original) then
      WriteLn('FEHLER: Länge unterschiedlich!')
    else
      for I := 0 to High(Decrypted) do
        if Decrypted[I] <> Original[I] then
          WriteLn('FEHLER: Byte ', I, ' unterschiedlich!');
  end;
```

  WIEDERHOLUNG: ECB-SICHERHEITSWARNUNG:

  ⚠️ ECB IST FÜR PRODUKTIVSYSTEME UNSICHER! ⚠️

  Verwende ECB nur für:
  - Lehrzwecke (wie dieser Code)
  - Verschlüsselung einzelner Blöcke (Schlüssel, Tokens)
  - Tests und Entwicklung

  Für echte Anwendungen:
  - Verwende CBC mit zufälligem IV
  - Besser noch: GCM (Verschlüsselung + Authentifizierung)
  - Oder ChaCha20-Poly1305 (modern und schnell)

  AUTHENTIFIZIERUNG FEHLT:

  ECB (und auch CBC alleine) bieten KEINE Authentifizierung:
  - Angreifer kann Blöcke verändern
  - Manipulation wird nicht erkannt
  - Datenintegrität nicht gewährleistet

  Lösung 1: HMAC zusätzlich verwenden (Encrypt-then-MAC)
  Lösung 2: AEAD-Modi verwenden (GCM, ChaCha20-Poly1305)

  WEITERFÜHRENDE INFORMATIONEN:
  - NIST SP 800-38A: "Modes of Operation", Sektion 6.1 (ECB)
  - "Cryptography Engineering" (Ferguson, Schneier, Kohno): Warnung vor ECB
  - NIST: "Do not use ECB mode for general-purpose encryption"
  - Authenticated Encryption: RFC 5116
  - GCM Mode: NIST SP 800-38D

  ============================================================================
}

var
  DataLen: Integer;                     // Länge der verschlüsselten Daten in Bytes
  NumBlocks: Integer;                   // Anzahl der 16-Byte-Blöcke
  BlockIndex: Integer;                 // Index des aktuell verarbeiteten Blocks
  Offset: Integer;                      // Offset im Byte-Array für aktuellen Block
  InBlock, OutBlock: TByteArray16;      // Eingabe- und Ausgabe-Block (je 16 Bytes)
  I: Integer;                          // Laufvariable für Byte-Kopieroperationen
begin
  Result := nil;                        // Ergebnis initial auf nil setzen (leeres Array)

  DataLen := Length(CipherData);       // Länge der verschlüsselten Daten ermitteln


  // -------------------------------------------------------------------------
  // VALIDIERUNG 1: Sind überhaupt Daten vorhanden?
  // -------------------------------------------------------------------------
  if DataLen = 0 then                   // Leere Eingabe → Leere Ausgabe, kein Fehler
    Exit;

  // -------------------------------------------------------------------------
  // VALIDIERUNG 2: Ist die Länge ein Vielfaches von 16?
  // -------------------------------------------------------------------------
  // Verschlüsselte Daten MÜSSEN ein Vielfaches von 16 Bytes sein
  // (Dies wurde durch Padding vor der Verschlüsselung sichergestellt)

  if (DataLen mod 16) <> 0 then         // ECB erwartet Vielfaches von 16
    raise Exception.Create('AES256DecryptECB: Datenlänge muss ein Vielfaches von 16 sein.');

  // Nach dieser Prüfung: DataLen ist garantiert durch 16 teilbar
  // Korrupte Daten oder falsches Format würden hier erkannt



  // -------------------------------------------------------------------------
  // VORBEREITUNG
  // -------------------------------------------------------------------------

  // Anzahl der 16-Byte-Blöcke berechnen

  NumBlocks := DataLen div 16;          // Anzahl Blöcke berechnen

  // Ergebnis-Array in gleicher Größe allokieren
  // Entschlüsselung ändert die Länge nicht: Input = Output Länge
  // (Padding wird später separat entfernt)

  SetLength(Result, DataLen);           // Ergebnis bekommt gleiche Länge wie CipherData

  Offset := 0;                          // Offset startet bei 0 (erstes Byte der verschlüsselten Daten)

  // -------------------------------------------------------------------------
  // HAUPTSCHLEIFE: Entschlüssele jeden Block einzeln
  // -------------------------------------------------------------------------
  // Jeder 16-Byte-Block wird UNABHÄNGIG entschlüsselt
  // Dies ist das charakteristische Merkmal von ECB-Modus
  // Identische Struktur wie bei EncryptECB, nur DecryptBlock statt EncryptBlock

  for BlockIndex := 0 to NumBlocks - 1 do
  begin

     // -----------------------------------------------------------------------
    // Schritt 1: 16 Bytes aus CipherData in InBlock kopieren
    // -----------------------------------------------------------------------
    // Extrahiere den aktuellen verschlüsselten 16-Byte-Block
    for I := 0 to 15 do
      InBlock[I] := CipherData[Offset + I];
    // Nach dieser Schleife: InBlock enthält 16 Bytes Ciphertext
    // InBlock = CipherData[Offset .. Offset+15]

    // -----------------------------------------------------------------------
    // Schritt 2: Block mit AES-256 entschlüsseln
    // -----------------------------------------------------------------------
    // Dies ist der Kern: Einzelner verschlüsselter Block wird entschlüsselt
    // Verwendet die inversen Transformationen über 14 Runden

    AES256DecryptBlock(InBlock, OutBlock, Context);

    // Nach diesem Aufruf: OutBlock enthält 16 Bytes entschlüsselten Plaintext
    // (noch mit Padding, falls dies der letzte Block ist)
    // OutBlock = AES_Decrypt(InBlock, RoundKeys)

    // -----------------------------------------------------------------------
    // Schritt 3: Entschlüsselten Block in Ergebnis kopieren
    // -----------------------------------------------------------------------
    // Kopiere die 16 entschlüsselten Bytes ins Ergebnis-Array
    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

     // Nach dieser Schleife: Result[Offset .. Offset+15] = entschlüsselter Block

    // -----------------------------------------------------------------------
    // Schritt 4: Offset für nächsten Block erhöhen
    // -----------------------------------------------------------------------
    // Springe 16 Bytes weiter zum nächsten Block

    Inc(Offset, 16);                    // Offset für den nächsten Block erhöhen
     // Nach Inc: Offset zeigt auf den Start des nächsten verschlüsselten Blocks

  end;

  // Nach der Schleife:
  // - ALLE Blöcke wurden entschlüsselt
  // - Result enthält DataLen Bytes entschlüsselte Daten
  // - Result enthält noch PKCS#7-Padding am Ende!
  // - Padding muss vom Aufrufer entfernt werden (PKCS7Unpad oder manuell)

  // WICHTIG:
  // - Wenn CipherData mit falschem Passwort entschlüsselt wurde,
  //   enthält Result zufällige Bytes ("Müll")
  // - Das Padding wird dann ungültig sein
  // - Dies ist oft die erste Erkennung eines falschen Passworts

  // GARANTIE (bei korrektem Passwort):
  // AES256DecryptECB(AES256EncryptECB(P, K), K) = P (mit Padding)


end;

end.
