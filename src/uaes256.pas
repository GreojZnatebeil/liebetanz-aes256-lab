unit uAES256;                         // Definiert eine eigene Unit für unsere AES256-Funktionen

{$mode objfpc}{$H+}                   // Objekt-Pascal-Modus, H+ für lange Strings (Lazarus-Standard)

interface                              // Schnittstellen-Teil der Unit
   (*
  ----------------------------------------------------------------------------
  AES-Projekt / Lazarus / FreePascal – Krypto- und Hilfsfunktionen
  ----------------------------------------------------------------------------
  Teile dieses Codes wurden unter Verwendung eines KI-basierten Assistenten
  (ChatGPT – Modell GPT-5.1) generiert und anschließend von
      Jörg Liebetanz
  überprüft, angepasst, erweitert und getestet.

  Datum der letzten Erstellung/Überarbeitung: 2025-11-20

  ----------------------------------------------------------------------------
  Transparenz / Open-Source-Kompatibilität
  ----------------------------------------------------------------------------
  Dieses Hinweis-Header ist kompatibel mit allen gängigen Open-Source-Lizenzen,
  einschließlich:
    • MIT License
    • BSD 2-Clause / BSD 3-Clause
    • GPLv2 / GPLv3
    • Apache 2.0

  Es enthält:
    - keine Lizenzvorgaben,
    - keine Copyleft-Erweiterungen,
    - keine Nutzungsauflagen.

  Der Hinweis dient ausschließlich der fairen und transparenten Nennung
  der KI-Assistenz und stellt sicher, dass Herkunft und menschliche
  Verantwortung klar dokumentiert bleiben.

  ----------------------------------------------------------------------------
  Hinweis
  ----------------------------------------------------------------------------
  Alle sicherheitskritischen Entscheidungen, Anpassungen, Tests und die finale
  Integration in dieses Projekt wurden durch den menschlichen Entwickler
  Jörg Liebetanz vorgenommen. Die KI diente ausschließlich als Werkzeug.

  ----------------------------------------------------------------------------
*)

uses
  SysUtils;                            // SysUtils wird für TBytes, Exceptions und Hilfsroutinen benötigt

type
  // TAESState stellt den internen 4x4-Byte-Block von AES dar (State-Matrix)
  TAESState = array[0..3, 0..3] of Byte;

  // Ein einzelner 16-Byte-Block (praktisch für Input/Output von AES-Blockfunktionen)
  TByteArray16 = array[0..15] of Byte;

  // Ein Roundkey wird ebenfalls als 4x4-Byte-Matrix dargestellt
  TAESRoundKey = array[0..3, 0..3] of Byte;

  // AES-256 hat 14 Runden + initialen Roundkey = 15 Roundkeys
  TAESRoundKeyArray = array[0..14] of TAESRoundKey;

  // Kontext für AES-256: hier speichern wir alle vorberechneten Roundkeys
  TAES256Context = record
    RoundKeys: TAESRoundKeyArray;     // Array aller Roundkeys für die einzelnen Runden
  end;

const
  AES_BLOCK_SIZE = 16;
  AES_NB = 4;         // Number of columns (state width)
  AES_NK_256 = 8;     // Key length in 32-bit words for AES-256
  AES_NR_256 = 14;    // Number of rounds for AES-256


{ High-Level-Hilfsfunktionen (ohne eigentliche AES-Mathematik) }

function StringToBytesUTF8(const S: string): TBytes;
  // Wandelt einen Lazarus-String (UTF-8) in ein dynamisches Byte-Array um

function BytesToHex(const Data: TBytes): string;
  // Wandelt ein Byte-Array in einen Hex-String um

function HexToBytes(const Hex: string): TBytes;
  // Wandelt eine Hex-Zeichenkette in ein Byte-Array um

function BytesToStringUTF8(const Data: TBytes): string;
  // Wandelt ein UTF-8-kodiertes Byte-Array wieder in einen Lazarus-String um

function PKCS7Pad(const Data: TBytes; BlockSize: Integer = 16): TBytes;
  // Wendet PKCS#7-Padding an

function PKCS7Unpad(const Data: TBytes; BlockSize: Integer = 16): TBytes;
  // Entfernt PKCS#7-Padding (wirft Exceptions bei ungültigem Padding)

{ ✅ Lehrzweck: Padding prüfen, ohne Exceptions (Debugger bleibt ruhig) }

function TryGetPKCS7PadLen(const Data: TBytes; out PadLen: Integer; BlockSize: Integer = 16): Boolean;
  // Prüft, ob Data gültiges PKCS#7 Padding hat.
  // Wenn ja: Result=True und PadLen enthält die Padding-Länge (1..BlockSize).
  // Wenn nein: Result=False und PadLen=0.

function IsValidPKCS7Padding(const Data: TBytes; BlockSize: Integer = 16): Boolean;
  // Wrapper, liefert nur True/False

{ AES-256 Grundgerüst }

procedure AES256InitKey(const Key: TBytes; out Context: TAES256Context);
  // Bereitet aus einem 256-Bit-Schlüssel (32 Bytes) den AES-256-Kontext (Roundkeys) vor

procedure AES256EncryptBlock(const InBlock: TByteArray16; out OutBlock: TByteArray16;
  const Context: TAES256Context);
  // Verschlüsselt genau einen 16-Byte-Block mit AES-256

procedure AES256DecryptBlock(const InBlock: TByteArray16; out OutBlock: TByteArray16;
  const Context: TAES256Context);
  // Entschlüsselt genau einen 16-Byte-Block mit AES-256

function AES256SelfTest(out Report: string): Boolean;
  // Führt wenige bekannte Testvektoren (NIST KAT) aus und liefert True/False.
  // Report enthält eine kurze Zusammenfassung für Log/Memo.


function AES256EncryptECB_TEST(const PlainData: TBytes; const Context: TAES256Context): TBytes;
  // Verschlüsselt Daten im ECB-Modus (Daten müssen vorher gepaddet sein)

function AES256DecryptECB_TEST(const CipherData: TBytes; const Context: TAES256Context): TBytes;
  // Entschlüsselt Daten im ECB-Modus

function AES256EncryptCBC_TEST(const PlainData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
  // Verschlüsselt Daten im CBC-Modus (PlainData muss gepaddet sein)

function AES256DecryptCBC_TEST(const CipherData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
  // Entschlüsselt Daten im CBC-Modus



{ AES State-Transformationen }

procedure BlockToState(const Block: TByteArray16; out State: TAESState);
procedure StateToBlock(const State: TAESState; out Block: TByteArray16);

procedure SubBytesState(var State: TAESState);
procedure InvSubBytesState(var State: TAESState);

procedure ShiftRowsState(var State: TAESState);
procedure InvShiftRowsState(var State: TAESState);

procedure MixColumnsState(var State: TAESState);
procedure InvMixColumnsState(var State: TAESState);

procedure AddRoundKey(var State: TAESState; const RoundKey: TAESRoundKey);

procedure XorBlockInPlace(var Block: TByteArray16; const Mask: TByteArray16);

implementation                          // Implementierungsteil der Unit

const
  // AES S-Box (FIPS-197)
  AES_SBOX: array[0..255] of Byte = (
    $63, $7C, $77, $7B, $F2, $6B, $6F, $C5, $30, $01, $67, $2B, $FE, $D7, $AB, $76,
    $CA, $82, $C9, $7D, $FA, $59, $47, $F0, $AD, $D4, $A2, $AF, $9C, $A4, $72, $C0,
    $B7, $FD, $93, $26, $36, $3F, $F7, $CC, $34, $A5, $E5, $F1, $71, $D8, $31, $15,
    $04, $C7, $23, $C3, $18, $96, $05, $9A, $07, $12, $80, $E2, $EB, $27, $B2, $75,
    $09, $83, $2C, $1A, $1B, $6E, $5A, $A0, $52, $3B, $D6, $B3, $29, $E3, $2F, $84,
    $53, $D1, $00, $ED, $20, $FC, $B1, $5B, $6A, $CB, $BE, $39, $4A, $4C, $58, $CF,
    $D0, $EF, $AA, $FB, $43, $4D, $33, $85, $45, $F9, $02, $7F, $50, $3C, $9F, $A8,
    $51, $A3, $40, $8F, $92, $9D, $38, $F5, $BC, $B6, $DA, $21, $10, $FF, $F3, $D2,
    $CD, $0C, $13, $EC, $5F, $97, $44, $17, $C4, $A7, $7E, $3D, $64, $5D, $19, $73,
    $60, $81, $4F, $DC, $22, $2A, $90, $88, $46, $EE, $B8, $14, $DE, $5E, $0B, $DB,
    $E0, $32, $3A, $0A, $49, $06, $24, $5C, $C2, $D3, $AC, $62, $91, $95, $E4, $79,
    $E7, $C8, $37, $6D, $8D, $D5, $4E, $A9, $6C, $56, $F4, $EA, $65, $7A, $AE, $08,
    $BA, $78, $25, $2E, $1C, $A6, $B4, $C6, $E8, $DD, $74, $1F, $4B, $BD, $8B, $8A,
    $70, $3E, $B5, $66, $48, $03, $F6, $0E, $61, $35, $57, $B9, $86, $C1, $1D, $9E,
    $E1, $F8, $98, $11, $69, $D9, $8E, $94, $9B, $1E, $87, $E9, $CE, $55, $28, $DF,
    $8C, $A1, $89, $0D, $BF, $E6, $42, $68, $41, $99, $2D, $0F, $B0, $54, $BB, $16
  );

var
  AES_INV_SBOX: array[0..255] of Byte;  // Inverse AES-S-Box, wird zur Laufzeit erzeugt

procedure InitAESInverseTables;
{
  ============================================================================
  InitAESInverseTables - Initialisierung der inversen S-Box
  ============================================================================

  ZWECK:
  Diese Prozedur wird einmalig beim Start des Programms aufgerufen (siehe
  'initialization' am Ende der Unit) und berechnet die inverse S-Box
  (AES_INV_SBOX) aus der vorwärts S-Box (AES_SBOX).

  HINTERGRUND - Die AES S-Box:
  Die S-Box (Substitution Box) ist eine Nachschlagetabelle mit 256 Einträgen,
  die bei der SubBytes-Transformation verwendet wird. Sie wurde von den
  AES-Entwicklern Joan Daemen und Vincent Rijmen so konstruiert, dass sie
  bestimmte kryptographische Eigenschaften erfüllt:
  - Nichtlinearität (macht lineare Kryptoanalyse schwieriger)
  - Keine Fixed Points (kein Byte wird auf sich selbst abgebildet, außer $00)
  - Schutz gegen differentielle Kryptoanalyse

  Die S-Box basiert auf der multiplikativen Inversen im Galois-Feld GF(2^8)
  mit anschließender affiner Transformation. Details dazu finden sich in
  FIPS 197, Seite 15-16.

  WARUM EINE INVERSE S-BOX?
  Beim Entschlüsseln muss die SubBytes-Operation rückgängig gemacht werden.
  Statt die inverse Transformation mathematisch zu berechnen (was langsam
  wäre), wird ebenfalls eine Lookup-Tabelle verwendet.

  Die Beziehung ist: AES_INV_SBOX[AES_SBOX[x]] = x für alle x von 0..255

  FUNKTIONSWEISE:
  Die Funktion durchläuft alle 256 möglichen Byte-Werte (0..255) und trägt
  für jeden Wert in die inverse S-Box ein, an welcher Position der
  ursprüngliche Wert in der Vorwärts-S-Box stand.

  BEISPIEL:
  Wenn AES_SBOX[83] = $D1 ist, dann wird AES_INV_SBOX[$D1] = 83 gesetzt.
  Das bedeutet: SubByte(83) = $D1 und InvSubByte($D1) = 83

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197 (AES-Standard): Sektion 5.1.1 (SubBytes) und 5.3.2 (InvSubBytes)
  - "The Design of Rijndael" (Daemen & Rijmen, 2002), Kapitel 3.4
  - Die exakten mathematischen Konstruktionsprinzipien der S-Box sind in
    FIPS 197, Appendix B beschrieben

  ============================================================================
}
var
  I: Integer;
begin
  // AES_INV_SBOX[ AES_SBOX[x] ] = x
  for I := 0 to 255 do
    AES_INV_SBOX[AES_SBOX[I]] := I;
end;

function SubByte(B: Byte): Byte;
{
  ============================================================================
  SubByte - S-Box Substitution (Vorwärts-Transformation)
  ============================================================================

  ZWECK:
  Führt die S-Box-Substitution für ein einzelnes Byte durch. Dies ist die
  fundamentale nichtlineare Operation in AES, die jeden 8-Bit-Wert durch
  einen anderen ersetzt.

  PARAMETER:
  - B: Das zu substituierende Eingabe-Byte (0..255)

  RÜCKGABEWERT:
  - Das substituierte Byte gemäß der AES S-Box Tabelle

  HINTERGRUND - Warum S-Box?
  Die S-Box ist das Herzstück der Sicherheit von AES. Ohne sie wäre AES
  eine rein lineare Chiffre, die sehr leicht zu brechen wäre. Die S-Box
  sorgt für:

  1. NICHTLINEARITÄT: Macht es unmöglich, AES als System linearer
     Gleichungen darzustellen
  2. KONFUSION: Ein einzelnes Bit-Flip im Input kann mehrere Bits im
     Output ändern (nach Claude Shannon, 1949)
  3. SCHUTZ VOR KRYPTOANALYSE: Speziell designed gegen differentielle
     und lineare Angriffe

  FUNKTIONSWEISE:
  Die Funktion verwendet die vordefinierte AES_SBOX Lookup-Tabelle.
  Das Eingabe-Byte wird als Index verwendet: AES_SBOX[B]

  BEISPIEL:
  SubByte($53) = $ED
  SubByte($00) = $63
  SubByte($FF) = $16

  PERFORMANCE:
  Die Lookup-Tabelle ist extrem schnell (O(1) Komplexität). Eine
  mathematische Berechnung der S-Box-Transformation (multiplikative
  Inverse in GF(2^8) + affine Transformation) wäre deutlich langsamer.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.1.1: SubBytes Transformation
  - FIPS 197, Appendix B: S-Box mathematische Konstruktion
  - Die S-Box Werte sind in FIPS 197, Figure 7 vollständig aufgelistet

  ============================================================================
}
begin
  Result := AES_SBOX[B];
end;

function InvSubByte(B: Byte): Byte;
{
  ============================================================================
  InvSubByte - Inverse S-Box Substitution (Rückwärts-Transformation)
  ============================================================================

  ZWECK:
  Führt die inverse S-Box-Substitution durch - die Umkehrung von SubByte.
  Diese Funktion wird beim Entschlüsseln benötigt, um die SubBytes-
  Transformation rückgängig zu machen.

  PARAMETER:
  - B: Das zu substituierende Eingabe-Byte (0..255)

  RÜCKGABEWERT:
  - Das inverse substituierte Byte gemäß der inversen AES S-Box

  MATHEMATISCHE EIGENSCHAFT:
  Für alle Byte-Werte x gilt:
  InvSubByte(SubByte(x)) = x
  SubByte(InvSubByte(x)) = x

  Dies macht SubByte und InvSubByte zu mathematisch inversen Funktionen.

  WARUM EINE SEPARATE FUNKTION?
  Man könnte theoretisch beim Entschlüsseln durch die normale S-Box suchen,
  wo der gewünschte Wert steht. Das wäre aber sehr langsam (O(256) statt O(1)).
  Durch die vorgefertigte inverse S-Box bleibt auch das Entschlüsseln schnell.

  FUNKTIONSWEISE:
  Nutzt die bei Programmstart durch InitAESInverseTables() berechnete
  inverse S-Box Lookup-Tabelle AES_INV_SBOX.

  BEISPIEL:
  InvSubByte($ED) = $53  (da SubByte($53) = $ED war)
  InvSubByte($63) = $00  (da SubByte($00) = $63 war)
  InvSubByte($16) = $FF  (da SubByte($FF) = $16 war)

  SYMMETRIE IN AES:
  Die Existenz dieser inversen Funktion ist charakteristisch für
  symmetrische Verschlüsselung: Der gleiche Schlüssel kann zum Ver-
  und Entschlüsseln verwendet werden, weil alle Operationen umkehrbar sind.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.3.2: InvSubBytes Transformation
  - Die inverse S-Box ist in FIPS 197, Figure 14 aufgelistet

  ============================================================================
}
begin
  Result := AES_INV_SBOX[B];
end;

procedure SubBytesState(var State: TAESState);
{
  ============================================================================
  SubBytesState - S-Box Substitution auf die gesamte State-Matrix
  ============================================================================

  ZWECK:
  Wendet die SubBytes-Transformation auf alle 16 Bytes der State-Matrix an.
  Dies ist eine der vier Haupttransformationen im AES-Algorithmus und die
  einzige nichtlineare Operation.

  PARAMETER:
  - State: Die 4×4 State-Matrix (wird direkt modifiziert, call-by-reference)

  RÜCKGABEWERT:
  - Keiner (die State-Matrix wird in-place modifiziert)

  HINTERGRUND - SubBytes im AES-Kontext:

  SubBytes ist die EINZIGE nichtlineare Transformation in AES. Alle anderen
  Operationen (ShiftRows, MixColumns, AddRoundKey) sind linear. Ohne SubBytes
  wäre AES anfällig gegen lineare Kryptoanalyse.

  ROLLE IN AES:
  SubBytes wird in JEDER Runde angewendet (außer im Schluss der letzten Runde):
  - Runden 1-13: SubBytes → ShiftRows → MixColumns → AddRoundKey
  - Runde 14: SubBytes → ShiftRows → AddRoundKey (ohne MixColumns)

  HISTORISCHER KONTEXT:
  Joan Daemen und Vincent Rijmen haben die S-Box so konstruiert, dass sie:
  1. Maximale Nichtlinearität aufweist
  2. Keine schwachen algebraischen Strukturen hat
  3. Resistent gegen differentielle Kryptoanalyse ist
  4. Resistent gegen lineare Kryptoanalyse ist

  Diese Konstruktion basiert auf jahrzehntelanger Forschung in der
  Kryptographie, insbesondere nach den Erkenntnissen aus der Analyse
  des DES-Algorithmus.

  DIE TRANSFORMATION - Byte für Byte:

  SubBytes ersetzt jedes Byte in der State-Matrix durch sein entsprechendes
  Byte aus der AES S-Box:

  Vorher (Beispiel):
       [0]  [1]  [2]  [3]
  [0]  19   A0   9A   E9
  [1]  3D   F4   C6   F8
  [2]  E3   E2   8D   48
  [3]  BE   2B   2A   08

  Nach SubBytes:
       [0]  [1]  [2]  [3]
  [0]  D4   E0   B8   1E
  [1]  27   BF   B4   41
  [2]  11   98   5D   52
  [4]  AE   F1   E5   30

  Jedes Byte wurde durch S-Box ersetzt:
  - 0x19 → 0xD4 (SubByte(0x19) = 0xD4)
  - 0xA0 → 0xE0 (SubByte(0xA0) = 0xE0)
  - usw.

  MATHEMATISCHER HINTERGRUND - Die S-Box:

  Die AES S-Box kombiniert zwei Operationen:

  1. MULTIPLIKATIVE INVERSE in GF(2^8):
     Jedes Byte x wird auf x^(-1) abgebildet (außer 0 → 0)

  2. AFFINE TRANSFORMATION:
     Das Ergebnis wird durch eine affine Abbildung geschickt, die
     zusätzliche Nichtlinearität und Komplexität hinzufügt

  Die genaue mathematische Konstruktion findet sich in FIPS 197, Sektion 5.1.1.

  WARUM NICHTLINEARITÄT SO WICHTIG IST:

  Angenommen, SubBytes wäre linear (z.B. einfache XOR-Operation):
  → Dann wäre der gesamte AES-Algorithmus ein lineares Gleichungssystem
  → Ein Angreifer könnte mit etwa 256 Klartext/Ciphertext-Paaren das
    gesamte System lösen und den Schlüssel extrahieren
  → AES wäre praktisch wertlos

  Die Nichtlinearität durch SubBytes macht dies unmöglich!

  KONFUSION nach Claude Shannon (1949):

  SubBytes realisiert das von Shannon definierte Prinzip der "Konfusion":
  → Die Beziehung zwischen Ciphertext und Schlüssel soll so komplex wie
     möglich sein
  → Jedes Bit des Ciphertexts soll von vielen Bits des Schlüssels abhängen
  → Statistisches Rauschen: Kleine Änderungen im Input erzeugen große
     Änderungen im Output

  AVALANCHE-EFFEKT:

  Ein einzelnes geändertes Bit im Input sollte im Durchschnitt die Hälfte
  der Output-Bits ändern. SubBytes trägt wesentlich dazu bei:

  Beispiel:
  Input:  0x53 = 01010011
  Output: 0xED = 11101101

  Input:  0x52 = 01010010 (1 Bit geändert)
  Output: 0x00 = 00000000 (viele Bits geändert)

  FUNKTIONSWEISE:

  Diese Funktion ist konzeptionell sehr einfach:
  1. Durchlaufe alle 4 Zeilen der Matrix
  2. Durchlaufe alle 4 Spalten der Matrix
  3. Für jede Position [Row, Col]:
     - Lese das aktuelle Byte
     - Ersetze es durch SubByte(Byte)

  Dies sind insgesamt 16 unabhängige S-Box-Lookups.

  IN-PLACE MODIFIKATION:

  Die State-Matrix wird direkt modifiziert (var-Parameter in Pascal).
  Es wird kein neuer Speicher allokiert. Dies ist effizient und entspricht
  der FIPS 197 Spezifikation, die alle Operationen als Transformationen
  der State-Matrix definiert.

  PERFORMANCE:

  SubBytes ist sehr schnell:
  - 16 einfache Array-Lookups
  - Keine Berechnungen, nur Tabellenzugriffe
  - In moderner Hardware (AES-NI) wird dies durch spezielle CPU-Instruktionen
    noch weiter beschleunigt

  SICHERHEITSASPEKT:

  Die S-Box-Lookups sind zeitkonstant (nicht datenabhängig), was wichtig
  gegen Timing-Angriffe ist. Jeder Lookup dauert gleich lang, unabhängig
  vom Input-Wert.

  TESTVEKTOREN (FIPS 197, Appendix B):

  Die NIST-Testvektoren zeigen SubBytes an verschiedenen Stellen:
  - Appendix B: Vollständige Cipher-Beispiele mit Zwischenschritten
  - Appendix C.1: Einzelne SubBytes-Beispiele

  Diese können zur Verifikation der Implementierung verwendet werden.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.1.1: SubBytes Transformation (offiziell)
  - FIPS 197, Figure 7: Komplette S-Box Tabelle
  - "The Design of Rijndael" (Daemen & Rijmen), Kapitel 3.4: S-Box Design
  - Claude Shannon (1949): "Communication Theory of Secrecy Systems"
  - Eli Biham, Adi Shamir: "Differential Cryptanalysis of DES"

  ============================================================================
}
var
  Row, Col: Integer;    // Laufvariablen für Zeile und Spalte
begin
  for Row := 0 to 3 do
    for Col := 0 to 3 do // Innere Schleife: Alle Spalten durchlaufen (0..3)
      // S-Box Substitution für das Byte an Position [Row, Col]
      // 1. Aktuelles Byte auslesen: State[Row, Col]
      // 2. S-Box Lookup durchführen: SubByte(...)
      // 3. Ergebnis zurückschreiben: State[Row, Col] := ...
      State[Row, Col] := SubByte(State[Row, Col]);
      // Nach dieser Operation wurde das Byte an Position [Row, Col]
      // durch sein S-Box-Äquivalent ersetzt

      // Nach beiden Schleifen wurden alle 16 Bytes der State-Matrix
      // durch ihre entsprechenden S-Box-Werte ersetzt
      // Die nichtlineare Transformation ist abgeschlossen
end;

procedure InvSubBytesState(var State: TAESState);
{
  ============================================================================
  InvSubBytesState - Inverse S-Box Substitution auf die gesamte State-Matrix
  ============================================================================

  ZWECK:
  Wendet die inverse SubBytes-Transformation auf alle 16 Bytes der
  State-Matrix an. Dies ist die Umkehrung von SubBytesState() und wird
  beim Entschlüsseln benötigt.

  PARAMETER:
  - State: Die 4×4 State-Matrix (wird direkt modifiziert, call-by-reference)

  RÜCKGABEWERT:
  - Keiner (die State-Matrix wird in-place modifiziert)

  HINTERGRUND - Inverse Transformation:

  Beim Entschlüsseln müssen alle Verschlüsselungs-Schritte rückgängig
  gemacht werden. Da SubBytes beim Verschlüsseln angewendet wurde, muss
  InvSubBytes beim Entschlüsseln verwendet werden.

  ROLLE IN AES-ENTSCHLÜSSELUNG:

  InvSubBytes wird in JEDER Entschlüsselungs-Runde angewendet:
  - Runde 14 (zuerst): AddRoundKey → InvShiftRows → InvSubBytes
  - Runden 13-1: AddRoundKey → InvMixColumns → InvShiftRows → InvSubBytes
  - Runde 0: AddRoundKey

  WICHTIG: Die Reihenfolge ist umgekehrt zur Verschlüsselung!

  Verschlüsselung:  SubBytes → ShiftRows → MixColumns → AddRoundKey
  Entschlüsselung:  AddRoundKey → InvMixColumns → InvShiftRows → InvSubBytes

  DIE INVERSE TRANSFORMATION:

  InvSubBytes verwendet die inverse S-Box (AES_INV_SBOX), die bei
  Programmstart durch InitAESInverseTables() berechnet wurde.

  Die inverse S-Box hat die Eigenschaft:
  AES_INV_SBOX[AES_SBOX[x]] = x für alle x

  Beispiel (Rückwärts zu SubBytesState):

  Nach SubBytes:
       [0]  [1]  [2]  [3]
  [0]  D4   E0   B8   1E
  [1]  27   BF   B4   41
  [2]  11   98   5D   52
  [3]  AE   F1   E5   30

  Nach InvSubBytes (zurück zum Original):
       [0]  [1]  [2]  [3]
  [0]  19   A0   9A   E9
  [1]  3D   F4   C6   F8
  [2]  E3   E2   8D   48
  [3]  BE   2B   2A   08

  Jedes Byte wurde durch inverse S-Box zurückverwandelt:
  - 0xD4 → 0x19 (InvSubByte(0xD4) = 0x19)
  - 0xE0 → 0xA0 (InvSubByte(0xE0) = 0xA0)
  - usw.

  MATHEMATISCHER HINTERGRUND:

  Die inverse S-Box ist mathematisch definiert als:
  1. Inverse der affinen Transformation
  2. Multiplikative Inverse in GF(2^8)

  Dies ist die exakte Umkehrung der Schritte in der Vorwärts-S-Box.

  SYMMETRIE-EIGENSCHAFT:

  Für alle State-Matrizen S gilt:
  InvSubBytesState(SubBytesState(S)) = S
  SubBytesState(InvSubBytesState(S)) = S

  Diese Eigenschaft ist fundamental für AES:
  → Verschlüsselung muss umkehrbar sein
  → Sonst wäre Entschlüsselung unmöglich
  → Jede Abweichung würde Datenverlust bedeuten

  FUNKTIONSWEISE:

  Die Implementierung ist IDENTISCH zu SubBytesState(), nur mit
  InvSubByte() statt SubByte():

  1. Durchlaufe alle 4 Zeilen der Matrix
  2. Durchlaufe alle 4 Spalten der Matrix
  3. Für jede Position [Row, Col]:
     - Lese das aktuelle Byte
     - Ersetze es durch InvSubByte(Byte)

  WARUM ZWEI SEPARATE FUNKTIONEN?

  Man könnte theoretisch eine Funktion mit einem Parameter "Forward/Inverse"
  schreiben. Separate Funktionen sind aber klarer:
  - Bessere Lesbarkeit
  - Entspricht der FIPS 197 Notation
  - Kein Overhead durch Verzweigungen (if Forward then...)
  - Compiler kann besser optimieren

  PERFORMANCE:

  InvSubBytes ist genauso schnell wie SubBytes:
  - 16 Array-Lookups in AES_INV_SBOX
  - Keine zusätzlichen Berechnungen
  - Gleiche zeitkonstante Eigenschaften

  SICHERHEITSASPEKT - Timing-Konstanz:

  Wie SubBytes ist auch InvSubBytes zeitkonstant:
  - Jeder Lookup dauert gleich lang
  - Unabhängig vom Input-Wert
  - Schutz gegen Timing-basierte Seitenkanalangriffe

  VERWENDUNG IN AES256DecryptBlock:
```pascal
  procedure AES256DecryptBlock(...);
  begin
    BlockToState(InBlock, State);
    AddRoundKey(State, Context.RoundKeys[14]);

    for Round := 13 downto 1 do
    begin
      InvShiftRowsState(State);      // Zuerst InvShiftRows
      InvSubBytesState(State);       // Dann InvSubBytes ← HIER
      AddRoundKey(State, Context.RoundKeys[Round]);
      InvMixColumnsState(State);
    end;

    InvShiftRowsState(State);
    InvSubBytesState(State);         // Auch in letzter Runde ← HIER
    AddRoundKey(State, Context.RoundKeys[0]);

    StateToBlock(State, OutBlock);
  end;
```

  DEBUGGING-TIPP:

  Beim Debuggen kann man testen, ob InvSubBytes korrekt arbeitet:
  1. Erzeuge eine zufällige State-Matrix
  2. Wende SubBytesState() an
  3. Wende InvSubBytesState() an
  4. Vergleiche mit Original → muss identisch sein!

  Dies ist ein einfacher Unit-Test für die Korrektheit der Implementierung.

  TESTVEKTOREN:

  FIPS 197 enthält vollständige Beispiele für beide Richtungen:
  - Appendix B: Komplette Ver- und Entschlüsselung mit Zwischenschritten
  - Appendix C: Einzelne Transformations-Beispiele

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.3.2: InvSubBytes Transformation (offiziell)
  - FIPS 197, Figure 14: Inverse S-Box Tabelle
  - "The Design of Rijndael", Kapitel 4: Inverse Cipher
  - NIST: "Advanced Encryption Standard (AES)" - Implementierungshinweise

  ============================================================================
}
var
  Row, Col: Integer;         // Laufvariablen für Zeile und Spalte
begin
  for Row := 0 to 3 do           // Äußere Schleife: Alle Zeilen durchlaufen (0..3)
    for Col := 0 to 3 do         // Innere Schleife: Alle Spalten durchlaufen (0..3)
       // Inverse S-Box Substitution für das Byte an Position [Row, Col]
      // 1. Aktuelles Byte auslesen: State[Row, Col]
      // 2. Inverse S-Box Lookup durchführen: InvSubByte(...)
      // 3. Ergebnis zurückschreiben: State[Row, Col] := ...
      State[Row, Col] := InvSubByte(State[Row, Col]);
      // Nach dieser Operation wurde das Byte an Position [Row, Col]
      // durch sein inverses S-Box-Äquivalent ersetzt
      // Die Substitution wurde rückgängig gemacht

      // Nach beiden Schleifen wurden alle 16 Bytes der State-Matrix
      // durch ihre entsprechenden inversen S-Box-Werte ersetzt
      // Die inverse nichtlineare Transformation ist abgeschlossen

     // GARANTIE: Wenn vorher SubBytesState() angewendet wurde,
     // ist der ursprüngliche Zustand jetzt wiederhergestellt
end;

function StringToBytesUTF8(const S: string): TBytes;
{
  ============================================================================
  StringToBytesUTF8 - Konvertiert einen String in UTF-8 Bytes
  ============================================================================

  ZWECK:
  Wandelt einen Lazarus-String in ein Byte-Array um, wobei die UTF-8
  Kodierung verwendet wird. Diese Funktion ist essentiell, um Texte für
  die Verschlüsselung vorzubereiten.

  PARAMETER:
  - S: Der zu konvertierende String (kann Umlaute, Sonderzeichen etc. enthalten)

  RÜCKGABEWERT:
  - TBytes: Dynamisches Byte-Array mit der UTF-8-kodierten Darstellung
  - Bei leerem Input-String wird ein leeres Array (nil) zurückgegeben

  HINTERGRUND - Warum UTF-8?
  UTF-8 ist die Standard-Textkodierung im modernen Computing:

  1. VARIABLE LÄNGE: ASCII-Zeichen benötigen nur 1 Byte, Umlaute 2 Bytes,
     Emoji bis zu 4 Bytes. Dies ist platzsparend.

  2. KOMPATIBILITÄT: Die ersten 128 Zeichen sind identisch mit ASCII,
     was maximale Kompatibilität gewährleistet.

  3. SELBSTSYNCHRONISIEREND: Man kann mitten in einem UTF-8-Stream
     einsteigen und den nächsten Zeichenanfang finden.

  4. KEINE BYTE ORDER PROBLEME: Im Gegensatz zu UTF-16 ist UTF-8
     plattformunabhängig (kein Little/Big-Endian).

  WARUM WICHTIG FÜR VERSCHLÜSSELUNG?
  AES arbeitet mit Bytes, nicht mit Zeichen. Vor der Verschlüsselung muss
  jeder Text in eine eindeutige Byte-Repräsentation umgewandelt werden.
  UTF-8 garantiert, dass:
  - Der gleiche Text immer die gleichen Bytes erzeugt
  - Texte plattformübergreifend identisch verschlüsselt werden
  - Internationale Zeichen korrekt behandelt werden

  FUNKTIONSWEISE:
  1. Der Lazarus-String wird mit UTF8Encode() in einen UTF8String konvertiert
  2. Die Länge des UTF-8 Strings wird ermittelt
  3. Ein entsprechend großes Byte-Array wird allokiert
  4. Die UTF-8 Bytes werden mit Move() in das Array kopiert

  BEISPIELE:
  "Hello"      → 5 Bytes:  [48 65 6C 6C 6F]
  "Hällo"      → 6 Bytes:  [48 C3 A4 6C 6C 6F]  (ä = 2 Bytes in UTF-8)
  "日本"        → 6 Bytes:  [E6 97 A5 E6 9C AC]  (jedes Zeichen = 3 Bytes)
  ""           → 0 Bytes:  []

  BESONDERHEIT LAZARUS:
  In Lazarus (FreePascal) sind normale Strings bereits UTF-8 kodiert,
  aber UTF8Encode() stellt explizit sicher, dass das Ergebnis wirklich
  UTF-8 ist, auch wenn der Quellstring in einem anderen Format vorliegt.

  WEITERFÜHRENDE INFORMATIONEN:
  - RFC 3629: UTF-8 Standard Spezifikation
  - Unicode Standard: www.unicode.org
  - FreePascal Dokumentation: String-Handling und UTF-8

  ============================================================================
}
var
  Utf8: UTF8String;        // UTF-8 kodierter String (garantiert UTF-8 Format)
  Len: Integer;            // Länge des UTF-8 Strings in Bytes
begin
  // Ergebnis zunächst auf nil setzen (leeres Array)
  // Dies ist wichtig für den Fall, dass der Input-String leer ist
  Result := nil;

  Utf8 := UTF8Encode(S);
  Len := Length(Utf8);

  if Len > 0 then
  begin
    SetLength(Result, Len);
    Move(Utf8[1], Result[0], Len);
  end;
end;

function BytesToStringUTF8(const Data: TBytes): string;
{
  ============================================================================
  BytesToStringUTF8 - Konvertiert UTF-8 Bytes zurück in einen String
  ============================================================================

  ZWECK:
  Wandelt ein Byte-Array mit UTF-8-kodierten Daten zurück in einen
  lesbaren Lazarus-String um. Diese Funktion wird nach dem Entschlüsseln
  benötigt, um aus den Bytes wieder Text zu machen.

  PARAMETER:
  - Data: Byte-Array mit UTF-8-kodierten Zeichen

  RÜCKGABEWERT:
  - String: Lazarus-String mit dem dekodierten Text
  - Bei leerem Input-Array wird ein leerer String zurückgegeben

  HINTERGRUND:
  Diese Funktion ist die exakte Umkehrung von StringToBytesUTF8().
  Sie muss die UTF-8 Kodierung korrekt interpretieren, damit:
  - Mehrbyte-Zeichen (Umlaute, Sonderzeichen) richtig erkannt werden
  - Die Zeichengrenzen korrekt identifiziert werden
  - Ungültige UTF-8-Sequenzen nicht zu Fehlern führen

  WICHTIG - FEHLERHAFTE ENTSCHLÜSSELUNG:
  Wenn ein Text mit dem falschen Passwort entschlüsselt wurde, entstehen
  zufällige Bytes. Diese Funktion versucht trotzdem, daraus einen String
  zu machen, was oft zu "Müll-Zeichen" führt. Dies ist normal und zeigt,
  dass das Passwort falsch war.

  FUNKTIONSWEISE:
  1. Prüfen, ob das Byte-Array leer ist
  2. Ein UTF8String-Objekt in der passenden Größe erzeugen
  3. Die Bytes vom Array in den UTF8String kopieren
  4. Den UTF8String implizit als normalen Lazarus-String zurückgeben

  BEISPIELE (Rückwärts-Konvertierung):
  [48 65 6C 6C 6F]           → "Hello"
  [48 C3 A4 6C 6C 6F]        → "Hällo"
  [E6 97 A5 E6 9C AC]        → "日本"
  []                          → ""
  [FF FF FF]                  → "���" (ungültige UTF-8 Sequenz)

  SYMMETRIE-EIGENSCHAFT:
  Für alle gültigen UTF-8 Strings gilt:
  BytesToStringUTF8(StringToBytesUTF8(S)) = S

  Diese Eigenschaft ist essentiell für die Verschlüsselung:
  Klartext → Bytes → Verschlüsselung → Entschlüsselung → Bytes → Klartext

  LAZARUS-BESONDERHEIT:
  Lazarus arbeitet intern mit UTF-8, daher ist die Zuweisung eines
  UTF8String an einen normalen String automatisch kompatibel.

  WEITERFÜHRENDE INFORMATIONEN:
  - UTF-8 Dekodierung: RFC 3629
  - Character Encoding: "The Absolute Minimum Every Software Developer
    Absolutely, Positively Must Know About Unicode" (Joel Spolsky)

  ============================================================================
}
var
  Utf8: UTF8String;
  Len: Integer;
begin
  Result := '';
  Utf8 := '';

  Len := Length(Data);
  if Len = 0 then
    Exit;       // Frühzeitiger Ausstieg spart unnötige Operationen

  SetLength(Utf8, Len);
  // Bytes vom Array in den UTF8String kopieren
  // Data[0] ist das erste Byte (Array beginnt bei 0)
  // Utf8[1] ist das erste Zeichen (String beginnt bei 1)
  Move(Data[0], Utf8[1], Len);

  Result := Utf8;
  // Nach diesem Punkt enthält Result den dekodierten Text
  // Falls die Bytes keine gültige UTF-8-Sequenz waren (z.B. nach falscher
  // Entschlüsselung), können Ersatzzeichen (�) erscheinen
end;

function BytesToHex(const Data: TBytes): string;
{
  ============================================================================
  BytesToHex - Konvertiert Bytes in hexadezimale Darstellung
  ============================================================================

  ZWECK:
  Wandelt ein Byte-Array in einen lesbaren Hexadezimal-String um.
  Diese Funktion wird hauptsächlich für Debug-Ausgaben und zur Anzeige
  von verschlüsselten Daten verwendet.

  PARAMETER:
  - Data: Das zu konvertierende Byte-Array

  RÜCKGABEWERT:
  - String: Hexadezimale Darstellung (z.B. "4A3F2E1B")
  - Großbuchstaben A-F werden verwendet
  - Keine Trennzeichen zwischen den Bytes

  HINTERGRUND - Warum Hexadezimal?
  Hexadezimal (Basis 16) ist die Standarddarstellung für Binärdaten in
  der Kryptographie, weil:

  1. KOMPAKT: Jedes Byte wird durch genau 2 Zeichen dargestellt
     (00 bis FF), während binär 8 Zeichen nötig wären (00000000 bis 11111111)

  2. LESBAR: Menschen können Hex-Werte leichter erfassen und vergleichen
     als lange Binär-Strings

  3. STANDARD: Alle kryptographischen Spezifikationen (FIPS 197, RFCs)
     verwenden Hex-Notation für Testvektoren und Beispiele

  4. DEBUGGING: Hex-Dumps ermöglichen einfache visuelle Inspektion von
     verschlüsselten Daten, Schlüsseln und IVs

  VERWENDUNG IN DIESEM PROJEKT:
  - Anzeige des verschlüsselten Ciphertexts im MemoCipher
  - Ausgabe von Schlüsseln (SHA-256 Hash)
  - Darstellung von Testvektoren beim Selftest
  - Debug-Ausgaben während der Verschlüsselung

  FUNKTIONSWEISE:
  1. Für jedes Byte im Array werden 2 Hex-Zeichen erzeugt
  2. Das obere Nibble (4 Bits) ergibt das erste Zeichen
  3. Das untere Nibble ergibt das zweite Zeichen
  4. Bit-Operationen (shr, and) extrahieren die Nibbles
  5. Die HexChars-Tabelle bildet Werte 0-15 auf Zeichen '0'-'9','A'-'F' ab

  BEISPIELE:
  []                    → ""
  [0]                   → "00"
  [255]                 → "FF"
  [74, 63, 46, 27]      → "4A3F2E1B"
  [1, 2, 3, 4, 5]       → "0102030405"

  DETAILLIERTE BERECHNUNG (Beispiel Byte = 74 = 0x4A):
  Byte 74 binär: 01001010
  Oberes Nibble: 0100 = 4 → Zeichen '4'
  Unteres Nibble: 1010 = 10 → Zeichen 'A'
  Ergebnis: "4A"

  PERFORMANCE:
  Die Verwendung einer Lookup-Tabelle (HexChars) ist deutlich schneller
  als die Verwendung von IntToHex() oder Format() für jedes Byte.
  Bei großen Datenmengen macht dies einen spürbaren Unterschied.

  ALTERNATIVE DARSTELLUNGEN:
  Manche Programme verwenden Trennzeichen wie "4A:3F:2E:1B" oder
  "4A 3F 2E 1B". Diese Funktion verwendet die kompakte Form ohne
  Trennzeichen, wie sie in FIPS 197 üblich ist.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197: Alle Beispiele und Testvektoren sind in Hex notiert
  - RFC 4648: "Base16" (Hexadezimal) Encoding

  ============================================================================
}
const
  // Lookup-Tabelle für schnelle Hex-Konvertierung
  // Index 0-15 wird auf Zeichen '0'-'9' und 'A'-'F' abgebildet
  HexChars: PChar = '0123456789ABCDEF';
var
  I: Integer;
  B: Byte;
begin
  Result := '';
  for I := 0 to High(Data) do
  begin
    B := Data[I];
    // Oberes Nibble (4 Bits) extrahieren und in Hex-Zeichen umwandeln
    // (B shr 4): Schiebt die oberen 4 Bits nach rechts
    // and $0F: Maskiert auf 4 Bits (0-15), um sicher zu sein
    // Das Ergebnis (0-15) wird als Index in HexChars verwendet
    Result := Result + HexChars[(B shr 4) and $0F];
    // Unteres Nibble (4 Bits) extrahieren und in Hex-Zeichen umwandeln
    // and $0F: Maskiert die unteren 4 Bits direkt
    Result := Result + HexChars[B and $0F];
    // Nach der Schleife enthält Result die vollständige Hex-Darstellung
    // Beispiel: [74, 63] → "4A3F"
  end;
end;

function HexToBytes(const Hex: string): TBytes;
     {
  ============================================================================
  HexToBytes - Konvertiert hexadezimale Darstellung zurück in Bytes
  ============================================================================

  ZWECK:
  Wandelt einen Hexadezimal-String zurück in ein Byte-Array um.
  Diese Funktion ist die Umkehrung von BytesToHex() und wird verwendet,
  um Hex-Strings (z.B. aus Test-Vektoren oder Benutzereingaben) in
  binäre Daten zu konvertieren.

  PARAMETER:
  - Hex: String mit hexadezimalen Zeichen (z.B. "4A3F2E1B" oder "4A 3F 2E 1B")

  RÜCKGABEWERT:
  - TBytes: Byte-Array mit den konvertierten Daten

  FEHLERBEHANDLUNG:
  - Ungültige Hex-Zeichen (nicht 0-9, A-F, a-f) → Exception
  - Ungerade Anzahl Hex-Zeichen → Exception
  - Leerzeichen im String werden automatisch entfernt (tolerant)

  HINTERGRUND:
  Diese Funktion ist essentiell beim Testen der AES-Implementierung,
  da die NIST-Testvektoren (FIPS 197) in Hex-Notation angegeben sind.
  Ohne diese Funktion müssten alle Testvektoren manuell in Byte-Arrays
  übertragen werden, was fehleranfällig wäre.

  FUNKTIONSWEISE:
  1. Leerzeichen aus dem Input-String entfernen (Toleranz für formatierte Eingaben)
  2. Prüfen, dass eine gerade Anzahl von Zeichen vorliegt (2 Zeichen = 1 Byte)
  3. Für jedes Zeichen-Paar:
     a) Erstes Zeichen → oberes Nibble (4 Bits)
     b) Zweites Zeichen → unteres Nibble (4 Bits)
     c) Beide Nibbles kombinieren zu einem Byte

  BEISPIELE:
  ""              → []
  "00"            → [0]
  "FF"            → [255]
  "4A3F2E1B"      → [74, 63, 46, 27]
  "4A 3F 2E 1B"   → [74, 63, 46, 27] (Leerzeichen werden entfernt)
  "0102030405"    → [1, 2, 3, 4, 5]

  DETAILLIERTE BERECHNUNG (Beispiel "4A"):
  Zeichen '4': HexCharToVal('4') = 4 (oberes Nibble)
  Zeichen 'A': HexCharToVal('A') = 10 (unteres Nibble)
  Kombination: (4 shl 4) or 10 = 64 or 10 = 74
  Ergebnis: Byte-Wert 74 (0x4A)

  GROSS-/KLEINSCHREIBUNG:
  Die Funktion akzeptiert sowohl Großbuchstaben (A-F) als auch
  Kleinbuchstaben (a-f), wie es in der Praxis üblich ist.

  VERWENDUNG IN DIESEM PROJEKT:
  - Laden von Testvektoren im Selftest
  - Manuelles Eingeben von Schlüsseln oder IVs (falls gewünscht)
  - Debugging und Verifikation gegen bekannte Werte

  SYMMETRIE-EIGENSCHAFT:
  Für alle gültigen Byte-Arrays gilt:
  HexToBytes(BytesToHex(Data)) = Data

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197: Appendix C enthält vollständige Hex-Testvektoren
  - RFC 4648: Base16 (Hexadecimal) Encoding

  ============================================================================
}

  function HexCharToVal(C: Char): Integer;
   {
    ------------------------------------------------------------------------
    HexCharToVal - Lokale Hilfsfunktion (nur innerhalb von HexToBytes sichtbar)
    ------------------------------------------------------------------------

    ZWECK:
    Konvertiert ein einzelnes Hex-Zeichen ('0'-'9', 'A'-'F', 'a'-'f')
    in seinen numerischen Wert (0-15).

    PARAMETER:
    - C: Einzelnes Zeichen

    RÜCKGABEWERT:
    - Integer: Numerischer Wert (0-15)

    FEHLERBEHANDLUNG:
    - Wirft eine Exception bei ungültigen Zeichen

    BEISPIELE:
    '0' → 0, '9' → 9, 'A'/'a' → 10, 'F'/'f' → 15
    'G' → Exception (ungültiges Hex-Zeichen)
    ------------------------------------------------------------------------
  }
  begin
    if (C >= '0') and (C <= '9') then
      Result := Ord(C) - Ord('0')
    else if (C >= 'A') and (C <= 'F') then
      Result := 10 + (Ord(C) - Ord('A'))
    else if (C >= 'a') and (C <= 'f') then
      Result := 10 + (Ord(C) - Ord('a'))
    else
      // Exception werfen mit aussagekräftiger Fehlermeldung
      // Dies verhindert, dass fehlerhafte Hex-Strings stillschweigend
      // falsche Bytes erzeugen
      raise Exception.Create('HexToBytes: Ungültiges Hex-Zeichen: ' + C);
  end;

var
  CleanHex: string;    // Hex-String ohne Leerzeichen
  I, N: Integer;       // I: Schleifenzähler, N: Anzahl der Bytes im Ergebnis
  Hi, Lo: Integer;     // Hi: Oberes Nibble, Lo: Unteres Nibble
begin
  Result := nil;
  CleanHex := '';

  for I := 1 to Length(Hex) do
    if Hex[I] <> ' ' then
      CleanHex := CleanHex + Hex[I];

  if (Length(CleanHex) mod 2) <> 0 then
    raise Exception.Create('HexToBytes: Ungerade Anzahl von Hex-Zeichen.');

  N := Length(CleanHex) div 2;
  SetLength(Result, N);

  for I := 0 to N - 1 do
  begin
    Hi := HexCharToVal(CleanHex[2 * I + 1]);
    Lo := HexCharToVal(CleanHex[2 * I + 2]);
    // Beide Nibbles zu einem Byte kombinieren
    // Oberes Nibble wird um 4 Bits nach links verschoben
    // Unteres Nibble wird mit OR hinzugefügt
    // Beispiel: Hi=4, Lo=10 → (4 shl 4) or 10 = 64 or 10 = 74
    Result[I] := Byte((Hi shl 4) or Lo);
    // Nach der Schleife enthält Result die konvertierten Bytes
    // Beispiel: "4A3F" → [74, 63]
  end;
end;


function AES256SelfTest(out Report: string): Boolean;
{
  ============================================================================
  AES256SelfTest - Minimaler Selbsttest (NIST Known Answer Tests)
  ----------------------------------------------------------------------------
  Zweck:
    - Schnelle Plausibilitätsprüfung, ob AES-Kern + Modi korrekt arbeiten
    - Hilft Contributors beim Verifizieren ohne GUI

  Hinweis:
    Das ist kein vollständiger Kryptotest-Suite, aber ein guter "Smoke Test".
  ============================================================================
}
  function EqualBytes(const A, B: TBytes): Boolean;
  var
    I: Integer;
  begin
    if Length(A) <> Length(B) then Exit(False);
    for I := 0 to High(A) do
      if A[I] <> B[I] then Exit(False);
    Result := True;
  end;

  procedure BytesToBlock16(const Src: TBytes; out Dst: TByteArray16);
  begin
    if Length(Src) <> AES_BLOCK_SIZE then
      raise Exception.Create('AES256SelfTest: Blocklänge ist nicht 16 Byte.');

    Dst[0]:=0;        //<- nimmt dem Compiler den Hint

    Move(Src[0], Dst[0], AES_BLOCK_SIZE);
  end;

  function Block16ToBytes(const Src: TByteArray16): TBytes;
  begin
    Result:=nil;
    SetLength(Result, AES_BLOCK_SIZE);
    Move(Src[0], Result[0], AES_BLOCK_SIZE);
  end;

var
  Key, Plain, ExpECB, ExpCBC, GotECB, GotCBC, DecCBC: TBytes;
  Ctx: TAES256Context;
  InBlk, OutBlk, DecBlk: TByteArray16;
  IV: TByteArray16;
begin
  Report := '';
  Result := False;

  // NIST SP 800-38A (bekannte Testwerte für AES-256)
  Key   := HexToBytes('603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4');
  Plain := HexToBytes('6bc1bee22e409f96e93d7e117393172a');

  // AES-256 ECB (1. Block)
  ExpECB := HexToBytes('f3eed1bdb5d2a03c064b5a7e3db181f8');

  // AES-256 CBC (1. Block) mit IV = 000102...0F
  BytesToBlock16(HexToBytes('000102030405060708090a0b0c0d0e0f'), IV);
  ExpCBC := HexToBytes('f58c4c04d6e5f1ba779eabfb5f7bfbd6');

  // Key Schedule
  AES256InitKey(Key, Ctx);

  // --- ECB Block Test ---
  BytesToBlock16(Plain, InBlk);
  AES256EncryptBlock(InBlk, OutBlk, Ctx);
  GotECB := Block16ToBytes(OutBlk);

  if EqualBytes(GotECB, ExpECB) then
    Report := Report + 'ECB: OK' + LineEnding
  else
  begin
    Report := Report + 'ECB: FAIL' + LineEnding +
              '  expected: ' + BytesToHex(ExpECB) + LineEnding +
              '  got     : ' + BytesToHex(GotECB) + LineEnding;
    Exit(False);
  end;

  AES256DecryptBlock(OutBlk, DecBlk, Ctx);
  if EqualBytes(Block16ToBytes(DecBlk), Plain) then
    Report := Report + 'ECB decrypt: OK' + LineEnding
  else
  begin
    Report := Report + 'ECB decrypt: FAIL' + LineEnding;
    Exit(False);
  end;

  // --- CBC Test (1 Block) ---

  GotCBC :=  AES256EncryptCBC_TEST(Plain, IV, Ctx);
  if EqualBytes(GotCBC, ExpCBC) then
    Report := Report + 'CBC: OK' + LineEnding
  else
  begin
    Report := Report + 'CBC: FAIL' + LineEnding +
              '  expected: ' + BytesToHex(ExpCBC) + LineEnding +
              '  got     : ' + BytesToHex(GotCBC) + LineEnding;
    Exit(False);
  end;

  DecCBC := AES256DecryptCBC_TEST(GotCBC, IV, Ctx);
  if EqualBytes(DecCBC, Plain) then
    Report := Report + 'CBC decrypt: OK' + LineEnding
  else
  begin
    Report := Report + 'CBC decrypt: FAIL' + LineEnding;
    Exit(False);
  end;

  Result := True;
end;

function PKCS7Pad(const Data: TBytes; BlockSize: Integer): TBytes;
{
  ============================================================================
  PKCS7Pad - Fügt PKCS#7-Padding zu den Daten hinzu
  ============================================================================

  ZWECK:
  Erweitert die Eingabedaten auf ein Vielfaches der Blockgröße (16 Bytes
  bei AES) durch Hinzufügen von Padding-Bytes. Dies ist notwendig, weil
  AES nur mit kompletten 16-Byte-Blöcken arbeiten kann.

  PARAMETER:
  - Data: Die zu paddenden Eingabedaten (beliebige Länge)
  - BlockSize: Die Blockgröße in Bytes (Standard: 16 für AES)

  RÜCKGABEWERT:
  - TBytes: Die gepaddeten Daten (Länge ist immer ein Vielfaches von BlockSize)

  HINTERGRUND - Warum Padding?
  Nachrichten haben selten eine Länge, die exakt ein Vielfaches von 16 Bytes
  ist. Beispiele:
  - "Hallo" = 5 Bytes → braucht 11 Padding-Bytes → 16 Bytes total
  - "Test" = 4 Bytes → braucht 12 Padding-Bytes → 16 Bytes total
  - "1234567890123456" = 16 Bytes → braucht 16 Padding-Bytes → 32 Bytes total

  WICHTIG - Padding ist IMMER nötig:
  Selbst wenn die Nachricht bereits ein Vielfaches von 16 Bytes ist, wird
  ein kompletter Block (16 Bytes) Padding hinzugefügt. Warum?
  → Ohne dies könnte der Empfänger nicht unterscheiden, ob das letzte Byte
     Teil der Nachricht oder Padding ist.

  DER PKCS#7-STANDARD:
  PKCS#7 (Public Key Cryptography Standards #7) definiert eine eindeutige
  Padding-Methode:

  - Wenn N Bytes Padding benötigt werden, wird N-mal das Byte N angefügt
  - N kann Werte von 1 bis BlockSize (16) annehmen

  Beispiele bei BlockSize=16:
  - Benötigt 1 Byte Padding: füge 0x01 hinzu
  - Benötigt 5 Bytes Padding: füge 0x05 0x05 0x05 0x05 0x05 hinzu
  - Benötigt 16 Bytes Padding: füge 16× 0x10 hinzu

  MATHEMATISCHE BERECHNUNG:
  PadLen = BlockSize - (DataLen mod BlockSize)

  Beispiel: DataLen=13, BlockSize=16
  → 13 mod 16 = 13
  → 16 - 13 = 3
  → Es werden 3 Bytes mit Wert 0x03 hinzugefügt

  VOLLSTÄNDIGE BEISPIELE:

  Input: "Hello" (5 Bytes) = [48 65 6C 6C 6F]
  → DataLen mod 16 = 5
  → PadLen = 16 - 5 = 11
  → Output: [48 65 6C 6C 6F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B] (16 Bytes)

  Input: "" (0 Bytes) = []
  → DataLen mod 16 = 0
  → PadLen = 16 - 0 = 16
  → Output: [10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10] (16 Bytes)

  Input: "1234567890123456" (16 Bytes, exakt ein Block)
  → DataLen mod 16 = 0
  → PadLen = 16
  → Output: Original 16 Bytes + 16 Bytes Padding = 32 Bytes total

  WARUM DIESER STANDARD?
  PKCS#7 hat mehrere Vorteile:

  1. EINDEUTIG: Beim Entpadding kann man immer das letzte Byte lesen,
     um zu erfahren, wie viele Padding-Bytes es gibt

  2. VERIFIZIERBAR: Man kann prüfen, ob das Padding korrekt ist
     (alle letzten N Bytes müssen den Wert N haben)

  3. KOMPATIBEL: PKCS#7 ist der De-facto-Standard und wird von allen
     gängigen Krypto-Bibliotheken unterstützt

  SICHERHEITSHINWEIS - Padding Oracle Angriffe:
  In CBC-Modus kann ungültige Padding-Erkennung zu "Padding Oracle"-
  Angriffen führen. Deshalb ist wichtig:
  - Padding-Fehler NICHT unterscheidbar von anderen Fehlern machen
  - Konstante Zeit für Validierung verwenden
  → In diesem Lehrprojekt wird dies durch TryGetPKCS7PadLen() erreicht

  WEITERFÜHRENDE INFORMATIONEN:
  - RFC 5652: "Cryptographic Message Syntax (CMS)" - beschreibt PKCS#7
  - PKCS #7 v1.5: Original-Spezifikation
  - "Practical Cryptography" (Ferguson & Schneier): Kapitel zu Padding
  - NIST SP 800-38A: Empfehlungen für Block Cipher Modes

  ============================================================================
}

var
  DataLen: Integer;    // Länge der Eingabedaten
  PadLen: Integer;     // Anzahl der hinzuzufügenden Padding-Bytes
  I: Integer;          // Laufvariable für die Padding-Schleife
begin
  Result := nil;

  DataLen := Length(Data);      // Länge der Eingabedaten ermitteln
  // Berechnen, wie viele Padding-Bytes benötigt werden
  // Modulo-Operation: DataLen mod BlockSize gibt den Rest der Division
  // Beispiel: 13 mod 16 = 13, dann 16 - 13 = 3 Padding-Bytes
  // Spezialfall: 16 mod 16 = 0, dann 16 - 0 = 16 (kompletter Padding-Block!)
  PadLen := BlockSize - (DataLen mod BlockSize);

  SetLength(Result, DataLen + PadLen);

  if DataLen > 0 then
    Move(Data[0], Result[0], DataLen);

  for I := DataLen to DataLen + PadLen - 1 do
    Result[I] := Byte(PadLen);
  // Nach diesem Schritt: Result[DataLen..Ende] = PadLen-Bytes

  // Ergebnis hat jetzt garantiert eine Länge, die ein Vielfaches von BlockSize ist
  // und kann sicher mit AES verschlüsselt werden
end;

function PKCS7Unpad(const Data: TBytes; BlockSize: Integer): TBytes;
{
  ============================================================================
  PKCS7Unpad - Entfernt PKCS#7-Padding von den Daten
  ============================================================================

  ZWECK:
  Entfernt das PKCS#7-Padding, das bei der Verschlüsselung hinzugefügt wurde,
  um die Original-Nachricht wiederherzustellen. Diese Funktion wird nach
  dem Entschlüsseln aufgerufen.

  PARAMETER:
  - Data: Die gepaddeten Daten (z.B. nach AES-Entschlüsselung)
  - BlockSize: Die Blockgröße in Bytes (Standard: 16 für AES)

  RÜCKGABEWERT:
  - TBytes: Die Daten ohne Padding (ursprüngliche Nachricht)

  FEHLERBEHANDLUNG:
  Diese Funktion wirft Exceptions bei ungültigem Padding:
  - Leere Daten
  - Länge ist kein Vielfaches von BlockSize
  - Padding-Byte außerhalb des gültigen Bereichs (1..BlockSize)
  - Padding-Bytes haben nicht alle den gleichen Wert

  WICHTIG FÜR DEN LEHRBETRIEB:
  In diesem Projekt wird PKCS7Unpad() NICHT direkt verwendet, sondern
  die Exception-freie Variante TryGetPKCS7PadLen(). Warum?
  → Im Lazarus-Debugger würden die Exceptions stören, auch wenn sie
     korrekt abgefangen werden. Für Lehrzwecke ist dies unerwünscht.

  HINTERGRUND - Das Padding-Problem:
  Nach der Entschlüsselung haben wir Daten, die Padding enthalten.
  Problem: Wir wissen nicht, wie lang die ursprüngliche Nachricht war.
  Lösung: Das letzte Byte gibt uns diese Information!

  FUNKTIONSWEISE:
  1. Letztes Byte auslesen → dies ist die Padding-Länge N
  2. Validieren, dass N im gültigen Bereich liegt (1 bis BlockSize)
  3. Prüfen, dass die letzten N Bytes alle den Wert N haben
  4. Falls alles korrekt: Original-Länge = Gesamt-Länge - N
  5. Daten ohne die letzten N Bytes zurückgeben

  BEISPIELE (Rückwärts zu PKCS7Pad):

  Input: [48 65 6C 6C 6F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B] (16 Bytes)
  → Letztes Byte = 0x0B = 11
  → Prüfe: Letzte 11 Bytes sind alle 0x0B ✓
  → Output: [48 65 6C 6C 6F] = "Hello" (5 Bytes)

  Input: [10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10] (16 Bytes)
  → Letztes Byte = 0x10 = 16
  → Prüfe: Alle 16 Bytes sind 0x10 ✓
  → Output: [] (0 Bytes, war ein leerer String)

  FEHLERHAFTE EINGABEN (werfen Exceptions):

  [48 65 6C 6C 6F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0C]
  → Letztes Byte = 0x0C = 12
  → Prüfe: Byte an Position [Länge-12] sollte 0x0C sein, ist aber 0x48
  → Exception: "Ungültiges Padding (Bytewert stimmt nicht)"

  [48 65 6C 6C 6F] (5 Bytes, keine volle Blockgröße)
  → Exception: "Ungültige Datenlänge (kein Vielfaches der Blockgröße)"

  WARUM SO STRENGE VALIDIERUNG?
  Stellen Sie sich vor, was passiert, wenn falsches Passwort verwendet wurde:
  1. Entschlüsselung erzeugt zufällige Bytes (Müll)
  2. Letztes Byte ist zufällig, z.B. 0x73
  3. Ohne Validierung würden wir 115 Bytes entfernen → Fehler!
  4. Mit Validierung: Exception zeigt, dass etwas nicht stimmt

  Die strenge Validierung schützt also vor:
  - Falschem Passwort
  - Korrupten Daten
  - Falscher Blockgröße
  - Manipulierten Daten

  SICHERHEITSASPEKT - Timing-Angriffe:
  Die verschiedenen Exception-Meldungen können theoretisch einen Hinweis
  geben, wo das Padding ungültig ist (Timing-Unterschiede). In produktiven
  Systemen sollte man:
  - Alle Fehler gleich behandeln
  - Konstante Validierungszeit verwenden
  → TryGetPKCS7PadLen() ist hier besser

  SYMMETRIE-EIGENSCHAFT:
  Für alle gültigen Daten gilt:
  PKCS7Unpad(PKCS7Pad(Data)) = Data

  Dies gewährleistet, dass Ver- und Entschlüsselung korrekt zusammenarbeiten.

  WEITERFÜHRENDE INFORMATIONEN:
  - RFC 5652: Cryptographic Message Syntax
  - "Practical Cryptography" (Ferguson & Schneier): Padding Oracle Attacks
  - NIST SP 800-38A: Block Cipher Modes
  - Serge Vaudenay (2002): "Security Flaws Induced by CBC Padding"

  ============================================================================
}
var
  DataLen: Integer;         // Länge der gepaddeten Eingabedaten
  PadLen: Integer;         // Anzahl der Padding-Bytes (aus letztem Byte)
  I: Integer;                // Laufvariable zur Validierung
begin
  Result := nil;

  DataLen := Length(Data);

  if DataLen = 0 then     // Validierung 1: Daten dürfen nicht leer sein
    raise Exception.Create('PKCS7Unpad: Daten sind leer.');

  if (DataLen mod BlockSize) <> 0 then    // Validierung 2: Daten müssen ein Vielfaches der Blockgröße sein
    raise Exception.Create('PKCS7Unpad: Ungültige Datenlänge (kein Vielfaches der Blockgröße).');

  // Padding-Länge aus dem letzten Byte auslesen
  // Dies ist der Kern des PKCS#7-Standards: Das letzte Byte enthält
  // die Information, wie viele Padding-Bytes es gibt
  PadLen := Data[DataLen - 1];

  if (PadLen <= 0) or (PadLen > BlockSize) then      // Validierung 3: Padding-Länge muss im gültigen Bereich liegen
    raise Exception.Create('PKCS7Unpad: Ungültige Padding-Länge.');

  for I := DataLen - PadLen to DataLen - 1 do   // Validierung 4: Alle Padding-Bytes müssen den gleichen Wert haben
    if Data[I] <> PadLen then
      raise Exception.Create('PKCS7Unpad: Ungültiges Padding (Bytewert stimmt nicht).');
    // Falls diese Schleife ohne Exception durchläuft, ist das Padding gültig

  SetLength(Result, DataLen - PadLen);

  if Length(Result) > 0 then
    Move(Data[0], Result[0], Length(Result));
  // Ergebnis enthält jetzt die ursprüngliche, ungepaddete Nachricht
  // Beispiel: [48 65 6C 6C 6F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B] → [48 65 6C 6C 6F]
end;

{ ✅ Neue Lehrzweck-Funktionen (ohne Exceptions) }

function TryGetPKCS7PadLen(const Data: TBytes; out PadLen: Integer; BlockSize: Integer): Boolean;
  {
  ============================================================================
  TryGetPKCS7PadLen - Padding-Validierung ohne Exceptions (Lehrzweck)
  ============================================================================

  ZWECK:
  Prüft, ob die Daten gültiges PKCS#7-Padding enthalten, und gibt die
  Padding-Länge zurück - OHNE Exceptions zu werfen. Diese Funktion ist
  speziell für den Lehrbetrieb entwickelt worden.

  PARAMETER:
  - Data: Die zu prüfenden Daten (nach Entschlüsselung)
  - PadLen: OUT-Parameter - enthält bei Erfolg die Padding-Länge (1..BlockSize)
  - BlockSize: Die Blockgröße in Bytes (Standard: 16 für AES)

  RÜCKGABEWERT:
  - Boolean: True = Padding ist gültig, False = Padding ist ungültig
  - Bei True: PadLen enthält die Anzahl der Padding-Bytes
  - Bei False: PadLen wird auf 0 gesetzt

  WARUM DIESE FUNKTION? - Das Exception-Problem im Debugger:

  PKCS7Unpad() wirft Exceptions bei ungültigem Padding. Das ist korrekt
  und sicher, aber im Lehrbetrieb problematisch:

  1. DEBUGGER-UNTERBRECHUNGEN: Lazarus/FreePascal stoppt bei jeder Exception,
     auch wenn sie später korrekt abgefangen wird

  2. STÖRENDE MELDUNGEN: Schüler sehen "Exception EException: Ungültiges
     Padding" und denken, das Programm sei fehlerhaft

  3. ABLENKUNG VOM LERNEN: Die eigentliche Logik (falsches Passwort →
     ungültiges Padding) wird durch technische Details überdeckt

  LÖSUNG: Try-Pattern ohne Exceptions
  Diese Funktion prüft alle Bedingungen, gibt aber nur True/False zurück.
  Kein Exception-Handling nötig, der Debugger bleibt ruhig.

  VERWENDUNG IM PROJEKT:
  In Unit1.pas (entschluesseln_ECBClick und entschluesseln_CBCClick) wird
  diese Funktion verwendet:
```pascal
  if not TryGetPKCS7PadLen(DecryptedPadded, PadLen, 16) then
  begin
    StatusMemo.Lines.Add('FEHLER: Padding ungültig.');
    StatusMemo.Lines.Add('→ Sehr wahrscheinlich falsches Passwort');
    Exit;
  end;
```

  FUNKTIONSWEISE - Gleiche Logik wie PKCS7Unpad, aber ohne Exceptions:

  1. Prüfe, ob Daten leer sind → False statt Exception
  2. Prüfe BlockSize > 0 → False statt Exception
  3. Prüfe Länge ist Vielfaches von BlockSize → False statt Exception
  4. Lese Padding-Länge aus letztem Byte
  5. Prüfe, ob PadLen im gültigen Bereich (1..BlockSize) → False statt Exception
  6. Prüfe, ob alle Padding-Bytes korrekt sind → False statt Exception
  7. Falls alle Prüfungen bestanden: True + PadLen wird gesetzt

  DETAILLIERTE VALIDIERUNG - Schritt für Schritt:

  SCHRITT 1: Leere Daten
  → Keine Daten = kein Padding möglich → False

  SCHRITT 2: BlockSize-Validierung
  → BlockSize muss positiv sein (typisch 16) → False bei ≤ 0

  SCHRITT 3: Längen-Validierung
  → DataLen mod BlockSize muss 0 sein
  → Beispiel: 17 Bytes bei BlockSize=16 → ungültig → False

  SCHRITT 4: Padding-Byte auslesen
  → PadLen = Data[DataLen - 1]
  → Beispiel: Letztes Byte ist 0x0B → PadLen = 11

  SCHRITT 5: Bereichsprüfung
  → PadLen muss zwischen 1 und BlockSize liegen
  → 0 ist ungültig (kein Padding in PKCS#7)
  → 17 bei BlockSize=16 ist ungültig (zu groß)

  SCHRITT 6: Byte-Wert-Validierung
  → Alle letzten PadLen Bytes müssen den Wert PadLen haben
  → Bei PadLen=11: Letzte 11 Bytes müssen alle 0x0B sein
  → Falls auch nur ein Byte abweicht → False

  BEISPIELE:

  Gültiges Padding:
  Input: [48 65 6C 6C 6F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B]
  → DataLen = 16 ✓
  → 16 mod 16 = 0 ✓
  → PadLen = 0x0B = 11 ✓
  → 11 liegt in 1..16 ✓
  → Letzte 11 Bytes sind alle 0x0B ✓
  → Result = True, PadLen = 11

  Ungültiges Padding (falsches Passwort):
  Input: [7A 3F E2 91 C4 88 0D 5B 2E F1 A3 67 D9 4C B8 73]
  → DataLen = 16 ✓
  → 16 mod 16 = 0 ✓
  → PadLen = 0x73 = 115
  → 115 liegt NICHT in 1..16 ✗
  → Result = False, PadLen = 0

  Ungültiges Padding (manipuliert):
  Input: [48 65 6C 6C 6F 0B 0B 0B 0B 0B 0B 0B 0B 0B 0B 0C]
  → DataLen = 16 ✓
  → 16 mod 16 = 0 ✓
  → PadLen = 0x0C = 12 ✓
  → 12 liegt in 1..16 ✓
  → Prüfe letzte 12 Bytes: Position [4] ist 0x6F, sollte aber 0x0C sein ✗
  → Result = False, PadLen = 0

  Ungültige Länge:
  Input: [48 65 6C 6C 6F] (5 Bytes)
  → DataLen = 5 ✓
  → 5 mod 16 = 5 ≠ 0 ✗
  → Result = False, PadLen = 0

  VERWENDUNG IN DER PRAXIS:
```pascal
  var
    PadLen: Integer;
  begin
    if TryGetPKCS7PadLen(Data, PadLen, 16) then
    begin
      // Padding ist gültig, PadLen enthält die Anzahl
      // Jetzt manuell entpadden:
      OutLen := Length(Data) - PadLen;
      SetLength(PlainBytes, OutLen);
      if OutLen > 0 then
        Move(Data[0], PlainBytes[0], OutLen);
    end
    else
    begin
      // Padding ungültig - vermutlich falsches Passwort
      ShowMessage('Entschlüsselung fehlgeschlagen.');
    end;
  end;
```

  VORTEILE DES TRY-PATTERNS:

  1. KEINE EXCEPTIONS: Debugger bleibt ruhig
  2. KLARER CODE: Einfache if-then-else Struktur
  3. GLEICHE SICHERHEIT: Alle Validierungen wie bei PKCS7Unpad()
  4. LEHRTAUGLICH: Schüler sehen die Logik ohne Ablenkung

  HINWEIS FÜR PRODUKTIVSYSTEME:
  In echten Anwendungen sollte man zusätzlich:
  - Konstante Validierungszeit sicherstellen (gegen Timing-Angriffe)
  - Fehler nicht unterscheidbar machen (gegen Padding Oracle)
  - Logging bei verdächtigen Mustern

  WEITERFÜHRENDE INFORMATIONEN:
  - "Try-Pattern" in modernen Programmiersprachen (TryParse, TryGet, etc.)
  - Best Practices für Exception-Handling in kryptographischem Code
  - Padding Oracle Attacks: Vaudenay (2002)

  ============================================================================
}

var
  DataLen: Integer;      // Länge der Eingabedaten
  I: Integer;            // Laufvariable für die Validierung
begin
  Result := False;         // Optimistisch auf False setzen
  PadLen := 0;             // PadLen auf 0 setzen (ungültig)

  DataLen := Length(Data);

  // --- Grundbedingungen ---
  if DataLen = 0 then
    Exit;

  if BlockSize <= 0 then
    Exit;

  if (DataLen mod BlockSize) <> 0 then
    Exit;

  // --- Padding-Länge aus letztem Byte ---
  PadLen := Data[DataLen - 1];

  if (PadLen <= 0) or (PadLen > BlockSize) then
  begin
    PadLen := 0;
    Exit;
  end;

  // --- Prüfen ob die letzten PadLen Bytes wirklich = PadLen sind ---
  for I := DataLen - PadLen to DataLen - 1 do
  begin
    if Data[I] <> PadLen then
    begin
      PadLen := 0;
      Exit;
    end;
  end;

  Result := True;
end;

function IsValidPKCS7Padding(const Data: TBytes; BlockSize: Integer): Boolean;
{
  ============================================================================
  IsValidPKCS7Padding - Einfacher Wrapper für Padding-Validierung
  ============================================================================

  ZWECK:
  Bietet eine vereinfachte Schnittstelle zur Padding-Validierung, wenn man
  nur wissen möchte "ist das Padding gültig?" ohne die genaue Padding-Länge
  zu benötigen.

  PARAMETER:
  - Data: Die zu prüfenden Daten
  - BlockSize: Die Blockgröße in Bytes (Standard: 16 für AES)

  RÜCKGABEWERT:
  - Boolean: True = Padding ist gültig, False = Padding ist ungültig

  HINTERGRUND:
  Diese Funktion ist ein einfacher "Wrapper" (Umhüllung) um
  TryGetPKCS7PadLen(). Sie ruft intern TryGetPKCS7PadLen() auf, ignoriert
  aber die zurückgegebene PadLen und gibt nur das Validierungsergebnis zurück.

  VERWENDUNG:
  Nützlich, wenn man nur eine Ja/Nein-Antwort braucht, z.B.:
```pascal
  if IsValidPKCS7Padding(DecryptedData, 16) then
    ProcessData(DecryptedData)
  else
    ShowMessage('Ungültige Daten oder falsches Passwort');
```

  UNTERSCHIED ZU TryGetPKCS7PadLen:

  TryGetPKCS7PadLen():
  - Gibt True/False UND die Padding-Länge zurück
  - Verwendung, wenn man die Daten entpadden möchte

  IsValidPKCS7Padding():
  - Gibt nur True/False zurück
  - Verwendung, wenn man nur validieren möchte

  FUNKTIONSWEISE:
  1. Deklariert eine lokale Variable PadLen
  2. Ruft TryGetPKCS7PadLen() auf
  3. Ignoriert den PadLen-Wert
  4. Gibt nur das Boolean-Ergebnis zurück

  BEISPIEL:
```pascal
  var
    Data: TBytes;
  begin
    Data := [...]; // Irgendwelche Daten

    // Schnelle Validierung:
    if not IsValidPKCS7Padding(Data, 16) then
    begin
      WriteLn('Padding ungültig!');
      Exit;
    end;

    // Hier wissen wir: Padding ist OK
    // Wenn wir jetzt entpadden wollen, nutzen wir TryGetPKCS7PadLen()
  end;
```

  DESIGN-PATTERN:
  Dies ist ein klassisches "Convenience Method" Pattern:
  - Vereinfacht häufige Anwendungsfälle
  - Reduziert Code-Duplikation
  - Macht Code lesbarer

  Statt:
```pascal
  var Dummy: Integer;
  if TryGetPKCS7PadLen(Data, Dummy, 16) then ...
```

  Schreibt man:
```pascal
  if IsValidPKCS7Padding(Data, 16) then ...
```

  PERFORMANCE:
  Kein Performance-Unterschied zu TryGetPKCS7PadLen(), da es nur ein
  dünner Wrapper ist. Der Compiler optimiert solche Aufrufe sehr effizient.

  WEITERFÜHRENDE INFORMATIONEN:
  - Software Design Patterns: "Wrapper Pattern" / "Facade Pattern"
  - Clean Code (Robert C. Martin): Kapitel über Funktionsschnittstellen

  ============================================================================
}
var
  PadLen: Integer;
begin
     // Ruft die vollständige Validierungsfunktion auf
     // Ignoriert die zurückgegebene Padding-Länge (PadLen)
     // Gibt nur das Validierungsergebnis (True/False) zurück
  Result := TryGetPKCS7PadLen(Data, PadLen, BlockSize);
end;

procedure BlockToState(const Block: TByteArray16; out State: TAESState);
{
  ============================================================================
  BlockToState - Konvertiert einen 16-Byte-Block in eine AES State-Matrix
  ============================================================================

  ZWECK:
  Wandelt einen linearen 16-Byte-Block in die AES State-Matrix (4×4 Bytes)
  um. Dies ist der erste Schritt jeder AES-Blockoperation.

  PARAMETER:
  - Block: Eingabe als lineares Array von 16 Bytes [0..15]
  - State: Ausgabe als 4×4 Matrix [Zeile, Spalte]

  HINTERGRUND - Die AES State-Matrix:

  AES wurde von Joan Daemen und Vincent Rijmen (daher "Rijndael") so
  entworfen, dass es intern mit einer 4×4-Matrix arbeitet. Warum?

  1. MATHEMATISCHE STRUKTUR: Die Matrix-Darstellung ermöglicht elegante
     mathematische Operationen (MixColumns arbeitet spaltenweise)

  2. DIFFUSION: Durch die 2D-Anordnung verteilen sich Änderungen besser
     über den gesamten Block (Claude Shannon's Diffusionsprinzip)

  3. HARDWARE-OPTIMIERUNG: Die Matrix-Struktur lässt sich effizient
     in Hardware implementieren (parallele Verarbeitung)

  4. ALGEBRAISCHE EIGENSCHAFTEN: Die Spalten können als Polynome im
     Galois-Feld GF(2^8) interpretiert werden

  DIE ABBILDUNG - Column-Major Order:

  WICHTIG: AES verwendet "Column-Major" (spaltenweise) Anordnung!

  Die 16 Bytes des Blocks werden SPALTENWEISE in die Matrix eingetragen:

  Block (linear):
  [B0, B1, B2, B3, B4, B5, B6, B7, B8, B9, B10, B11, B12, B13, B14, B15]

  State (Matrix):
       Spalte 0  Spalte 1  Spalte 2  Spalte 3
  Zeile 0:  B0       B4       B8       B12
  Zeile 1:  B1       B5       B9       B13
  Zeile 2:  B2       B6       B10      B14
  Zeile 3:  B3       B7       B11      B15

  NICHT (wie man vielleicht erwarten würde):
  Zeile 0:  B0  B1  B2  B3    ← Das wäre Row-Major!
  Zeile 1:  B4  B5  B6  B7
  ...

  WARUM COLUMN-MAJOR?

  1. MIXCOLUMNS-OPERATION: MixColumns arbeitet spaltenweise, daher ist
     es effizienter, die Daten spaltenweise anzuordnen

  2. FIPS 197 STANDARD: Der offizielle AES-Standard definiert diese
     Anordnung explizit (siehe FIPS 197, Sektion 3.4)

  3. KONSISTENZ: Alle AES-Implementierungen weltweit verwenden diese
     Konvention, was Interoperabilität garantiert

  KONKRETES BEISPIEL:

  Block-Bytes (Hex):
  [00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0A, 0B, 0C, 0D, 0E, 0F]

  Wird zu State:
       [0]  [1]  [2]  [3]
  [0]  00   04   08   0C
  [1]  01   05   09   0D
  [2]  02   06   0A   0E
  [3]  03   07   0B   0F

  Zugriff auf einzelne Elemente:
  - State[0,0] = 0x00 (Block[0])
  - State[1,2] = 0x09 (Block[9])
  - State[3,3] = 0x0F (Block[15])

  FUNKTIONSWEISE - Die Doppelschleife:

  Die äußere Schleife läuft über die Spalten (Col: 0..3)
  Die innere Schleife läuft über die Zeilen (Row: 0..3)

  Für jede Position (Row, Col):
  - Berechne den Index im linearen Block-Array
  - Index = Col * 4 + Row (Column-Major Formel!)
  - Kopiere Block[Index] nach State[Row, Col]

  FORMEL-HERLEITUNG:

  Position State[Row, Col] entspricht Block[Index]
  Index = Col * 4 + Row

  Beispiele:
  - State[0,0] → Index = 0*4 + 0 = 0  → Block[0]
  - State[1,0] → Index = 0*4 + 1 = 1  → Block[1]
  - State[2,1] → Index = 1*4 + 2 = 6  → Block[6]
  - State[3,3] → Index = 3*4 + 3 = 15 → Block[15]

  SPEICHERLAYOUT-VERGLEICH:

  Block (linear im Speicher):
  Adresse: 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
  Wert:    B0 B1 B2 B3 B4 B5 B6 B7 B8 B9 B10 B11 B12 B13 B14 B15

  State (konzeptionell 2D, aber auch linear im Speicher):
  Adresse: [0,0] [1,0] [2,0] [3,0] [0,1] [1,1] ... [3,3]
  Wert:    B0    B1    B2    B3    B4    B5    ... B15

  Die Column-Major Anordnung bedeutet, dass die Speicherreihenfolge
  gleich bleibt - wir ändern nur die Interpretation (1D → 2D).

  SYMMETRIE:
  StateToBlock() ist die exakte Umkehrfunktion:
  StateToBlock(BlockToState(Block)) = Block

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 3.4: "State" - definiert die Matrix-Anordnung
  - FIPS 197, Appendix B: Visualisierung der State-Transformation
  - "The Design of Rijndael" (Daemen & Rijmen, 2002), Kapitel 3.2
  - Column-Major vs Row-Major: Wikipedia "Row- and column-major order"

  ============================================================================
}
var
  Row, Col: Integer;      // Laufvariablen für Zeile und Spalte
  Index: Integer;        // Index im linearen Block-Array
begin
  Index := 0;  // Index für den linearen Block startet bei 0
   // Äußere Schleife: Spalten durchlaufen (0..3)
  // WICHTIG: Spalten ZUERST wegen Column-Major Order!
  for Col := 0 to 3 do
    for Row := 0 to 3 do
      // Aktuelles Byte aus Block in State-Matrix übertragen
      // State[Row, Col] bekommt das Byte an Position Index
    begin
      State[Row, Col] := Block[Index];
      Inc(Index);      // Index für das nächste Byte erhöhen
       // Nach dieser Operation:
      // - Index zeigt auf das nächste zu verarbeitende Byte
      // - State[Row, Col] enthält das korrekte Byte aus dem Block
    end;
  // Nach beiden Schleifen:
  // - Index = 16 (alle Bytes verarbeitet)
  // - State enthält die vollständige 4×4 Matrix in Column-Major Order
  // - State[Row, Col] = Block[Col * 4 + Row] für alle Row, Col
end;

procedure StateToBlock(const State: TAESState; out Block: TByteArray16);
{
  ============================================================================
  StateToBlock - Konvertiert eine AES State-Matrix zurück in einen Block
  ============================================================================

  ZWECK:
  Wandelt die AES State-Matrix (4×4 Bytes) zurück in einen linearen
  16-Byte-Block um. Dies ist die Umkehrung von BlockToState() und wird
  am Ende jeder AES-Blockoperation benötigt.

  PARAMETER:
  - State: Eingabe als 4×4 Matrix [Zeile, Spalte]
  - Block: Ausgabe als lineares Array von 16 Bytes [0..15]

  HINTERGRUND:

  Nach allen AES-Transformationen (SubBytes, ShiftRows, MixColumns,
  AddRoundKey) liegt das Ergebnis als State-Matrix vor. Um es als
  Ciphertext auszugeben oder für weitere Blockoperationen zu verwenden,
  muss es zurück in die lineare Block-Form konvertiert werden.

  DIE RÜCK-ABBILDUNG - Column-Major Order (identisch):

  State (Matrix):
       Spalte 0  Spalte 1  Spalte 2  Spalte 3
  Zeile 0:  S0,0     S0,1     S0,2     S0,3
  Zeile 1:  S1,0     S1,1     S1,2     S1,3
  Zeile 2:  S2,0     S2,1     S2,2     S2,3
  Zeile 3:  S3,0     S3,1     S3,2     S3,3

  Block (linear):
  [S0,0, S1,0, S2,0, S3,0, S0,1, S1,1, S2,1, S3,1, ...]
   B0    B1    B2    B3    B4    B5    B6    B7   ...

  Die Matrix wird SPALTENWEISE ausgelesen:
  1. Erste Spalte (Col=0): S0,0, S1,0, S2,0, S3,0 → Block[0..3]
  2. Zweite Spalte (Col=1): S0,1, S1,1, S2,1, S3,1 → Block[4..7]
  3. Dritte Spalte (Col=2): S0,2, S1,2, S2,2, S3,2 → Block[8..11]
  4. Vierte Spalte (Col=3): S0,3, S1,3, S2,3, S3,3 → Block[12..15]

  KONKRETES BEISPIEL (Rückwärts):

  State:
       [0]  [1]  [2]  [3]
  [0]  00   04   08   0C
  [1]  01   05   09   0D
  [2]  02   06   0A   0E
  [3]  03   07   0B   0F

  Wird zu Block:
  [00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0A, 0B, 0C, 0D, 0E, 0F]

  FUNKTIONSWEISE - Identische Schleifenstruktur:

  Die Implementierung ist IDENTISCH zu BlockToState(), nur die
  Kopierrichtung ist umgekehrt:

  BlockToState: Block[Index] → State[Row, Col]
  StateToBlock: State[Row, Col] → Block[Index]

  Dies ist kein Zufall, sondern Absicht:
  - Column-Major Order ist symmetrisch
  - Die gleiche Index-Berechnung funktioniert in beide Richtungen
  - Einfacher zu verstehen und zu verifizieren

  FORMEL (identisch):

  Block[Index] entspricht State[Row, Col]
  Index = Col * 4 + Row

  WICHTIGE EIGENSCHAFT - Inverse Funktionen:

  Für alle Block b und alle State s gilt:
  1. StateToBlock(BlockToState(b)) = b (Identität)
  2. BlockToState(StateToBlock(s)) = s (Identität)

  Diese Eigenschaft ist essentiell für AES, da:
  - Verschlüsselung: Block → State → Transformationen → State → Block
  - Die Konvertierungen dürfen keine Information verlieren
  - Jede Abweichung würde die Entschlüsselung unmöglich machen

  VERWENDUNG IN AES:

  Verschlüsselung (AES256EncryptBlock):
```pascal
  BlockToState(InBlock, State);           // 1. Block → State
  // ... SubBytes, ShiftRows, MixColumns, AddRoundKey ...
  StateToBlock(State, OutBlock);          // 2. State → Block
```

  Entschlüsselung (AES256DecryptBlock):
```pascal
  BlockToState(InBlock, State);           // 1. Block → State
  // ... InvSubBytes, InvShiftRows, InvMixColumns, AddRoundKey ...
  StateToBlock(State, OutBlock);          // 2. State → Block
```

  PERFORMANCE-HINWEIS:

  Diese Konvertierung ist sehr schnell:
  - Nur 16 Byte-Kopieroperationen
  - Keine Berechnungen, nur Umordnung
  - Moderne CPUs können dies in wenigen Takten erledigen
  - Bei Hardware-AES (AES-NI) entfällt die Konvertierung komplett,
    da die CPU-Instruktionen direkt mit der internen Darstellung arbeiten

  MEMORY LAYOUT:

  Sowohl Block als auch State sind kontinuierlich im Speicher:
  - Block: 16 Bytes hintereinander
  - State: 16 Bytes hintereinander (trotz 2D-Deklaration)
  - Nur die Interpretation/Zugriffsmuster unterscheiden sich

  DEBUGGING-TIPP:

  Bei der Fehlersuche ist es hilfreich, beide Darstellungen zu sehen:
  - Block-Form: Gut für Hex-Dumps und Vergleiche mit Testvektoren
  - State-Form: Gut für das Verständnis der Transformationen

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 3.4: State-Definition
  - FIPS 197, Sektion 5: Cipher-Algorithmus (zeigt den Einsatz)
  - "The Design of Rijndael", Kapitel 3: State und Operationen
  - Numerische Datenstrukturen: "Array Layout in Memory"

  ============================================================================
}

var
  Row, Col: Integer;         // Laufvariablen für Zeile und Spalte
  Index: Integer;            // Index im linearen Block-Array
begin
  Index := 0;                // Index für den linearen Block startet bei 0

  // Äußere Schleife: Spalten durchlaufen (0..3)
  // Gleiche Reihenfolge wie bei BlockToState (Column-Major!)
  for Col := 0 to 3 do
    for Row := 0 to 3 do     // Innere Schleife: Zeilen durchlaufen (0..3)
    begin
       // Aktuelles Byte aus State-Matrix in Block übertragen
      // Block[Index] bekommt das Byte an Position State[Row, Col]
      Block[Index] := State[Row, Col];
      Inc(Index);    // Index für das nächste Byte erhöhen
        // Nach dieser Operation:
      // - Index zeigt auf die nächste Position im Block
      // - Block[Index-1] enthält das korrekte Byte aus State
    end;
  // Nach beiden Schleifen:
  // - Index = 16 (alle Bytes übertragen)
  // - Block enthält die 16 Bytes in linearer Column-Major Anordnung
  // - Block[Col * 4 + Row] = State[Row, Col] für alle Row, Col

  // GARANTIE: StateToBlock(BlockToState(Block)) = Block (Identität)
end;

procedure ShiftRowsState(var State: TAESState);
{
  ============================================================================
  ShiftRowsState - Zyklische Verschiebung der Zeilen in der State-Matrix
  ============================================================================

  ZWECK:
  Verschiebt jede Zeile der State-Matrix um eine bestimmte Anzahl von
  Positionen nach links. Dies ist eine der vier Haupttransformationen
  in AES und sorgt für Diffusion zwischen den Spalten.

  PARAMETER:
  - State: Die 4×4 State-Matrix (wird direkt modifiziert, call-by-reference)

  RÜCKGABEWERT:
  - Keiner (die State-Matrix wird in-place modifiziert)

  HINTERGRUND - ShiftRows im AES-Kontext:

  ShiftRows ist eine lineare Transformation, die zusammen mit MixColumns
  für die Diffusion in AES sorgt. Während SubBytes für Konfusion sorgt
  (komplexe Beziehung zwischen Input und Output), sorgen ShiftRows und
  MixColumns für Diffusion (Verteilung von Änderungen über den gesamten Block).

  ROLLE IM AES-ALGORITHMUS:

  ShiftRows wird in JEDER Verschlüsselungs-Runde angewendet:
  - Runden 1-13: SubBytes → ShiftRows → MixColumns → AddRoundKey
  - Runde 14: SubBytes → ShiftRows → AddRoundKey (ohne MixColumns)

  DIFFUSION nach Claude Shannon (1949):

  Shannon definierte "Diffusion" als kryptographisches Prinzip:
  → Jedes Bit des Plaintexts soll möglichst viele Bits des Ciphertexts
     beeinflussen
  → Statistische Strukturen im Plaintext sollen im Ciphertext verschwinden
  → Kleine Änderungen im Input sollen große Änderungen im Output bewirken

  ShiftRows trägt wesentlich zur Diffusion bei, indem es Bytes zwischen
  den Spalten vermischt.

  DIE VERSCHIEBUNGSREGEL - Einfach aber wirkungsvoll:

  Jede Zeile wird um eine andere Anzahl von Positionen nach LINKS verschoben:

  - Zeile 0: Keine Verschiebung (bleibt unverändert)
  - Zeile 1: 1 Position nach links (zyklisch)
  - Zeile 2: 2 Positionen nach links (zyklisch)
  - Zeile 3: 3 Positionen nach links (zyklisch)

  "Zyklisch" bedeutet: Bytes, die links herausfallen, werden rechts
  wieder eingefügt (wie bei einem Rotations-Register).

  VISUELLE DARSTELLUNG:

  Vorher:
       Spalte 0  Spalte 1  Spalte 2  Spalte 3
  Zeile 0:  A0       A1       A2       A3    ← bleibt
  Zeile 1:  B0       B1       B2       B3    ← 1 nach links
  Zeile 2:  C0       C1       C2       C3    ← 2 nach links
  Zeile 3:  D0       D1       D2       D3    ← 3 nach links

  Nachher:
       Spalte 0  Spalte 1  Spalte 2  Spalte 3
  Zeile 0:  A0       A1       A2       A3    (unverändert)
  Zeile 1:  B1       B2       B3       B0    (B0 wandert nach rechts)
  Zeile 2:  C2       C3       C0       C1    (C0,C1 wandern nach rechts)
  Zeile 3:  D3       D0       D1       D2    (D0,D1,D2 wandern nach rechts)

  KONKRETE BYTE-BEWEGUNGEN:

  Zeile 1 (1 Position nach links):
  - B0 (war Spalte 0) → geht nach Spalte 3
  - B1 (war Spalte 1) → geht nach Spalte 0
  - B2 (war Spalte 2) → geht nach Spalte 1
  - B3 (war Spalte 3) → geht nach Spalte 2

  Zeile 2 (2 Positionen nach links):
  - C0 (war Spalte 0) → geht nach Spalte 2
  - C1 (war Spalte 1) → geht nach Spalte 3
  - C2 (war Spalte 2) → geht nach Spalte 0
  - C3 (war Spalte 3) → geht nach Spalte 1

  Zeile 3 (3 Positionen nach links):
  - D0 (war Spalte 0) → geht nach Spalte 1
  - D1 (war Spalte 1) → geht nach Spalte 2
  - D2 (war Spalte 2) → geht nach Spalte 3
  - D3 (war Spalte 3) → geht nach Spalte 0

  WARUM DIESE VERSCHIEBUNGEN?

  1. SPALTEN-DURCHMISCHUNG: Bytes aus verschiedenen Spalten werden gemischt
     → Nach ShiftRows + MixColumns beeinflussen sich alle Bytes gegenseitig

  2. OPTIMALE DIFFUSION: Die Verschiebungen (0,1,2,3) wurden von Daemen und
     Rijmen so gewählt, dass zusammen mit MixColumns maximale Diffusion
     erreicht wird

  3. EINFACHHEIT: Die Regel ist einfach zu implementieren (auch in Hardware)
     und hat minimalen Performance-Overhead

  4. SYMMETRIE: Die Verschiebungen sind für AES-128, AES-192 und AES-256
     identisch (nur Rundenzahl unterscheidet sich)

  ZUSAMMENSPIEL MIT MIXCOLUMNS:

  ShiftRows alleine würde nur Bytes innerhalb der Zeilen vermischen.
  MixColumns alleine würde nur Bytes innerhalb der Spalten vermischen.

  ZUSAMMEN ergeben sie vollständige Diffusion:
  1. SubBytes macht Bytes nichtlinear abhängig vom Input
  2. ShiftRows verteilt Bytes über verschiedene Spalten
  3. MixColumns mischt Bytes innerhalb jeder Spalte
  → Nach 2-3 Runden: Jedes Output-Bit hängt von allen Input-Bits ab!

  IMPLEMENTIERUNG - Temporäre Variable für Rotation:

  Für jede Zeile wird ein temporäres Byte verwendet, um die zyklische
  Verschiebung zu realisieren:

  Zeile 1 (Rotation nach links um 1):
  - Temp = erstes Element
  - Verschiebe Elemente 1,2,3 um eine Position nach links
  - Setze letztes Element = Temp

  Dies ist der klassische "Rotations-Algorithmus" für Arrays.

  FUNKTIONSWEISE - Zeile für Zeile:

  ZEILE 0: Keine Operation (bleibt unverändert)

  ZEILE 1: Rotation um 1 Position nach links
```
  Temp := State[1,0];         // Erstes Element retten
  State[1,0] := State[1,1];   // Element 1 nach Position 0
  State[1,1] := State[1,2];   // Element 2 nach Position 1
  State[1,2] := State[1,3];   // Element 3 nach Position 2
  State[1,3] := Temp;         // Gerettetes Element nach Position 3
```

  ZEILE 2: Rotation um 2 Positionen (= 2× Paar-Tausch)
```
  Temp := State[2,0];         // Erstes Paar: 0 ↔ 2
  State[2,0] := State[2,2];
  State[2,2] := Temp;

  Temp := State[2,1];         // Zweites Paar: 1 ↔ 3
  State[2,1] := State[2,3];
  State[2,3] := Temp;
```

  ZEILE 3: Rotation um 3 Positionen nach links = 1 Position nach rechts
```
  Temp := State[3,3];         // Letztes Element retten
  State[3,3] := State[3,2];   // Element 2 nach Position 3
  State[3,2] := State[3,1];   // Element 1 nach Position 2
  State[3,1] := State[3,0];   // Element 0 nach Position 1
  State[3,0] := Temp;         // Gerettetes Element nach Position 0
```

  PERFORMANCE:

  ShiftRows ist extrem schnell:
  - Nur 12 Byte-Bewegungen (Zeilen 1-3, je 4 Bytes)
  - Keine Berechnungen, nur Kopieroperationen
  - In moderner Hardware oft in einem Taktzyklus
  - Mit AES-NI (CPU-Instruktionen) quasi kostenlos

  BEISPIEL MIT HEX-WERTEN:

  Vorher:
       [0]  [1]  [2]  [3]
  [0]  87   F2   4D   97
  [1]  6E   4C   90   EC
  [2]  46   E7   4A   C3
  [3]  A6   8C   D8   95

  Nach ShiftRows:
       [0]  [1]  [2]  [3]
  [0]  87   F2   4D   97   (unverändert)
  [1]  4C   90   EC   6E   (um 1 nach links)
  [2]  4A   C3   46   E7   (um 2 nach links)
  [3]  95   A6   8C   D8   (um 3 nach links = 1 nach rechts)

  SYMMETRIE MIT INVSHIFTROWS:

  InvShiftRowsState() ist die exakte Umkehrung:
  - Verschiebt nach RECHTS statt nach LINKS
  - Gleiche Anzahl Positionen (0,1,2,3)

  Für alle State S gilt:
  InvShiftRowsState(ShiftRowsState(S)) = S

  SICHERHEITSASPEKT:

  Ohne ShiftRows wäre AES anfällig für spaltenweise Angriffe:
  - Jede Spalte würde isoliert transformiert
  - Angreifer könnten die 4 Spalten separat analysieren
  - Die effektive Schlüssellänge würde sinken

  ShiftRows verhindert dies durch Vermischung der Spalten!

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.1.2: ShiftRows Transformation
  - FIPS 197, Figure 8: Visuelle Darstellung der Verschiebungen
  - "The Design of Rijndael" (Daemen & Rijmen), Kapitel 3.5
  - Claude Shannon (1949): "Communication Theory of Secrecy Systems"
  - "Wide Trail Strategy" - Design-Prinzip von AES (Daemen & Rijmen)

  ============================================================================
}
var
  Temp: Byte;         // Temporäre Variable für die zyklische Rotation
begin
  // Zeile 0 bleibt
   // ZEILE 0: Bleibt unverändert (keine Verschiebung)
  // Keine Operation nötig

  // -------------------------------------------------------------------------
  // ZEILE 1: Rotation um 1 Position nach links
  // -------------------------------------------------------------------------
  // Vorher: [B0, B1, B2, B3]
  // Nachher: [B1, B2, B3, B0]

  // Zeile 1
  Temp := State[1,0];            // Erstes Element (B0) temporär sichern
  State[1,0] := State[1,1];       // B1 nach Position 0 verschieben
  State[1,1] := State[1,2];       // B2 nach Position 1 verschieben
  State[1,2] := State[1,3];       // B3 nach Position 2 verschieben
  State[1,3] := Temp;             // Gesichertes B0 nach Position 3
   // Ergebnis: Die Zeile wurde um 1 Position zyklisch nach links rotiert

  // -------------------------------------------------------------------------
  // ZEILE 2: Rotation um 2 Positionen nach links
  // -------------------------------------------------------------------------
  // Vorher: [C0, C1, C2, C3]
  // Nachher: [C2, C3, C0, C1]
  // Strategie: 2 Positionen = Tausche Paare (0↔2) und (1↔3)


  // Zeile 2
  // Erstes Paar tauschen: Position 0 ↔ Position 2
  Temp := State[2,0];             // C0 temporär sichern
  State[2,0] := State[2,2];       // C2 nach Position 0
  State[2,2] := Temp;              // Gesichertes C0 nach Position 2

   // Zweites Paar tauschen: Position 1 ↔ Position 3
  Temp := State[2,1];              // C1 temporär sichern
  State[2,1] := State[2,3];        // C3 nach Position 1
  State[2,3] := Temp;              // Gesichertes C1 nach Position 3

  // Ergebnis: Die Zeile wurde um 2 Positionen zyklisch nach links rotiert

  // -------------------------------------------------------------------------
  // ZEILE 3: Rotation um 3 Positionen nach links
  // -------------------------------------------------------------------------
  // Vorher: [D0, D1, D2, D3]
  // Nachher: [D3, D0, D1, D2]
  // TRICK: 3 nach links = 1 nach rechts (bei 4 Elementen)
  // Strategie: Letztes Element nach vorne holen, Rest nach rechts schieben


  // Zeile 3
  Temp := State[3,3];                  // Letztes Element (D3) temporär sichern
  State[3,3] := State[3,2];            // D2 nach Position 3 verschieben
  State[3,2] := State[3,1];            // D1 nach Position 2 verschieben
  State[3,1] := State[3,0];              // D0 nach Position 1 verschieben
  State[3,0] := Temp;                   // Gesichertes D3 nach Position 0

   // Ergebnis: Die Zeile wurde um 3 Positionen zyklisch nach links rotiert
  // (was äquivalent zu 1 Position nach rechts ist)

  // Nach allen Operationen:
  // - Zeile 0: unverändert
  // - Zeile 1: um 1 Position nach links verschoben
  // - Zeile 2: um 2 Positionen nach links verschoben
  // - Zeile 3: um 3 Positionen nach links verschoben
  // Die Diffusion zwischen den Spalten ist hergestellt
end;

procedure InvShiftRowsState(var State: TAESState);
{
  ============================================================================
  InvShiftRowsState - Inverse zyklische Verschiebung der Zeilen
  ============================================================================

  ZWECK:
  Macht die ShiftRows-Transformation rückgängig, indem jede Zeile um die
  gleiche Anzahl von Positionen nach RECHTS verschoben wird. Dies wird
  beim Entschlüsseln benötigt.

  PARAMETER:
  - State: Die 4×4 State-Matrix (wird direkt modifiziert, call-by-reference)

  RÜCKGABEWERT:
  - Keiner (die State-Matrix wird in-place modifiziert)

  HINTERGRUND - Inverse Transformation:

  InvShiftRows kehrt die Wirkung von ShiftRows exakt um. Da ShiftRows
  nach LINKS verschiebt, verschiebt InvShiftRows nach RECHTS.

  ROLLE IN AES-ENTSCHLÜSSELUNG:

  InvShiftRows wird in JEDER Entschlüsselungs-Runde angewendet:
  - Runde 14: AddRoundKey → InvShiftRows → InvSubBytes
  - Runden 13-1: AddRoundKey → InvMixColumns → InvShiftRows → InvSubBytes
  - Runde 0: AddRoundKey

  DIE INVERSE VERSCHIEBUNGSREGEL:

  Jede Zeile wird um die gleiche Anzahl von Positionen nach RECHTS verschoben:

  - Zeile 0: Keine Verschiebung (bleibt unverändert)
  - Zeile 1: 1 Position nach rechts (= 3 nach links)
  - Zeile 2: 2 Positionen nach rechts (= 2 nach links, symmetrisch!)
  - Zeile 3: 3 Positionen nach rechts (= 1 nach links)

  WICHTIGE BEOBACHTUNG:
  - Links 1 ↔ Rechts 3 (bei 4 Elementen)
  - Links 2 ↔ Rechts 2 (symmetrisch!)
  - Links 3 ↔ Rechts 1

  VISUELLE DARSTELLUNG:

  Nach ShiftRows (verschlüsselt):
       Spalte 0  Spalte 1  Spalte 2  Spalte 3
  Zeile 0:  A0       A1       A2       A3
  Zeile 1:  B1       B2       B3       B0
  Zeile 2:  C2       C3       C0       C1
  Zeile 3:  D3       D0       D1       D2

  Nach InvShiftRows (zurück zum Original):
       Spalte 0  Spalte 1  Spalte 2  Spalte 3
  Zeile 0:  A0       A1       A2       A3    (unverändert)
  Zeile 1:  B0       B1       B2       B3    (B0 wandert nach links)
  Zeile 2:  C0       C1       C2       C3    (C0,C1 wandern nach links)
  Zeile 3:  D0       D1       D2       D3    (D0,D1,D2 wandern nach links)

  IMPLEMENTIERUNG - Spiegelung von ShiftRows:

  Die Implementierung ist strukturell identisch zu ShiftRows, aber die
  Verschiebungsrichtung ist umgekehrt:

  ShiftRows Zeile 1: [B0,B1,B2,B3] → [B1,B2,B3,B0] (1 nach links)
  InvShiftRows Zeile 1: [B1,B2,B3,B0] → [B0,B1,B2,B3] (1 nach rechts)

  FUNKTIONSWEISE - Zeile für Zeile:

  ZEILE 0: Keine Operation (identisch zu ShiftRows)

  ZEILE 1: Rotation um 1 Position nach RECHTS
```
  Temp := State[1,3];         // Letztes Element retten
  State[1,3] := State[1,2];   // Element 2 nach Position 3
  State[1,2] := State[1,1];   // Element 1 nach Position 2
  State[1,1] := State[1,0];   // Element 0 nach Position 1
  State[1,0] := Temp;         // Gerettetes Element nach Position 0
```

  ZEILE 2: Rotation um 2 Positionen (IDENTISCH zu ShiftRows!)
  → 2 nach links = 2 nach rechts bei 4 Elementen (symmetrisch)
```
  Temp := State[2,0];         // Paar-Tausch 0 ↔ 2
  State[2,0] := State[2,2];
  State[2,2] := Temp;

  Temp := State[2,1];         // Paar-Tausch 1 ↔ 3
  State[2,1] := State[2,3];
  State[2,3] := Temp;
```

  ZEILE 3: Rotation um 3 Positionen nach RECHTS = 1 nach LINKS
```
  Temp := State[3,0];         // Erstes Element retten
  State[3,0] := State[3,1];   // Element 1 nach Position 0
  State[3,1] := State[3,2];   // Element 2 nach Position 1
  State[3,2] := State[3,3];   // Element 3 nach Position 2
  State[3,3] := Temp;         // Gerettetes Element nach Position 3
```

  SYMMETRIE-EIGENSCHAFT:

  Für alle State-Matrizen S gilt:
  InvShiftRowsState(ShiftRowsState(S)) = S
  ShiftRowsState(InvShiftRowsState(S)) = S

  Diese Eigenschaft ist essentiell für die Korrektheit von AES!

  BESONDERHEIT ZEILE 2:

  Zeile 2 ist bei ShiftRows und InvShiftRows IDENTISCH, da:
  - 2 Positionen nach links = 2 Positionen nach rechts (bei 4 Elementen)
  - Die Operation ist selbst-invers
  - Mathematisch: Rotation um n/2 bei n Elementen ist selbst-invers

  BEISPIEL MIT HEX-WERTEN (Rückwärts):

  Nach ShiftRows:
       [0]  [1]  [2]  [3]
  [0]  87   F2   4D   97
  [1]  4C   90   EC   6E
  [2]  4A   C3   46   E7
  [3]  95   A6   8C   D8

  Nach InvShiftRows (zurück zum Original):
       [0]  [1]  [2]  [3]
  [0]  87   F2   4D   97   (unverändert)
  [1]  6E   4C   90   EC   (um 1 nach rechts)
  [2]  46   E7   4A   C3   (um 2 nach rechts = wie vorher)
  [3]  A6   8C   D8   95   (um 3 nach rechts = 1 nach links)

  PERFORMANCE:

  Gleiche Performance wie ShiftRows:
  - 12 Byte-Bewegungen
  - Keine Berechnungen
  - Sehr schnell

  CODE-SYMMETRIE:

  Man erkennt die Symmetrie zum ShiftRows-Code:
  - Zeile 1: Rotation nach rechts statt links
  - Zeile 2: Identischer Code (selbst-invers!)
  - Zeile 3: Rotation nach links statt rechts

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.3.1: InvShiftRows Transformation
  - FIPS 197, Figure 13: Visuelle Darstellung der inversen Verschiebungen
  - "The Design of Rijndael", Kapitel 4: Inverse Cipher
  - Mathematik der zyklischen Gruppen: Rotation und Inverse

  ============================================================================
}
var
  Temp: Byte;         // Temporäre Variable für die zyklische Rotation
begin
  // Zeile 0 bleibt
  // ZEILE 0: Bleibt unverändert (identisch zu ShiftRows)
  // Keine Operation nötig

  // -------------------------------------------------------------------------
  // ZEILE 1: Rotation um 1 Position nach RECHTS
  // -------------------------------------------------------------------------
  // Vorher: [B1, B2, B3, B0]  (nach ShiftRows)
  // Nachher: [B0, B1, B2, B3]  (zurück zum Original)
  // Strategie: Letztes Element nach vorne, Rest nach rechts schieben

  // Zeile 1: nach rechts
  Temp := State[1,3];             // Letztes Element (B0) temporär sichern
  State[1,3] := State[1,2];       // B3 nach Position 3 verschieben
  State[1,2] := State[1,1];       // B2 nach Position 2 verschieben
  State[1,1] := State[1,0];       // B1 nach Position 1 verschieben
  State[1,0] := Temp;             // Gesichertes B0 nach Position 0

  // -------------------------------------------------------------------------
  // ZEILE 2: Rotation um 2 Positionen (IDENTISCH zu ShiftRows!)
  // -------------------------------------------------------------------------
  // Vorher: [C2, C3, C0, C1]  (nach ShiftRows)
  // Nachher: [C0, C1, C2, C3]  (zurück zum Original)
  // WICHTIG: 2 nach links = 2 nach rechts bei 4 Elementen!
  // Der Code ist EXAKT IDENTISCH zu ShiftRows für Zeile 2

  // Zeile 2: 2er swap
  // Erstes Paar tauschen: Position 0 ↔ Position 2
  Temp := State[2,0];            // C2 temporär sichern
  State[2,0] := State[2,2];      // C0 nach Position 0
  State[2,2] := Temp;            // Gesichertes C2 nach Position 2

  // Zweites Paar tauschen: Position 1 ↔ Position 3
  Temp := State[2,1];            // C3 temporär sichern
  State[2,1] := State[2,3];      // C1 nach Position 1
  State[2,3] := Temp;            // Gesichertes C3 nach Position 3

  // Ergebnis: Die Zeile wurde um 2 Positionen rotiert (Richtung egal!)
  // ShiftRows wurde für Zeile 2 rückgängig gemacht

  // -------------------------------------------------------------------------
  // ZEILE 3: Rotation um 3 Positionen nach RECHTS = 1 Position nach LINKS
  // -------------------------------------------------------------------------
  // Vorher: [D3, D0, D1, D2]  (nach ShiftRows)
  // Nachher: [D0, D1, D2, D3]  (zurück zum Original)
  // TRICK: 3 nach rechts = 1 nach links (bei 4 Elementen)
  // Strategie: Erstes Element nach hinten, Rest nach links schieben


  // Zeile 3: nach links 1
  Temp := State[3,0];               // Erstes Element (D3) temporär sichern
  State[3,0] := State[3,1];         // D0 nach Position 0 verschieben
  State[3,1] := State[3,2];         // D1 nach Position 1 verschieben
  State[3,2] := State[3,3];         // D2 nach Position 2 verschieben
  State[3,3] := Temp;               // Gesichertes D3 nach Position 3

  // Ergebnis: Die Zeile wurde um 3 Positionen zyklisch nach rechts rotiert
  // (was äquivalent zu 1 Position nach links ist)
  // ShiftRows wurde für Zeile 3 rückgängig gemacht

  // Nach allen Operationen:
  // - Alle ShiftRows-Verschiebungen wurden rückgängig gemacht
  // - Die State-Matrix ist in ihrem Zustand vor ShiftRows
  // - GARANTIE: InvShiftRowsState(ShiftRowsState(S)) = S


end;

procedure AddRoundKey(var State: TAESState; const RoundKey: TAESRoundKey);
{
  ============================================================================
  AddRoundKey - XOR der State-Matrix mit einem Rundenschlüssel
  ============================================================================

  ZWECK:
  Verknüpft die State-Matrix mit einem Rundenschlüssel durch bitweise
  XOR-Operation. Dies ist die einzige Stelle im AES-Algorithmus, wo der
  Schlüssel tatsächlich in die Verschlüsselung einfließt.

  PARAMETER:
  - State: Die 4×4 State-Matrix (wird direkt modifiziert, call-by-reference)
  - RoundKey: Der Rundenschlüssel als 4×4 Matrix (wird aus dem AES-Kontext
              bereitgestellt, für jede Runde ein anderer)

  RÜCKGABEWERT:
  - Keiner (die State-Matrix wird in-place modifiziert)

  HINTERGRUND - Die zentrale Rolle von AddRoundKey:

  AddRoundKey ist die EINZIGE Stelle, wo der geheime Schlüssel verwendet wird!
  Alle anderen Operationen (SubBytes, ShiftRows, MixColumns) sind öffentlich
  bekannte, feste Transformationen. Nur AddRoundKey bringt die "Geheimhaltung"
  in AES.

  OHNE AddRoundKey:
  → AES wäre eine rein deterministische, öffentlich bekannte Transformation
  → Jeder könnte verschlüsseln und entschlüsseln
  → Kein Schutz der Daten

  MIT AddRoundKey:
  → Nur wer den Schlüssel kennt, kann die Transformation umkehren
  → Die Sicherheit von AES basiert auf der Geheimhaltung des Schlüssels

  ROLLE IM AES-ALGORITHMUS:

  AddRoundKey wird am häufigsten von allen AES-Operationen aufgerufen:
  - VOR der ersten Runde: AddRoundKey (mit RoundKey[0])
  - In JEDER Runde (1-14): ... → AddRoundKey (mit RoundKey[1..14])
  - Insgesamt 15 mal bei AES-256!

  Ablauf AES-256 Verschlüsselung:
```
  AddRoundKey(State, RoundKey[0])           ← Initial

  for Round := 1 to 13 do
    SubBytes(State)
    ShiftRows(State)
    MixColumns(State)
    AddRoundKey(State, RoundKey[Round])    ← In jeder Runde

  SubBytes(State)
  ShiftRows(State)
  AddRoundKey(State, RoundKey[14])         ← Final
```

  DIE XOR-OPERATION - Einfach aber genial:

  XOR (exklusives ODER) ist eine bitweise Operation mit folgender Wahrheitstabelle:

  A  B  A⊕B
  0  0   0
  0  1   1
  1  0   1
  1  1   0

  In Worten: Das Ergebnis ist 1, wenn A und B unterschiedlich sind.

  WARUM XOR?

  XOR hat einzigartige Eigenschaften, die es ideal für Verschlüsselung machen:

  1. SELBST-INVERS: A ⊕ B ⊕ B = A
     → Dieselbe Operation ver- UND entschlüsselt!
     → Verschlüsselung: Cipher = Plain ⊕ Key
     → Entschlüsselung: Plain = Cipher ⊕ Key (identisch!)

  2. KOMMUTATIV: A ⊕ B = B ⊕ A
     → Reihenfolge egal

  3. ASSOZIATIV: (A ⊕ B) ⊕ C = A ⊕ (B ⊕ C)
     → Klammerung egal

  4. NEUTRALES ELEMENT: A ⊕ 0 = A
     → XOR mit 0 ändert nichts

  5. PERFEKTE DIFFUSION: Jedes Bit des Schlüssels beeinflusst genau ein Bit
     des Ergebnisses direkt

  MATHEMATISCHER BEWEIS - Selbst-Inverse Eigenschaft:

  Gegeben: C = P ⊕ K  (Verschlüsselung)
  Gesucht: P aus C und K

  Lösung:
  C ⊕ K = (P ⊕ K) ⊕ K      // C einsetzen
        = P ⊕ (K ⊕ K)       // Assoziativität
        = P ⊕ 0             // K ⊕ K = 0
        = P                 // P ⊕ 0 = P

  → Entschlüsselung ist IDENTISCH zur Verschlüsselung!

  KONKRETES BEISPIEL - Byte-Ebene:

  State[0,0] = 0x87 = 10000111 (binär)
  RoundKey[0,0] = 0x2B = 00101011 (binär)

  XOR Bit für Bit:
    10000111  (State)
  ⊕ 00101011  (RoundKey)
  -----------
    10101100  = 0xAC (Ergebnis)

  State[0,0] wird zu 0xAC

  BEISPIEL MIT VOLLSTÄNDIGER MATRIX:

  State:
       [0]  [1]  [2]  [3]
  [0]  87   F2   4D   97
  [1]  6E   4C   90   EC
  [2]  46   E7   4A   C3
  [3]  A6   8C   D8   95

  RoundKey:
       [0]  [1]  [2]  [3]
  [0]  2B   7E   15   16
  [1]  28   AE   D2   A6
  [2]  AB   F7   15   88
  [3]  09   CF   4F   3C

  State nach AddRoundKey (State ⊕ RoundKey):
       [0]  [1]  [2]  [3]
  [0]  AC   8C   58   81    (87⊕2B, F2⊕7E, 4D⊕15, 97⊕16)
  [1]  46   E2   42   4A    (6E⊕28, 4C⊕AE, 90⊕D2, EC⊕A6)
  [2]  ED   10   5F   4B    (46⊕AB, E7⊕F7, 4A⊕15, C3⊕88)
  [3]  AF   43   97   A9    (A6⊕09, 8C⊕CF, D8⊕4F, 95⊕3C)

  SCHLÜSSEL-EXPANSION (Key Schedule):

  Die 15 Rundenschlüssel (RoundKey[0..14]) werden NICHT einfach aus dem
  ursprünglichen 256-Bit-Schlüssel kopiert, sondern durch einen komplexen
  Algorithmus (Key Schedule) generiert:

  - Aus dem 32-Byte Hauptschlüssel werden 15 × 16 Bytes = 240 Bytes erzeugt
  - Jeder Rundenschlüssel ist eine 4×4-Matrix (16 Bytes)
  - Die Expansion verwendet SubBytes, Rotationen und Rcon-Konstanten
  - Siehe AES256InitKey() für die Implementierung

  Ziel der Key-Expansion:
  → Jeder Rundenschlüssel soll kryptographisch stark sein
  → Kenntnis eines Rundenschlüssels soll nicht auf andere schließen lassen
  → Diffusion des Hauptschlüssels über alle Runden

  SYMMETRIE - Ver- und Entschlüsselung:

  WICHTIG: AddRoundKey ist bei Ver- und Entschlüsselung IDENTISCH!

  Verschlüsselung: State := State ⊕ RoundKey
  Entschlüsselung: State := State ⊕ RoundKey (gleich!)

  Der Unterschied beim Entschlüsseln:
  - Die Rundenschlüssel werden in UMGEKEHRTER Reihenfolge verwendet
  - Verschlüsselung: RoundKey[0], RoundKey[1], ..., RoundKey[14]
  - Entschlüsselung: RoundKey[14], RoundKey[13], ..., RoundKey[0]

  FUNKTIONSWEISE - Doppelschleife:

  Die Implementierung ist sehr einfach:
  1. Durchlaufe alle Zeilen (0..3)
  2. Durchlaufe alle Spalten (0..3)
  3. Für jede Position [Row, Col]:
     State[Row, Col] := State[Row, Col] ⊕ RoundKey[Row, Col]

  Insgesamt 16 XOR-Operationen (eine pro Byte).

  IN-PLACE MODIFIKATION:

  Die State-Matrix wird direkt modifiziert. Dies ist effizient und entspricht
  der FIPS 197 Spezifikation.

  PERFORMANCE:

  AddRoundKey ist extrem schnell:
  - 16 XOR-Operationen (eine CPU-Instruktion pro Byte)
  - Keine Lookups, keine Berechnungen
  - Auf modernen CPUs in wenigen Nanosekunden
  - Mit AES-NI wird es direkt in die AES-Instruktion integriert

  SICHERHEITSASPEKT - Timing-Sicherheit:

  XOR ist zeitkonstant:
  - Dauert immer gleich lang, unabhängig von den Werten
  - Keine datenabhängigen Verzweigungen
  - Schutz gegen Timing-Angriffe

  HISTORISCHER KONTEXT:

  Die Verwendung von XOR für Schlüsselverknüpfung ist sehr alt:
  - One-Time-Pad (Shannon, 1949): Plaintext ⊕ Schlüssel = Ciphertext
  - DES (1977): Verwendet XOR für Rundenschlüssel
  - AES (2001): Gleiche Technik, aber bessere Gesamtkonstruktion

  WARUM NICHT ANDERE OPERATIONEN?

  Addition (mod 256): Nicht selbst-invers, Ver- und Entschlüsselung unterschiedlich
  AND: Informationsverlust, nicht umkehrbar
  OR: Informationsverlust, nicht umkehrbar
  XOR: ✓ Perfekt! Selbst-invers, keine Information verloren

  AVALANCHE-EFFEKT:

  Ein einzelnes geändertes Bit im Rundenschlüssel ändert genau ein Bit
  im State (direkt). In Kombination mit SubBytes, ShiftRows und MixColumns
  verteilt sich diese Änderung dann über den gesamten Block.

  DEBUGGING-TIPP:

  Beim Testen kann man überprüfen:
  - AddRoundKey zweimal mit gleichem Key anwenden → Original zurück
  - AddRoundKey(State, Key); AddRoundKey(State, Key); → State unverändert

  Dies beweist die Selbst-Inverse-Eigenschaft.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.1.4: AddRoundKey Transformation
  - FIPS 197, Sektion 5.2: Key Expansion
  - "The Design of Rijndael" (Daemen & Rijmen), Kapitel 3.6
  - Claude Shannon (1949): One-Time-Pad und perfekte Sicherheit
  - Boolean Algebra: XOR als Addition in GF(2)
  - NIST SP 800-38A: Block Cipher Modes of Operation

  ============================================================================
}
var
  Row, Col: Integer;          // Laufvariablen für Zeile und Spalte
begin
  for Row := 0 to 3 do        // Äußere Schleife: Alle Zeilen durchlaufen (0..3)
    for Col := 0 to 3 do      // Innere Schleife: Alle Spalten durchlaufen (0..3)
      // XOR-Verknüpfung des State-Bytes mit dem entsprechenden RoundKey-Byte
      // Dies ist die zentrale Operation: State ⊕ RoundKey
      State[Row, Col] := State[Row, Col] xor RoundKey[Row, Col];
      // Nach dieser Operation:
      // - Das Byte an Position [Row, Col] wurde mit dem Schlüssel verknüpft
      // - Die gleiche Operation rückwärts (mit gleichem Key) stellt Original her
      // - Dies ist die EINZIGE Stelle, wo der Schlüssel in AES verwendet wird!



  // Nach beiden Schleifen:
  // - Alle 16 Bytes der State-Matrix wurden mit dem Rundenschlüssel XOR-verknüpft
  // - Der Rundenschlüssel ist jetzt in die State-Matrix "eingemischt"
  // - Bei Verschlüsselung: Bringt Geheimhaltung
  // - Bei Entschlüsselung: Entfernt den Rundenschlüssel wieder (wegen XOR-Symmetrie)

  // KRITISCHE EIGENSCHAFT für AES:
  // AddRoundKey(AddRoundKey(State, Key), Key) = State
  // Dies macht Ver- und Entschlüsselung symmetrisch
end;

function GFMul2(B: Byte): Byte;
{
  ============================================================================
  GFMul2 - Multiplikation mit 2 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 2 im Galois-Feld GF(2^8). Dies ist die
  fundamentale Operation für MixColumns in AES und die Basis für alle
  anderen GF-Multiplikationen.

  PARAMETER:
  - B: Das zu multiplizierende Byte (0..255)

  RÜCKGABEWERT:
  - Byte: Das Ergebnis der Multiplikation B × 2 in GF(2^8)

  HINTERGRUND - Galois-Felder in der Kryptographie:

  AES arbeitet NICHT mit normaler Arithmetik, sondern mit Galois-Feld-
  Arithmetik (benannt nach Évariste Galois, 1811-1832). Warum?

  1. GESCHLOSSENHEIT: Alle Operationen in GF(2^8) bleiben in 8 Bit
     → Kein Überlauf, immer 0..255

  2. INVERTIERBARKEIT: Jedes Element ≠ 0 hat eine multiplikative Inverse
     → Wichtig für Entschlüsselung

  3. DIFFUSION: GF-Arithmetik verteilt Änderungen optimal über alle Bits
     → Sicherheit gegen Kryptoanalyse

  4. HARDWARE-EFFIZIENZ: GF(2^8) Operationen sind sehr schnell in Hardware

  WAS IST GF(2^8)?

  GF(2^8) ist ein endliches Feld mit 256 Elementen (alle 8-Bit-Werte).
  Die Elemente sind Polynome vom Grad < 8 über GF(2):

  Ein Byte b7 b6 b5 b4 b3 b2 b1 b0 repräsentiert das Polynom:
  b7·x^7 + b6·x^6 + b5·x^5 + b4·x^4 + b3·x^3 + b2·x^2 + b1·x + b0

  Beispiel: 0x53 = 01010011 = x^6 + x^4 + x + 1

  ADDITION in GF(2^8):
  → Ist einfach XOR (bitweise, keine Überträge)
  → Beispiel: 0x53 ⊕ 0xCA = 0x99

  MULTIPLIKATION in GF(2^8):
  → Ist Polynom-Multiplikation MODULO einem irreduziblen Polynom
  → AES verwendet: m(x) = x^8 + x^4 + x^3 + x + 1 = 0x11B

  WARUM 0x11B (das irreducible Polynom)?

  Daemen und Rijmen wählten dieses Polynom, weil:
  - Es ist irreduzibel (kann nicht faktorisiert werden)
  - Es garantiert, dass GF(2^8) ein echtes Feld ist
  - Es hat gute kryptographische Eigenschaften
  - Es ist effizient in Hardware implementierbar

  MULTIPLIKATION MIT 2 - Die Grundoperation:

  Multiplikation mit 2 bedeutet "x × Polynom":

  Fall 1: Höchstes Bit ist 0 (Byte < 128):
  → Einfach nach links schieben (b << 1)
  → Kein Überlauf, kein Modulo nötig

  Fall 2: Höchstes Bit ist 1 (Byte ≥ 128):
  → Nach links schieben würde Bit 8 erzeugen (Überlauf)
  → Deshalb: (b << 1) XOR 0x1B
  → 0x1B = niedrige 8 Bits von m(x) = 0x11B

  WARUM 0x1B?

  Das irreducible Polynom ist m(x) = 0x11B = x^8 + x^4 + x^3 + x + 1

  Wenn wir modulo m(x) rechnen und ein x^8 entsteht:
  x^8 ≡ x^4 + x^3 + x + 1 (mod m(x))

  In Binär: x^8 = 100000000, aber modulo m(x) wird es zu:
  00011011 = 0x1B

  DETAILLIERTES BEISPIEL - Fall 1 (kein Überlauf):

  B = 0x53 = 01010011
  Höchstes Bit = 0 → kein Überlauf

  B << 1 = 10100110 = 0xA6
  Ergebnis = 0xA6

  Polynom-Sicht:
  0x53 = x^6 + x^4 + x + 1
  × 2 = x × (x^6 + x^4 + x + 1) = x^7 + x^5 + x^2 + x
  = 10100110 = 0xA6 ✓

  DETAILLIERTES BEISPIEL - Fall 2 (mit Überlauf):

  B = 0xAE = 10101110
  Höchstes Bit = 1 → Überlauf!

  B << 1 = 0x15C (9 Bits!) = 101011100
  Aber wir brauchen nur 8 Bits, also:
  0x5C XOR 0x1B = 01011100 XOR 00011011 = 01000111 = 0x47

  Polynom-Sicht:
  0xAE = x^7 + x^5 + x^3 + x^2 + x
  × 2 = x^8 + x^6 + x^4 + x^3 + x^2

  Jetzt x^8 modulo m(x) ersetzen:
  x^8 ≡ x^4 + x^3 + x + 1 (mod m(x))

  Also: x^8 + x^6 + x^4 + x^3 + x^2
      ≡ (x^4 + x^3 + x + 1) + x^6 + x^4 + x^3 + x^2
      = x^6 + x^2 + x + 1  (x^4 und x^3 heben sich auf in GF(2))
      = 01000111 = 0x47 ✓

  IMPLEMENTIERUNG - Bedingung und XOR:
```pascal
  if (B and $80) <> 0 then
    Result := ((B shl 1) xor $1B) and $FF
  else
    Result := (B shl 1) and $FF;
```

  Schritt für Schritt:
  1. (B and $80): Teste höchstes Bit (Bit 7)
  2. Falls gesetzt: Schiebe und XOR mit 0x1B
  3. Falls nicht gesetzt: Nur schieben
  4. and $FF: Stelle sicher, dass Ergebnis 8 Bit bleibt (Sicherheit)

  ALTERNATIVE IMPLEMENTIERUNG (ohne if):

  Man kann die Verzweigung vermeiden (zeitkonstant):
```pascal
  Mask := -(B >> 7);  // 0x00 oder 0xFF
  Result := (B << 1) xor (0x1B and Mask);
```
  Dies ist schneller in Hardware und sicher gegen Timing-Angriffe.

  WICHTIGKEIT FÜR AES:

  GFMul2 ist die Basis für ALLE MixColumns-Operationen:
  - GFMul3 = GFMul2 + Original
  - GFMul4 = GFMul2(GFMul2(...))
  - Alle anderen Multiplikationen bauen darauf auf

  Ohne GFMul2 kein MixColumns, ohne MixColumns kein sicheres AES!

  PERFORMANCE:

  Sehr schnell:
  - 1 Bitshift
  - 1 Vergleich
  - Eventuell 1 XOR
  - Alles in wenigen CPU-Takten

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 4.2: "Multiplication" in GF(2^8)
  - "The Design of Rijndael", Kapitel 2.1: Finite Field Arithmetic
  - Évariste Galois: Begründer der Galois-Theorie (1830)
  - "A Course in Number Theory and Cryptography" (Neal Koblitz)
  - Abstract Algebra: Finite Fields und Polynomringe

  ============================================================================
}
begin
  // Prüfe, ob das höchste Bit (Bit 7) gesetzt ist
  // $80 = 10000000 in binär
  if (B and $80) <> 0 then
      // FALL 2: Höchstes Bit ist 1 → Überlauf beim Schieben
      // Nach links schieben würde ein 9. Bit erzeugen
      // Deshalb: Nach links schieben UND mit 0x1B XOR-en (Reduktion modulo m(x))
    Result := ((B shl 1) xor $1B) and $FF
  else
      // FALL 1: Höchstes Bit ist 0 → Kein Überlauf
      // Einfach nach links schieben (entspricht Multiplikation mit x)
    Result := (B shl 1) and $FF;
  // and $FF stellt sicher, dass das Ergebnis in 8 Bit bleibt
  // (In Pascal ist Byte bereits 8 Bit, aber explizite Maskierung ist gute Praxis)

  // GARANTIE: Ergebnis ist immer 0..255 (8 Bit)
  // EIGENSCHAFT: GFMul2(GFMul2(x)) ≠ 4x (normale Arithmetik)
  //              sondern = x × x × x^2 in GF(2^8)
end;

function GFMul3(B: Byte): Byte;
  {
  ============================================================================
  GFMul3 - Multiplikation mit 3 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 3 im Galois-Feld GF(2^8). Diese Operation
  wird in MixColumns benötigt.

  PARAMETER:
  - B: Das zu multiplizierende Byte

  RÜCKGABEWERT:
  - Byte: Das Ergebnis von B × 3 in GF(2^8)

  HINTERGRUND - Multiplikation mit 3:

  In GF(2^8) gilt: 3 = 2 + 1
  (Addition ist XOR, also: 3 = 0x03 = 11 in binär)

  In Polynom-Darstellung:
  3 = (x + 1)

  Also: B × 3 = B × (x + 1) = B × x + B × 1

  In Code: B × 3 = GFMul2(B) XOR B

  WARUM FUNKTIONIERT DAS?

  Distributivgesetz in GF(2^8):
  B × (x + 1) = B × x + B × 1

  In GF(2) ist Addition = XOR:
  = (B × 2) ⊕ B

  BEISPIEL:

  B = 0x53 = 01010011

  GFMul2(0x53) = 0xA6 = 10100110 (wie oben berechnet)

  GFMul3(0x53) = 0xA6 XOR 0x53
                = 10100110 XOR 01010011
                = 11110101
                = 0xF5

  Polynom-Überprüfung:
  0x53 = x^6 + x^4 + x + 1
  × 3 = × (x + 1)
      = (x^6 + x^4 + x + 1) × x + (x^6 + x^4 + x + 1)
      = x^7 + x^5 + x^2 + x + x^6 + x^4 + x + 1
      = x^7 + x^6 + x^5 + x^4 + x^2 + 1  (x und x heben sich auf in GF(2))
      = 11110101 = 0xF5 ✓

  VERWENDUNG IN MIXCOLUMNS:

  Die MixColumns-Matrix enthält die Werte {2, 3, 1, 1}:
```
  [ 2  3  1  1 ]
  [ 1  2  3  1 ]
  [ 1  1  2  3 ]
  [ 3  1  1  2 ]
```

  GFMul3 wird für alle "3"-Einträge verwendet.

  OPTIMIERUNG:

  Statt B × 3 durch wiederholte Addition zu berechnen:
  B + B + B (langsam, 3 Operationen)

  Nutzen wir:
  GFMul2(B) XOR B (schnell, 1 GFMul2 + 1 XOR)

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 4.2.1: Multiplikation in GF(2^8)
  - "The Design of Rijndael", Kapitel 4.1.2: MixColumns

  ============================================================================
}

begin
  // B × 3 = B × (2 + 1) = B × 2 + B × 1
  // In GF(2^8): Addition ist XOR
  Result := GFMul2(B) xor B;
  // Äquivalent zu: B × (x + 1) im Polynom-Ring
  // Sehr effizient: Nur 1 GFMul2 + 1 XOR
end;

function GFMul4(B: Byte): Byte;
{
  ============================================================================
  GFMul4 - Multiplikation mit 4 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 4 im Galois-Feld GF(2^8). Diese Operation
  wird für InvMixColumns benötigt.

  PARAMETER:
  - B: Das zu multiplizierende Byte

  RÜCKGABEWERT:
  - Byte: Das Ergebnis von B × 4 in GF(2^8)

  HINTERGRUND - Multiplikation mit 4:

  4 = 2 × 2

  In Polynom-Darstellung:
  4 = x^2

  Also: B × 4 = B × x × x = GFMul2(GFMul2(B))

  IMPLEMENTIERUNG:

  Zweimal GFMul2 anwenden:
  B × 4 = (B × 2) × 2

  BEISPIEL:

  B = 0x53

  Schritt 1: GFMul2(0x53) = 0xA6
  Schritt 2: GFMul2(0xA6) = ?

  0xA6 = 10100110, höchstes Bit = 1
  → (0xA6 << 1) XOR 0x1B = 0x14C XOR 0x1B
  → 0x4C XOR 0x1B = 01001100 XOR 00011011 = 01010111 = 0x57

  Also: GFMul4(0x53) = 0x57

  VERWENDUNG IN INVMIXCOLUMNS:

  Die InvMixColumns-Matrix enthält {9, 11, 13, 14}:
  - GFMul9 = GFMul8 + GFMul1
  - GFMul11 = GFMul8 + GFMul2 + GFMul1
  - GFMul13 = GFMul8 + GFMul4 + GFMul1
  - GFMul14 = GFMul8 + GFMul4 + GFMul2

  GFMul4 ist Teil dieser Berechnungen.

  OPTIMIERUNG:

  Könnte man auch als GFMul2(B) XOR GFMul2(B) berechnen?
  → NEIN! In GF(2^8) gilt: x XOR x = 0 (nicht 2x!)
  → Richtig: GFMul2(GFMul2(B))

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.3.3: InvMixColumns

  ============================================================================
}
begin
   // B × 4 = B × x^2 = (B × x) × x
  // Zweimal GFMul2 anwenden
  Result := GFMul2(GFMul2(B));
  // NICHT verwechseln mit: GFMul2(B) + GFMul2(B)
  // Das würde 0 ergeben, da x ⊕ x = 0 in GF(2)!
end;

function GFMul8(B: Byte): Byte;
{
  ============================================================================
  GFMul8 - Multiplikation mit 8 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 8 im Galois-Feld GF(2^8). Diese Operation
  wird für InvMixColumns benötigt (als Basis für GFMul9, GFMul11, etc.).

  PARAMETER:
  - B: Das zu multiplizierende Byte

  RÜCKGABEWERT:
  - Byte: Das Ergebnis von B × 8 in GF(2^8)

  HINTERGRUND - Multiplikation mit 8:

  8 = 2 × 2 × 2

  In Polynom-Darstellung:
  8 = x^3

  Also: B × 8 = B × x × x × x = GFMul2(GFMul2(GFMul2(B)))

  IMPLEMENTIERUNG:

  Dreimal GFMul2 anwenden:
  B × 8 = ((B × 2) × 2) × 2

  BEISPIEL:

  B = 0x53

  Schritt 1: GFMul2(0x53) = 0xA6
  Schritt 2: GFMul2(0xA6) = 0x57 (wie oben)
  Schritt 3: GFMul2(0x57) = ?

  0x57 = 01010111, höchstes Bit = 0
  → 0x57 << 1 = 10101110 = 0xAE

  Also: GFMul8(0x53) = 0xAE

  VERWENDUNG:

  GFMul8 ist die Basis für die großen Koeffizienten in InvMixColumns:
  - GFMul9 = GFMul8 ⊕ GFMul1
  - GFMul11 = GFMul8 ⊕ GFMul2 ⊕ GFMul1
  - GFMul13 = GFMul8 ⊕ GFMul4 ⊕ GFMul1
  - GFMul14 = GFMul8 ⊕ GFMul4 ⊕ GFMul2

  ============================================================================
}
begin
   // B × 8 = B × x^3 = ((B × x) × x) × x
  // Dreimal GFMul2 anwenden
  Result := GFMul2(GFMul4(B));
   // Äquivalent zu: GFMul2(GFMul2(GFMul2(B)))
  // Aber effizienter durch Wiederverwendung von GFMul4
end;

function GFMul9(B: Byte): Byte;
{
  ============================================================================
  GFMul9 - Multiplikation mit 9 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 9 im Galois-Feld GF(2^8). Diese Operation
  wird in InvMixColumns benötigt.

  PARAMETER:
  - B: Das zu multiplizierende Byte

  RÜCKGABEWERT:
  - Byte: Das Ergebnis von B × 9 in GF(2^8)

  HINTERGRUND - Multiplikation mit 9:

  9 = 8 + 1 (in GF(2^8), Addition = XOR)

  In Polynom-Darstellung:
  9 = x^3 + 1

  Also: B × 9 = B × (x^3 + 1) = B × x^3 + B × 1

  In Code: B × 9 = GFMul8(B) XOR B

  VERWENDUNG IN INVMIXCOLUMNS:

  Die InvMixColumns-Matrix verwendet 9, 11, 13, 14:
```
  [ 14  11  13   9 ]
  [  9  14  11  13 ]
  [ 13   9  14  11 ]
  [ 11  13   9  14 ]
```

  ============================================================================
}
begin
   // B × 9 = B × (8 + 1) = B × 8 + B × 1
  // In GF(2^8): Addition ist XOR
  Result := GFMul8(B) xor B;
   // Äquivalent zu: B × (x^3 + 1)
end;

function GFMul11(B: Byte): Byte;
{
  ============================================================================
  GFMul11 - Multiplikation mit 11 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 11 im Galois-Feld GF(2^8). Diese Operation
  wird in InvMixColumns benötigt.

  PARAMETER:
  - B: Das zu multiplizierende Byte

  RÜCKGABEWERT:
  - Byte: Das Ergebnis von B × 11 in GF(2^8)

  HINTERGRUND - Multiplikation mit 11:

  11 = 8 + 2 + 1 (in GF(2^8))

  In Polynom-Darstellung:
  11 = 0x0B = 00001011 = x^3 + x + 1

  Also: B × 11 = B × (x^3 + x + 1)
              = B × x^3 + B × x + B × 1

  In Code: B × 11 = GFMul8(B) XOR GFMul2(B) XOR B

  BEISPIEL:

  B = 0x53
  GFMul8(0x53) = 0xAE (wie oben berechnet)
  GFMul2(0x53) = 0xA6

  GFMul11(0x53) = 0xAE XOR 0xA6 XOR 0x53
                 = 10101110 XOR 10100110 XOR 01010011
                 = 00001000 XOR 01010011
                 = 01011011 = 0x5B

  ============================================================================
}
begin
  // B × 11 = B × (8 + 2 + 1) = B × 8 + B × 2 + B × 1
  // In GF(2^8): Addition ist XOR
  Result := GFMul8(B) xor GFMul2(B) xor B;
   // Äquivalent zu: B × (x^3 + x + 1)
end;

function GFMul13(B: Byte): Byte;
{
  ============================================================================
  GFMul13 - Multiplikation mit 13 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 13 im Galois-Feld GF(2^8). Diese Operation
  wird in InvMixColumns benötigt.

  PARAMETER:
  - B: Das zu multiplizierende Byte

  RÜCKGABEWERT:
  - Byte: Das Ergebnis von B × 13 in GF(2^8)

  HINTERGRUND - Multiplikation mit 13:

  13 = 8 + 4 + 1 (in GF(2^8))

  In Polynom-Darstellung:
  13 = 0x0D = 00001101 = x^3 + x^2 + 1

  Also: B × 13 = B × (x^3 + x^2 + 1)
               = B × x^3 + B × x^2 + B × 1

  In Code: B × 13 = GFMul8(B) XOR GFMul4(B) XOR B

  ============================================================================
}
begin
  // B × 13 = B × (8 + 4 + 1) = B × 8 + B × 4 + B × 1
  // In GF(2^8): Addition ist XOR
  Result := GFMul8(B) xor GFMul4(B) xor B;
  // Äquivalent zu: B × (x^3 + x^2 + 1)
end;

function GFMul14(B: Byte): Byte;
{
  ============================================================================
  GFMul14 - Multiplikation mit 14 im Galois-Feld GF(2^8)
  ============================================================================

  ZWECK:
  Multipliziert ein Byte mit 14 im Galois-Feld GF(2^8). Diese Operation
  wird in InvMixColumns benötigt.

  PARAMETER:
  - B: Das zu multiplizierende Byte

  RÜCKGABEWERT:
  - Byte: Das Ergebnis von B × 14 in GF(2^8)

  HINTERGRUND - Multiplikation mit 14:

  14 = 8 + 4 + 2 (in GF(2^8))

  In Polynom-Darstellung:
  14 = 0x0E = 00001110 = x^3 + x^2 + x

  Also: B × 14 = B × (x^3 + x^2 + x)
               = B × x^3 + B × x^2 + B × x

  In Code: B × 14 = GFMul8(B) XOR GFMul4(B) XOR GFMul2(B)

  BESONDERHEIT:

  14 ist der einzige Koeffizient in InvMixColumns, der NICHT den
  Summanden "1" (also B selbst) enthält.

  ============================================================================
}
begin
   // B × 14 = B × (8 + 4 + 2) = B × 8 + B × 4 + B × 2
  // In GF(2^8): Addition ist XOR
  Result := GFMul8(B) xor GFMul4(B) xor GFMul2(B);
  // Äquivalent zu: B × (x^3 + x^2 + x)
  // ACHTUNG: Kein "xor B" am Ende! (14 = 8 + 4 + 2, nicht + 1)
end;

procedure MixSingleColumn(var S0, S1, S2, S3: Byte);
{
  ============================================================================
  MixSingleColumn - Mischt eine einzelne Spalte der State-Matrix
  ============================================================================

  ZWECK:
  Führt die MixColumns-Transformation auf eine einzelne Spalte (4 Bytes)
  durch. Dies ist der Kern der MixColumns-Operation und wird für jede der
  vier Spalten der State-Matrix aufgerufen.

  PARAMETER:
  - S0, S1, S2, S3: Die vier Bytes einer Spalte (call-by-reference, werden modifiziert)

  RÜCKGABEWERT:
  - Keiner (die Parameter werden direkt modifiziert)

  HINTERGRUND - MixColumns und maximale Diffusion:

  MixColumns ist zusammen mit ShiftRows für die DIFFUSION in AES verantwortlich.
  Während ShiftRows Bytes horizontal (zwischen Spalten) mischt, mischt
  MixColumns Bytes vertikal (innerhalb jeder Spalte).

  ROLLE IM AES-ALGORITHMUS:

  MixColumns wird in fast allen Runden angewendet:
  - Runden 1-13: SubBytes → ShiftRows → MixColumns → AddRoundKey
  - Runde 14: SubBytes → ShiftRows → AddRoundKey (OHNE MixColumns!)

  WICHTIG: Die letzte Runde hat KEIN MixColumns!
  Warum? Dies vereinfacht die Äquivalenz zwischen Ver- und Entschlüsselung.

  DIE MATRIX-MULTIPLIKATION:

  MixColumns ist eine Matrix-Multiplikation in GF(2^8):

  [ S0' ]   [ 2  3  1  1 ]   [ S0 ]
  [ S1' ] = [ 1  2  3  1 ] × [ S1 ]
  [ S2' ]   [ 1  1  2  3 ]   [ S2 ]
  [ S3' ]   [ 3  1  1  2 ]   [ S3 ]

  Wobei alle Operationen in GF(2^8) sind:
  - Multiplikation: GFMul2, GFMul3
  - Addition: XOR

  WARUM DIESE MATRIX?

  Daemen und Rijmen wählten diese spezielle Matrix, weil sie:

  1. MAXIMUM DISTANCE SEPARABLE (MDS):
     → Bietet optimale Diffusion
     → Jedes Input-Byte beeinflusst alle Output-Bytes
     → Minimale Anzahl aktiver S-Boxen garantiert

  2. ZIRKULANT (Circulant Matrix):
     → Jede Zeile ist eine Rotation der vorherigen
     → Symmetrisch und effizient zu implementieren
     → Hardware-freundlich

  3. INVERTIERBAR in GF(2^8):
     → Notwendig für Entschlüsselung
     → Die Inverse ist eindeutig

  4. EFFIZIENT:
     → Nur Multiplikationen mit 1, 2, 3 nötig
     → Keine größeren Koeffizienten
     → Schnell in Software und Hardware

  DIE BERECHNUNG - Zeile für Zeile:

  Erste Zeile (S0'):
  S0' = (2 × S0) ⊕ (3 × S1) ⊕ (1 × S2) ⊕ (1 × S3)
      = GFMul2(S0) ⊕ GFMul3(S1) ⊕ S2 ⊕ S3

  Zweite Zeile (S1'):
  S1' = (1 × S0) ⊕ (2 × S1) ⊕ (3 × S2) ⊕ (1 × S3)
      = S0 ⊕ GFMul2(S1) ⊕ GFMul3(S2) ⊕ S3

  Dritte Zeile (S2'):
  S2' = (1 × S0) ⊕ (1 × S1) ⊕ (2 × S2) ⊕ (3 × S3)
      = S0 ⊕ S1 ⊕ GFMul2(S2) ⊕ GFMul3(S3)

  Vierte Zeile (S3'):
  S3' = (3 × S0) ⊕ (1 × S1) ⊕ (1 × S2) ⊕ (2 × S3)
      = GFMul3(S0) ⊕ S1 ⊕ S2 ⊕ GFMul2(S3)

  MUSTER ERKENNEN - Die Zirkulante Struktur:

  Beachte: Jede Zeile ist eine Rotation der ersten Zeile:
  Zeile 1: [2, 3, 1, 1]
  Zeile 2: [1, 2, 3, 1] (nach links rotiert)
  Zeile 3: [1, 1, 2, 3] (nach links rotiert)
  Zeile 4: [3, 1, 1, 2] (nach links rotiert)

  Diese Symmetrie macht die Implementierung elegant und effizient.

  KONKRETES BEISPIEL:

  Eingabe-Spalte:
  S0 = 0xDB
  S1 = 0x13
  S2 = 0x53
  S3 = 0x45

  Berechnung von S0':
  GFMul2(0xDB) = ?
    0xDB = 11011011, Bit 7 = 1
    → (0xDB << 1) XOR 0x1B = 0x1B6 XOR 0x1B = 0xB6 XOR 0x1B = 0xAD

  GFMul3(0x13) = GFMul2(0x13) XOR 0x13
    GFMul2(0x13) = 0x26 (Bit 7 = 0, einfach << 1)
    → 0x26 XOR 0x13 = 0x35

  S0' = 0xAD XOR 0x35 XOR 0x53 XOR 0x45
      = 10101101 XOR 00110101 XOR 01010011 XOR 01000101
      = 10011000 XOR 01010011 XOR 01000101
      = 11001011 XOR 01000101
      = 10001110 = 0x8E

  (Ähnlich für S1', S2', S3')

  WARUM TEMPORÄRE VARIABLEN?

  Die Funktion nutzt temporäre Variablen T0, T1, T2, T3:

  PROBLEM ohne Temporäre:
```pascal
  S0 := GFMul2(S0) xor GFMul3(S1) xor S2 xor S3;  // S0 wird überschrieben!
  S1 := S0 xor GFMul2(S1) xor GFMul3(S2) xor S3;  // Verwendet neues S0! FEHLER!
```

  LÖSUNG mit Temporären:
```pascal
  T0 := GFMul2(S0) xor GFMul3(S1) xor S2 xor S3;  // Original-Werte verwenden
  T1 := S0 xor GFMul2(S1) xor GFMul3(S2) xor S3;  // Original-Werte verwenden
  T2 := S0 xor S1 xor GFMul2(S2) xor GFMul3(S3);  // Original-Werte verwenden
  T3 := GFMul3(S0) xor S1 xor S2 xor GFMul2(S3);  // Original-Werte verwenden

  S0 := T0;  // Erst jetzt überschreiben
  S1 := T1;
  S2 := T2;
  S3 := T3;
```

  DIFFUSION - Wie gut ist sie?

  Nach einer MixColumns-Operation:
  - Jedes Output-Byte hängt von ALLEN 4 Input-Bytes ab
  - Ein geändertes Input-Byte ändert ALLE 4 Output-Bytes
  - In Kombination mit ShiftRows: Nach 2 Runden beeinflusst jedes Byte
    alle 16 Bytes des Blocks!

  BRANCH NUMBER:

  Die MixColumns-Matrix hat den "Branch Number" 5 (maximal für 4×4 Matrix):
  → Wenn n Input-Bytes unterschiedlich sind und m Output-Bytes unterschiedlich,
    dann gilt: n + m ≥ 5
  → Dies garantiert starke Diffusion gegen differentielle Kryptoanalyse

  WIDE TRAIL STRATEGY:

  Daemen und Rijmen entwickelten die "Wide Trail Strategy":
  - SubBytes sorgt für lokale Nichtlinearität
  - ShiftRows und MixColumns sorgen für globale Diffusion
  - Nach wenigen Runden: Vollständige Vermischung aller Bits

  Diese Strategie ist der Schlüssel zur Sicherheit von AES!

  PERFORMANCE:

  Pro Spalte:
  - 4 GFMul2-Aufrufe
  - 4 GFMul3-Aufrufe
  - 12 XOR-Operationen

  Sehr schnell, da alles Tabellensuche + Bitoperationen.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.1.3: MixColumns Transformation
  - "The Design of Rijndael", Kapitel 3.7 und 7.2: MDS-Codes
  - "Wide Trail Design Strategy" (Daemen & Rijmen, 1998)
  - Maximum Distance Separable (MDS) Codes: Coding Theory
  - Circulant Matrices: Linear Algebra

  ============================================================================
}
var
  T0, T1, T2, T3: Byte;           // Temporäre Variablen für die neuen Werte
begin
  // WICHTIG: Alle 4 neuen Werte müssen VOR dem Überschreiben berechnet werden,
  // da jeder neue Wert von ALLEN 4 alten Werten abhängt

  // -------------------------------------------------------------------------
  // Zeile 0 der Matrix: [2, 3, 1, 1]
  // -------------------------------------------------------------------------
  // T0 = (2 × S0) ⊕ (3 × S1) ⊕ (1 × S2) ⊕ (1 × S3)

  T0 := GFMul2(S0) xor GFMul3(S1) xor S2 xor S3;
  // Schrittweise Berechnung (für Verständnis):
  // 1. GFMul2(S0): Multipliziere S0 mit 2 in GF(2^8)
  // 2. GFMul3(S1): Multipliziere S1 mit 3 in GF(2^8)
  // 3. S2: Multipliziere S2 mit 1 (bleibt unverändert)
  // 4. S3: Multipliziere S3 mit 1 (bleibt unverändert)
  // 5. XOR alle Ergebnisse zusammen (Addition in GF(2^8))

  // -------------------------------------------------------------------------
  // Zeile 1 der Matrix: [1, 2, 3, 1]
  // -------------------------------------------------------------------------
  // T1 = (1 × S0) ⊕ (2 × S1) ⊕ (3 × S2) ⊕ (1 × S3)
  T1 := S0 xor GFMul2(S1) xor GFMul3(S2) xor S3;
  // Beachte: Die Koeffizienten [1, 2, 3, 1] sind eine Rotation von [2, 3, 1, 1]
  // Dies ist charakteristisch für zirkulante Matrizen

  // -------------------------------------------------------------------------
  // Zeile 2 der Matrix: [1, 1, 2, 3]
  // -------------------------------------------------------------------------
  // T2 = (1 × S0) ⊕ (1 × S1) ⊕ (2 × S2) ⊕ (3 × S3)
  T2 := S0 xor S1 xor GFMul2(S2) xor GFMul3(S3);
  // Wieder eine Rotation: [1, 1, 2, 3] ist [1, 2, 3, 1] rotiert

  // -------------------------------------------------------------------------
  // Zeile 3 der Matrix: [3, 1, 1, 2]
  // -------------------------------------------------------------------------
  // T3 = (3 × S0) ⊕ (1 × S1) ⊕ (1 × S2) ⊕ (2 × S3)
  T3 := GFMul3(S0) xor S1 xor S2 xor GFMul2(S3);
    // Und wieder eine Rotation: [3, 1, 1, 2] ist [1, 1, 2, 3] rotiert
  // Die vollständige Matrix ist zirkulant!

  // -------------------------------------------------------------------------
  // Ergebnisse zurückschreiben
  // -------------------------------------------------------------------------
  // JETZT erst die Original-Werte überschreiben, nachdem ALLE neuen Werte
  // berechnet wurden. Dies ist essentiell, da jeder neue Wert alle alten
  // Werte benötigt!

  S0 := T0;    // Neues S0 (hängt von allen alten S0, S1, S2, S3 ab)
  S1 := T1;    // Neues S1 (hängt von allen alten S0, S1, S2, S3 ab)
  S2 := T2;    // Neues S2 (hängt von allen alten S0, S1, S2, S3 ab)
  S3 := T3;    // Neues S3 (hängt von allen alten S0, S1, S2, S3 ab)

   // Nach dieser Operation:
  // - Jedes der 4 Bytes wurde durch eine Linearkombination aller 4 Bytes ersetzt
  // - Vollständige Diffusion innerhalb der Spalte ist erreicht
  // - Ein geändertes Input-Byte beeinflusst alle 4 Output-Bytes
  // - Die Transformation ist invertierbar (wichtig für Entschlüsselung)
end;

procedure InvMixSingleColumn(var S0, S1, S2, S3: Byte);
{
  ============================================================================
  InvMixSingleColumn - Inverse Mischung einer einzelnen Spalte
  ============================================================================

  ZWECK:
  Führt die inverse MixColumns-Transformation auf eine einzelne Spalte durch.
  Dies macht die Wirkung von MixSingleColumn rückgängig und wird beim
  Entschlüsseln benötigt.

  PARAMETER:
  - S0, S1, S2, S3: Die vier Bytes einer Spalte (call-by-reference, werden modifiziert)

  RÜCKGABEWERT:
  - Keiner (die Parameter werden direkt modifiziert)

  HINTERGRUND - Die Inverse Matrix:

  InvMixColumns verwendet die inverse Matrix der MixColumns-Matrix.
  Diese inverse Matrix wurde mathematisch berechnet (in GF(2^8)):

  Inverse MixColumns-Matrix:
  [ 14  11  13   9 ]
  [  9  14  11  13 ]
  [ 13   9  14  11 ]
  [ 11  13   9  14 ]

  Beziehung zur Original-Matrix:
  [ 2  3  1  1 ]   [ 14  11  13   9 ]   [ 1  0  0  0 ]
  [ 1  2  3  1 ] × [  9  14  11  13 ] = [ 0  1  0  0 ] = Identität
  [ 1  1  2  3 ]   [ 13   9  14  11 ]   [ 0  0  1  0 ]
  [ 3  1  1  2 ]   [ 11  13   9  14 ]   [ 0  0  0  1 ]

  (Alle Operationen in GF(2^8)!)

  ROLLE IN AES-ENTSCHLÜSSELUNG:

  InvMixColumns wird in den meisten Entschlüsselungs-Runden angewendet:
  - Runde 14: AddRoundKey → InvShiftRows → InvSubBytes (OHNE InvMixColumns)
  - Runden 13-1: AddRoundKey → InvMixColumns → InvShiftRows → InvSubBytes
  - Runde 0: AddRoundKey

  WICHTIG: Erste (=letzte bei Entschlüsselung) Runde hat KEIN InvMixColumns,
  spiegelnd dazu, dass die letzte Verschlüsselungsrunde kein MixColumns hat.

  WARUM GRÖSSERE KOEFFIZIENTEN (9, 11, 13, 14)?

  Die inverse Matrix hat notwendigerweise größere Koeffizienten:
  - Original: {1, 2, 3}
  - Invers: {9, 11, 13, 14}

  Dies ist mathematisch unvermeidbar - die Inverse einer Matrix mit kleinen
  Einträgen hat oft größere Einträge. Trotzdem sind diese Werte noch klein
  genug für effiziente Implementierung.

  DIE BERECHNUNG - Zeile für Zeile:

  Erste Zeile (S0'):
  S0' = (14 × S0) ⊕ (11 × S1) ⊕ (13 × S2) ⊕ (9 × S3)
      = GFMul14(S0) ⊕ GFMul11(S1) ⊕ GFMul13(S2) ⊕ GFMul9(S3)

  Zweite Zeile (S1'):
  S1' = (9 × S0) ⊕ (14 × S1) ⊕ (11 × S2) ⊕ (13 × S3)
      = GFMul9(S0) ⊕ GFMul14(S1) ⊕ GFMul11(S2) ⊕ GFMul13(S3)

  Dritte Zeile (S2'):
  S2' = (13 × S0) ⊕ (9 × S1) ⊕ (14 × S2) ⊕ (11 × S3)
      = GFMul13(S0) ⊕ GFMul9(S1) ⊕ GFMul14(S2) ⊕ GFMul11(S3)

  Vierte Zeile (S3'):
  S3' = (11 × S0) ⊕ (13 × S1) ⊕ (9 × S2) ⊕ (14 × S3)
      = GFMul11(S0) ⊕ GFMul13(S1) ⊕ GFMul9(S2) ⊕ GFMul14(S3)

  ZIRKULANTE STRUKTUR (auch hier!):

  Zeile 1: [14, 11, 13,  9]
  Zeile 2: [ 9, 14, 11, 13] (nach links rotiert)
  Zeile 3: [13,  9, 14, 11] (nach links rotiert)
  Zeile 4: [11, 13,  9, 14] (nach links rotiert)

  Die inverse Matrix ist ebenfalls zirkulant - eine elegante Eigenschaft!

  SYMMETRIE-EIGENSCHAFT:

  Für alle Spalten gilt:
  InvMixSingleColumn(MixSingleColumn(Spalte)) = Spalte
  MixSingleColumn(InvMixSingleColumn(Spalte)) = Spalte

  Dies ist fundamental für AES:
  → Verschlüsselung muss umkehrbar sein
  → Entschlüsselung stellt Original wieder her

  KONKRETES BEISPIEL (Rückwärts):

  Angenommen MixSingleColumn erzeugte:
  S0 = 0x8E, S1 = 0x4D, S2 = 0xA3, S3 = 0x9B

  Dann sollte InvMixSingleColumn die Original-Werte zurückliefern:
  S0 = 0xDB, S1 = 0x13, S2 = 0x53, S3 = 0x45

  (Vollständige Berechnung analog zu MixSingleColumn, aber mit den
   inversen GF-Multiplikationen)

  PERFORMANCE-VERGLEICH:

  InvMixColumns ist etwas langsamer als MixColumns:
  - MixColumns: 4× GFMul2 + 4× GFMul3
  - InvMixColumns: 4× GFMul9 + 4× GFMul11 + 4× GFMul13 + 4× GFMul14

  Die größeren Multiplikatoren erfordern mehr Basis-Operationen:
  - GFMul9 = GFMul8 ⊕ GFMul1 (2 Ops)
  - GFMul11 = GFMul8 ⊕ GFMul2 ⊕ GFMul1 (3 Ops)
  - GFMul13 = GFMul8 ⊕ GFMul4 ⊕ GFMul1 (3 Ops)
  - GFMul14 = GFMul8 ⊕ GFMul4 ⊕ GFMul2 (3 Ops)

  Trotzdem: Immer noch sehr schnell, besonders in Hardware.

  WARUM GLEICHE STRUKTUR WIE MIXSINGLECOLUMN?

  Die Implementierung ist identisch strukturiert:
  - Temporäre Variablen für alle 4 neuen Werte
  - Alle Berechnungen verwenden die Original-Werte
  - Erst am Ende werden die Ergebnisse zurückgeschrieben

  Dies ist kein Zufall - beide Operationen sind Matrix-Multiplikationen
  und folgen daher dem gleichen Muster.

  DEBUGGING-TIPP:

  Test für Korrektheit:
```pascal
  S0 := RandomByte; S1 := RandomByte; S2 := RandomByte; S3 := RandomByte;
  Original := [S0, S1, S2, S3];

  MixSingleColumn(S0, S1, S2, S3);
  InvMixSingleColumn(S0, S1, S2, S3);

  // S0, S1, S2, S3 sollten jetzt wieder die Original-Werte haben!
```

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.3.3: InvMixColumns Transformation
  - "The Design of Rijndael", Kapitel 4.1.3: Inverse MixColumns
  - Linear Algebra: Matrix-Inverse über endlichen Körpern
  - MDS Codes: Self-Dual Codes

  ============================================================================
}
var
  T0, T1, T2, T3: Byte;     // Temporäre Variablen für die neuen Werte
begin
   // WICHTIG: Gleiche Strategie wie MixSingleColumn - alle 4 neuen Werte
  // VOR dem Überschreiben berechnen, da jeder von allen 4 alten abhängt

  // -------------------------------------------------------------------------
  // Zeile 0 der inversen Matrix: [14, 11, 13, 9]
  // -------------------------------------------------------------------------
  // T0 = (14 × S0) ⊕ (11 × S1) ⊕ (13 × S2) ⊕ (9 × S3)

  T0 := GFMul14(S0) xor GFMul11(S1) xor GFMul13(S2) xor GFMul9(S3);
   // Schrittweise (für Verständnis):
  // 1. GFMul14(S0): S0 × 14 in GF(2^8) = S0 × (x^3 + x^2 + x)
  // 2. GFMul11(S1): S1 × 11 in GF(2^8) = S1 × (x^3 + x + 1)
  // 3. GFMul13(S2): S2 × 13 in GF(2^8) = S2 × (x^3 + x^2 + 1)
  // 4. GFMul9(S3): S3 × 9 in GF(2^8) = S3 × (x^3 + 1)
  // 5. XOR alle zusammen (Addition in GF(2^8))

  // -------------------------------------------------------------------------
  // Zeile 1 der inversen Matrix: [9, 14, 11, 13]
  // -------------------------------------------------------------------------
  // T1 = (9 × S0) ⊕ (14 × S1) ⊕ (11 × S2) ⊕ (13 × S3)
  T1 := GFMul9(S0)  xor GFMul14(S1) xor GFMul11(S2) xor GFMul13(S3);
   // Beachte: [9, 14, 11, 13] ist [14, 11, 13, 9] rotiert
  // Die inverse Matrix ist ebenfalls zirkulant!

  // -------------------------------------------------------------------------
  // Zeile 2 der inversen Matrix: [13, 9, 14, 11]
  // -------------------------------------------------------------------------
  // T2 = (13 × S0) ⊕ (9 × S1) ⊕ (14 × S2) ⊕ (11 × S3)
  T2 := GFMul13(S0) xor GFMul9(S1)  xor GFMul14(S2) xor GFMul11(S3);
  // Rotation fortgesetzt: [13, 9, 14, 11] ist [9, 14, 11, 13] rotiert

  // -------------------------------------------------------------------------
  // Zeile 3 der inversen Matrix: [11, 13, 9, 14]
  // -------------------------------------------------------------------------
  // T3 = (11 × S0) ⊕ (13 × S1) ⊕ (9 × S2) ⊕ (14 × S3)
  T3 := GFMul11(S0) xor GFMul13(S1) xor GFMul9(S2)  xor GFMul14(S3);

   // Letzte Rotation: [11, 13, 9, 14] ist [13, 9, 14, 11] rotiert
  // Komplette zirkulante Struktur bewahrt!

  // -------------------------------------------------------------------------
  // Ergebnisse zurückschreiben
  // -------------------------------------------------------------------------
  // JETZT die Original-Werte überschreiben, nachdem ALLE inversen
  // Transformationen berechnet wurden

  S0 := T0;     // Neues S0 (macht MixColumns für S0 rückgängig)
  S1 := T1;     // Neues S1 (macht MixColumns für S1 rückgängig)
  S2 := T2;     // Neues S2 (macht MixColumns für S2 rückgängig)
  S3 := T3;     // Neues S3 (macht MixColumns für S3 rückgängig)

   // Nach dieser Operation:
  // - Die Wirkung von MixSingleColumn wurde rückgängig gemacht
  // - Falls vorher MixSingleColumn angewendet wurde, sind die Original-Werte wiederhergestellt
  // - GARANTIE: InvMixSingleColumn(MixSingleColumn(Spalte)) = Spalte

  // Die inverse Matrix-Multiplikation hat die Diffusion der Verschlüsselung
  // rückgängig gemacht und die Original-Bytes wiederhergestellt
end;

procedure MixColumnsState(var State: TAESState);
{
  ============================================================================
  MixColumnsState - Wendet MixColumns auf alle Spalten der State-Matrix an
  ============================================================================

  ZWECK:
  Führt die MixColumns-Transformation auf allen vier Spalten der State-Matrix
  durch. Dies ist eine der vier Haupttransformationen in AES und sorgt für
  vertikale Diffusion (innerhalb der Spalten).

  PARAMETER:
  - State: Die 4×4 State-Matrix (wird direkt modifiziert, call-by-reference)

  RÜCKGABEWERT:
  - Keiner (die State-Matrix wird in-place modifiziert)

  HINTERGRUND - MixColumns im Gesamtkontext:

  MixColumns ist die dritte von vier Transformationen in jeder AES-Runde:
  1. SubBytes (Konfusion - nichtlinear)
  2. ShiftRows (Diffusion horizontal - zwischen Spalten)
  3. MixColumns (Diffusion vertikal - innerhalb Spalten) ← HIER
  4. AddRoundKey (Schlüssel-Integration)

  Zusammen bilden diese vier Operationen eine "Runde" in AES.

  ROLLE IM AES-ALGORITHMUS:

  MixColumns wird in FAST allen Verschlüsselungs-Runden angewendet:
  - Runden 1-13: SubBytes → ShiftRows → MixColumns → AddRoundKey
  - Runde 14: SubBytes → ShiftRows → AddRoundKey (OHNE MixColumns!)

  WICHTIGE AUSNAHME: Die letzte Runde (Runde 14) hat KEIN MixColumns!

  WARUM KEINE MIXCOLUMNS IN DER LETZTEN RUNDE?

  Dies ist eine bewusste Design-Entscheidung von Daemen und Rijmen:

  1. VEREINFACHUNG DER IMPLEMENTIERUNG:
     → Ver- und Entschlüsselung werden ähnlicher
     → Rundenschlüssel können in gleicher Reihenfolge gespeichert werden

  2. KEINE SICHERHEITSEINBUSSE:
     → Die letzte MixColumns würde nur vor dem finalen AddRoundKey stehen
     → Da nach AddRoundKey keine weiteren Transformationen folgen, würde
       MixColumns keinen Sicherheitsgewinn bringen
     → Ein Angreifer sieht nur das Ergebnis nach AddRoundKey

  3. EQUIVALENT KEY SCHEDULES:
     → Ermöglicht Optimierungen bei der Implementierung
     → Hardware kann effizienter designed werden

  DIFFUSION - Das Zusammenspiel:

  MixColumns alleine würde nur Bytes INNERHALB jeder Spalte mischen.
  ShiftRows alleine würde nur Bytes ZWISCHEN den Spalten mischen.

  ZUSAMMEN ergeben sie vollständige Diffusion:

  Nach 1 Runde:
  - SubBytes: Jedes Byte hängt nichtlinear von sich selbst ab
  - ShiftRows: Bytes werden zwischen Spalten verteilt
  - MixColumns: Jedes Byte einer Spalte hängt von allen Bytes der Spalte ab
  → Ergebnis: Jedes Byte beeinflusst 4-5 andere Bytes

  Nach 2 Runden:
  - Die Bytes, die in Runde 1 beeinflusst wurden, werden wieder gemischt
  - ShiftRows verteilt sie erneut über die Spalten
  - MixColumns mischt sie erneut
  → Ergebnis: Jedes Byte beeinflusst praktisch alle 16 Bytes!

  Nach 3-4 Runden:
  - VOLLSTÄNDIGE DIFFUSION erreicht
  - Jedes Output-Bit hängt von jedem Input-Bit ab
  - Dies ist der "Avalanche-Effekt" in Perfektion

  WARUM 14 RUNDEN BEI AES-256?

  Bei AES-256 haben wir 14 Runden (AES-128: 10, AES-192: 12):

  - 4 Runden: Vollständige Diffusion erreicht
  - 14 Runden: Große Sicherheitsmarge
  - Selbst wenn Angreifer 4-5 Runden "überspringen" könnten,
    bleiben genug Runden für Sicherheit

  Dies gibt Schutz gegen:
  - Differentielle Kryptoanalyse
  - Lineare Kryptoanalyse
  - Zukünftige, noch unbekannte Angriffe

  MATHEMATISCHE EIGENSCHAFTEN:

  MixColumns ist eine lineare Transformation:
  - MixColumns(A ⊕ B) = MixColumns(A) ⊕ MixColumns(B)
  - Dies ist wichtig für kryptographische Analysen

  Aber: In Kombination mit dem nichtlinearen SubBytes wird AES insgesamt
  stark nichtlinear!

  FUNKTIONSWEISE - Spalte für Spalte:

  Die Implementierung ist konzeptionell sehr einfach:
  1. Durchlaufe alle 4 Spalten (Col = 0..3)
  2. Für jede Spalte:
     a) Extrahiere die 4 Bytes der Spalte
     b) Rufe MixSingleColumn() auf
     c) Schreibe die gemischten Bytes zurück

  WARUM SPALTENWEISE?

  MixColumns operiert auf Spalten (nicht Zeilen), weil:
  - Die State-Matrix in Column-Major Order gespeichert ist
  - Spalten entsprechen "Wörtern" in der Kryptographie-Notation
  - Hardware-Implementierungen können Spalten parallel verarbeiten

  BEISPIEL - Vollständige State-Transformation:

  Vorher (nach ShiftRows):
       [0]  [1]  [2]  [3]
  [0]  87   F2   4D   97
  [1]  4C   6E   90   EC
  [2]  46   E7   4A   C3
  [3]  A6   8C   D8   95

  Nach MixColumns:
       [0]  [1]  [2]  [3]
  [0]  47   40   A3   4C    (Spalte 0 wurde gemischt)
  [1]  37   D4   70   9F    (Spalte 1 wurde gemischt)
  [2]  94   E4   3A   42    (Spalte 2 wurde gemischt)
  [3]  ED   A5   A6   BC    (Spalte 3 wurde gemischt)

  Jede Spalte wurde unabhängig durch MixSingleColumn transformiert.

  UNABHÄNGIGKEIT DER SPALTEN:

  WICHTIG: MixColumns behandelt jede Spalte unabhängig:
  - Spalte 0 beeinflusst nicht Spalte 1, 2, 3
  - Spalte 1 beeinflusst nicht Spalte 0, 2, 3
  - usw.

  Die Vermischung ZWISCHEN Spalten erfolgt durch ShiftRows!

  Dies ist das elegante Design von AES:
  - ShiftRows: Horizontale Diffusion (zwischen Spalten)
  - MixColumns: Vertikale Diffusion (innerhalb Spalten)
  - Zusammen: Vollständige 2D-Diffusion

  PERFORMANCE:

  Pro State (4 Spalten):
  - 4× MixSingleColumn
  - Jede MixSingleColumn: 4× GFMul2 + 4× GFMul3 + 12× XOR
  - Gesamt: 16× GFMul2 + 16× GFMul3 + 48× XOR

  Sehr schnell:
  - Alle Operationen sind Tabellensuche + Bitoperationen
  - Keine Schleifen über Bits
  - Keine komplexen Berechnungen
  - In moderner Hardware (AES-NI): Spezielle CPU-Instruktion

  HARDWARE-IMPLEMENTIERUNG:

  In Hardware können alle 4 Spalten PARALLEL verarbeitet werden:
  - 4 unabhängige MixColumn-Einheiten
  - Durchsatz: 1 kompletter Block pro Taktzyklus
  - Sehr effizient in FPGAs und ASICs

  ALTERNATIVE IMPLEMENTIERUNGEN:

  Statt MixSingleColumn könnte man auch direkt Matrix-Multiplikation
  mit Lookup-Tabellen implementieren (wie in manchen Bibliotheken):
```
  T-Tables: Vorberechnete Tabellen, die SubBytes + MixColumns kombinieren
  → Noch schneller, aber größerer Speicherbedarf
  → Anfälliger für Cache-Timing-Angriffe
```

  Unsere Implementierung: Klar, verständlich, lehrtauglich!

  SICHERHEITSASPEKT - Timing:

  MixColumns selbst ist zeitkonstant:
  - Keine datenabhängigen Verzweigungen
  - Jede Spalte dauert gleich lang
  - Schutz gegen Timing-Angriffe

  (Die GFMul-Funktionen haben Verzweigungen, aber diese hängen nur
  vom höchsten Bit ab, nicht vom gesamten Datenwert)

  DER "ACTIVE S-BOX" ZUSAMMENHANG:

  Kryptoanalytiker messen die Stärke von AES in "aktiven S-Boxen":
  - Eine S-Box ist "aktiv", wenn ihr Input sich von einem Vergleichswert unterscheidet
  - MixColumns garantiert: Wenn 1 Byte in einer Spalte aktiv ist, sind nach
    MixColumns alle 4 Bytes der Spalte aktiv
  - Dies ist die MDS-Eigenschaft (Maximum Distance Separable)
  - Je mehr aktive S-Boxen, desto sicherer der Algorithmus

  MixColumns ist essentiell für diese Sicherheitseigenschaft!

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.1.3: MixColumns Transformation
  - "The Design of Rijndael" (Daemen & Rijmen), Kapitel 3.7 und 7.4
  - "Wide Trail Design Strategy" (Daemen & Rijmen, 1998)
  - "AES Proposal: Rijndael" (1998): Original-Submission an NIST
  - Linear Cryptanalysis: Matsui (1993)
  - Differential Cryptanalysis: Biham & Shamir (1991)

  ============================================================================
}
var
  Col: Integer;          // Laufvariable für Spalten (0..3)
  S0, S1, S2, S3: Byte;  // Die 4 Bytes einer Spalte
begin
  for Col := 0 to 3 do            // Schleife über alle 4 Spalten der State-Matrix
  begin
     // -----------------------------------------------------------------------
    // Schritt 1: Die 4 Bytes der aktuellen Spalte extrahieren
    // -----------------------------------------------------------------------
    // Die Spalte besteht aus State[Row, Col] für Row = 0..3
    // Wir kopieren sie in temporäre Variablen für die Verarbeitung
    S0 := State[0, Col];        // Zeile 0 der aktuellen Spalte
    S1 := State[1, Col];        // Zeile 1 der aktuellen Spalte
    S2 := State[2, Col];        // Zeile 2 der aktuellen Spalte
    S3 := State[3, Col];        // Zeile 3 der aktuellen Spalte

    // Jetzt haben wir eine vollständige Spalte in S0, S1, S2, S3
    // Beispiel: Wenn Col=0, haben wir die erste Spalte der Matrix

    // -----------------------------------------------------------------------
    // Schritt 2: MixColumns auf diese Spalte anwenden
    // -----------------------------------------------------------------------
    // MixSingleColumn führt die Matrix-Multiplikation durch:
    // [ S0' ]   [ 2  3  1  1 ]   [ S0 ]
    // [ S1' ] = [ 1  2  3  1 ] × [ S1 ]  (in GF(2^8))
    // [ S2' ]   [ 1  1  2  3 ]   [ S2 ]
    // [ S3' ]   [ 3  1  1  2 ]   [ S3 ]
    //
    // S0, S1, S2, S3 werden direkt modifiziert (call-by-reference)

    MixSingleColumn(S0, S1, S2, S3);
      // Nach diesem Aufruf:
    // - S0, S1, S2, S3 enthalten die gemischten Werte
    // - Jeder neue Wert hängt von allen 4 alten Werten ab
    // - Vollständige Diffusion innerhalb dieser Spalte ist erreicht

    // -----------------------------------------------------------------------
    // Schritt 3: Die gemischten Bytes zurück in die State-Matrix schreiben
    // -----------------------------------------------------------------------

    State[0, Col] := S0;  // Neues Byte für Zeile 0, aktuelle Spalte
    State[1, Col] := S1;  // Neues Byte für Zeile 1, aktuelle Spalte
    State[2, Col] := S2;  // Neues Byte für Zeile 2, aktuelle Spalte
    State[3, Col] := S3;  // Neues Byte für Zeile 3, aktuelle Spalte
     // Die aktuelle Spalte wurde erfolgreich gemischt
    // und zurück in die State-Matrix geschrieben
  end;
   // Nach der Schleife:
  // - ALLE 4 Spalten wurden durch MixColumns transformiert
  // - Jede Spalte wurde unabhängig behandelt
  // - Die State-Matrix hat jetzt vollständige vertikale Diffusion

  // In Kombination mit ShiftRows (horizontale Diffusion) ergibt dies
  // vollständige 2D-Diffusion über die gesamte 4×4 Matrix

  // WICHTIG: Dies ist die LETZTE Operation vor AddRoundKey in den
  // Runden 1-13. In Runde 14 wird MixColumns NICHT aufgerufen!
end;

procedure InvMixColumnsState(var State: TAESState);
{
  ============================================================================
  InvMixColumnsState - Inverse MixColumns auf alle Spalten anwenden
  ============================================================================

  ZWECK:
  Führt die inverse MixColumns-Transformation auf allen vier Spalten der
  State-Matrix durch. Dies macht die Wirkung von MixColumnsState rückgängig
  und wird beim Entschlüsseln benötigt.

  PARAMETER:
  - State: Die 4×4 State-Matrix (wird direkt modifiziert, call-by-reference)

  RÜCKGABEWERT:
  - Keiner (die State-Matrix wird in-place modifiziert)

  HINTERGRUND - Inverse Transformation:

  InvMixColumns ist die mathematische Inverse von MixColumns:
  - MixColumns verwendet die Matrix [2,3,1,1; 1,2,3,1; 1,1,2,3; 3,1,1,2]
  - InvMixColumns verwendet die inverse Matrix [14,11,13,9; 9,14,11,13; ...]

  Für alle States S gilt:
  InvMixColumnsState(MixColumnsState(S)) = S

  ROLLE IN AES-ENTSCHLÜSSELUNG:

  InvMixColumns wird in den MEISTEN Entschlüsselungs-Runden angewendet:
  - Runde 14: AddRoundKey → InvShiftRows → InvSubBytes (OHNE InvMixColumns)
  - Runden 13-1: AddRoundKey → InvMixColumns → InvShiftRows → InvSubBytes
  - Runde 0: AddRoundKey

  WICHTIGE AUSNAHME: Die erste Entschlüsselungs-Runde (=Runde 14 rückwärts)
  hat KEIN InvMixColumns, spiegelnd zur letzten Verschlüsselungs-Runde.

  SYMMETRIE DER RUNDEN:

  Verschlüsselung Runde 14:  SubBytes → ShiftRows → AddRoundKey
  Entschlüsselung Runde 14:  AddRoundKey → InvShiftRows → InvSubBytes

  Beide OHNE (Inv)MixColumns - perfekte Symmetrie!

  FUNKTIONSWEISE - Identisch zu MixColumnsState:

  Die Implementierung ist strukturell IDENTISCH zu MixColumnsState:
  1. Schleife über alle 4 Spalten
  2. Für jede Spalte:
     a) Bytes extrahieren
     b) InvMixSingleColumn aufrufen (statt MixSingleColumn)
     c) Bytes zurückschreiben

  Der EINZIGE Unterschied: InvMixSingleColumn statt MixSingleColumn

  WARUM DIESE IMPLEMENTIERUNG?

  Code-Duplikation vermeiden? Man könnte einen Parameter "forward/inverse"
  hinzufügen. Aber:
  - Separate Funktionen sind klarer
  - Keine Verzweigung nötig (schneller)
  - Entspricht FIPS 197 Notation
  - Einfacher zu verstehen und warten

  BEISPIEL - Vollständige State-Rücktransformation:

  Nach MixColumns:
       [0]  [1]  [2]  [3]
  [0]  47   40   A3   4C
  [1]  37   D4   70   9F
  [2]  94   E4   3A   42
  [3]  ED   A5   A6   BC

  Nach InvMixColumns (zurück zum Original):
       [0]  [1]  [2]  [3]
  [0]  87   F2   4D   97
  [1]  4C   6E   90   EC
  [2]  46   E7   4A   C3
  [3]  A6   8C   D8   95

  Jede Spalte wurde unabhängig zurücktransformiert.

  PERFORMANCE-VERGLEICH:

  InvMixColumns ist etwas langsamer als MixColumns:

  MixColumns:
  - 16× GFMul2 (schnell)
  - 16× GFMul3 (mittel)

  InvMixColumns:
  - 4× GFMul9 (langsamer: GFMul8 + GFMul1)
  - 4× GFMul11 (langsamer: GFMul8 + GFMul2 + GFMul1)
  - 4× GFMul13 (langsamer: GFMul8 + GFMul4 + GFMul1)
  - 4× GFMul14 (langsamer: GFMul8 + GFMul4 + GFMul2)

  Typisch: InvMixColumns ist etwa 1.5-2× langsamer als MixColumns

  ABER: Immer noch sehr schnell im Gesamtkontext!

  OPTIMIERUNGEN IN PRODUKTIVSYSTEMEN:

  In optimierten AES-Implementierungen gibt es Tricks:

  1. T-TABLES (Combined Tables):
     → Kombiniere InvSubBytes + InvMixColumns in einer Lookup-Tabelle
     → Sehr schnell, aber 4× 256× 4 Bytes Speicher (4 KB)
     → Anfällig für Cache-Timing-Angriffe

  2. BITSLICING:
     → Verarbeite viele Blöcke parallel
     → Nutzt SIMD-Instruktionen
     → Sehr schnell für Bulk-Verschlüsselung

  3. HARDWARE (AES-NI):
     → Moderne CPUs haben spezielle AES-Instruktionen
     → Ein Befehl macht eine ganze Runde (inkl. InvMixColumns)
     → 10-20× schneller als Software

  Unsere Implementierung: Klar, korrekt, lehrtauglich!

  SYMMETRIE-EIGENSCHAFT (WICHTIG!):

  Für alle State-Matrizen S gilt:
  InvMixColumnsState(MixColumnsState(S)) = S
  MixColumnsState(InvMixColumnsState(S)) = S

  Dies ist fundamental für AES:
  → Ohne perfekte Inverse könnte Entschlüsselung nicht funktionieren
  → Jede Abweichung würde Datenverlust bedeuten
  → Mathematische Korrektheit ist essentiell

  DEBUGGING-TIPP:

  Test für Korrektheit der Implementierung:
```pascal
  var
    Original, Test: TAESState;
    Row, Col: Integer;
  begin
    // Zufällige State erzeugen
    for Row := 0 to 3 do
      for Col := 0 to 3 do
        Original[Row, Col] := Random(256);

    // Kopieren für Test
    Test := Original;

    // Ver- und Entschlüsseln
    MixColumnsState(Test);
    InvMixColumnsState(Test);

    // Vergleichen - sollte identisch sein!
    for Row := 0 to 3 do
      for Col := 0 to 3 do
        if Test[Row, Col] <> Original[Row, Col] then
          WriteLn('FEHLER: InvMixColumns ist nicht korrekt!');
  end;
```

  VERWENDUNG IM AES256DECRYPTBLOCK:
```pascal
  procedure AES256DecryptBlock(...);
  begin
    BlockToState(InBlock, State);
    AddRoundKey(State, Context.RoundKeys[14]);

    for Round := 13 downto 1 do
    begin
      InvShiftRowsState(State);
      InvSubBytesState(State);
      AddRoundKey(State, Context.RoundKeys[Round]);
      InvMixColumnsState(State);         // ← HIER (in Runden 13-1)
    end;

    InvShiftRowsState(State);
    InvSubBytesState(State);
    AddRoundKey(State, Context.RoundKeys[0]);
    // Kein InvMixColumns in letzter Runde (wie bei Verschlüsselung)

    StateToBlock(State, OutBlock);
  end;
```

  MATHEMATISCHE VERIFIKATION:

  Die Korrektheit von InvMixColumns kann mathematisch bewiesen werden:

  M = MixColumns-Matrix
  M^(-1) = InvMixColumns-Matrix

  M × M^(-1) = I (Identitätsmatrix)

  In GF(2^8) kann dies durch Matrixmultiplikation verifiziert werden.
  Daemen und Rijmen haben dies in ihrer Rijndael-Spezifikation formal
  bewiesen.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.3.3: InvMixColumns Transformation
  - "The Design of Rijndael", Kapitel 4.1.3: Inverse Cipher
  - Matrix-Inverse über endlichen Körpern: Abstract Algebra
  - Linear Codes: Maximum Distance Separable (MDS) Codes
  - "AES Proposal: Rijndael" (1998): Mathematische Begründung

  ============================================================================
}
var
  Col: Integer;          // Laufvariable für Spalten (0..3)
  S0, S1, S2, S3: Byte;  // Die 4 Bytes einer Spalte
begin
  for Col := 0 to 3 do
  begin
   // Schleife über alle 4 Spalten der State-Matrix
   // Identische Struktur wie MixColumnsState
    S0 := State[0, Col];   // Zeile 0 der aktuellen Spalte
    S1 := State[1, Col];   // Zeile 1 der aktuellen Spalte
    S2 := State[2, Col];   // Zeile 2 der aktuellen Spalte
    S3 := State[3, Col];   // Zeile 3 der aktuellen Spalte

     // Jetzt haben wir eine vollständige Spalte in S0, S1, S2, S3
    // Diese Spalte wurde vorher durch MixColumnsState transformiert

    // -----------------------------------------------------------------------
    // Schritt 2: INVERSE MixColumns auf diese Spalte anwenden
    // -----------------------------------------------------------------------
    // InvMixSingleColumn führt die INVERSE Matrix-Multiplikation durch:
    // [ S0' ]   [ 14  11  13   9 ]   [ S0 ]
    // [ S1' ] = [  9  14  11  13 ] × [ S1 ]  (in GF(2^8))
    // [ S2' ]   [ 13   9  14  11 ]   [ S2 ]
    // [ S3' ]   [ 11  13   9  14 ]   [ S3 ]
    //
    // Dies ist die mathematische Inverse der MixColumns-Matrix

    InvMixSingleColumn(S0, S1, S2, S3);

    // Nach diesem Aufruf:
    // - S0, S1, S2, S3 enthalten die ZURÜCK-transformierten Werte
    // - Die Wirkung von MixSingleColumn wurde rückgängig gemacht
    // - Die Original-Bytes sind wiederhergestellt

    // -----------------------------------------------------------------------
    // Schritt 3: Die zurück-transformierten Bytes in State schreiben
    // -----------------------------------------------------------------------

    State[0, Col] := S0;    // Wiederhergestelltes Byte für Zeile 0
    State[1, Col] := S1;     // Wiederhergestelltes Byte für Zeile 1
    State[2, Col] := S2;    // Wiederhergestelltes Byte für Zeile 2
    State[3, Col] := S3;   // Wiederhergestelltes Byte für Zeile 3
     // Die aktuelle Spalte wurde erfolgreich zurück-transformiert
  end;
   // Nach der Schleife:
  // - ALLE 4 Spalten wurden durch InvMixColumns zurücktransformiert
  // - Jede Spalte wurde unabhängig behandelt
  // - Die Wirkung von MixColumnsState wurde komplett rückgängig gemacht

  // GARANTIE: InvMixColumnsState(MixColumnsState(State)) = State
  // Dies ist essentiell für die Korrektheit der AES-Entschlüsselung!

  // Die vertikale Diffusion der Verschlüsselung wurde aufgehoben,
  // und die State-Matrix ist bereit für die nächsten inversen Transformationen
  // (InvShiftRows und InvSubBytes)
end;

{ Hilfsfunktionen für die Key-Expansion }

function RotWord(W: LongWord): LongWord;
{
  ============================================================================
  RotWord - Rotiert ein 32-Bit-Wort um 8 Bits nach links
  ============================================================================

  ZWECK:
  Rotiert ein 32-Bit-Wort (4 Bytes) zyklisch um 8 Bits (1 Byte) nach links.
  Dies ist eine Hilfsfunktion für die AES Key Expansion (Key Schedule).

  PARAMETER:
  - W: Das zu rotierende 32-Bit-Wort (LongWord = 4 Bytes)

  RÜCKGABEWERT:
  - LongWord: Das um 8 Bits nach links rotierte Wort

  HINTERGRUND - Key Schedule und Rundenschlüssel:

  AES-256 benötigt 15 Rundenschlüssel (RoundKey[0..14]):
  - Jeder Rundenschlüssel: 16 Bytes (4×4 Matrix)
  - Insgesamt: 15 × 16 = 240 Bytes
  - Eingabe: 32 Bytes Hauptschlüssel
  - Ausgabe: 240 Bytes Rundenschlüssel

  Die Key Expansion erzeugt aus dem 32-Byte Hauptschlüssel alle
  Rundenschlüssel durch einen komplexen Algorithmus.

  WARUM KEY EXPANSION?

  Man könnte einfach den Hauptschlüssel in jeder Runde wiederverwenden.
  Aber das wäre SEHR unsicher:

  1. RELATED-KEY ATTACKS:
     → Angreifer könnten Beziehungen zwischen Runden ausnutzen
     → Schwächere Sicherheit

  2. SLIDE ATTACKS:
     → Wenn alle Rundenschlüssel gleich sind, gibt es Muster
     → Angriffe wie "Slide Attacks" werden möglich

  3. KEINE DIFFUSION DES SCHLÜSSELS:
     → Jedes Bit des Hauptschlüssels sollte alle Rundenschlüssel beeinflussen
     → Nur so ist maximale Sicherheit gewährleistet

  Die Key Expansion sorgt dafür, dass:
  - Jeder Rundenschlüssel kryptographisch stark ist
  - Rundenschlüssel voneinander unabhängig erscheinen
  - Der gesamte Hauptschlüssel alle Rundenschlüssel beeinflusst

  DIE ROLLE VON ROTWORD:

  RotWord ist Teil der Key Expansion und wird verwendet, um Wörter
  (4-Byte-Blöcke) zu mischen. Es ist eine einfache, aber wichtige
  Operation, die zur Diffusion innerhalb des Key Schedule beiträgt.

  FUNKTIONSWEISE - Bitshift-Operationen:

  Ein 32-Bit-Wort besteht aus 4 Bytes:
  W = [B3, B2, B1, B0]  (B3 = höchstwertiges Byte)

  In Binär (32 Bits):
  W = B3 B2 B1 B0

  Rotation um 8 Bits nach links:
  → Das höchstwertige Byte (B3) wird zum niedrigstwertigen
  → Alle anderen Bytes rücken um eine Position nach oben

  Ergebnis:
  W' = [B2, B1, B0, B3]

  BEISPIEL MIT HEX-WERTEN:

  W = 0x12345678

  Byte-Darstellung:
  B3 = 0x12 (höchstwertiges Byte, Bits 24-31)
  B2 = 0x34 (Bits 16-23)
  B1 = 0x56 (Bits 8-15)
  B0 = 0x78 (niedrigstwertiges Byte, Bits 0-7)

  Nach RotWord:
  W' = 0x34567812

  Byte-Darstellung:
  B3' = 0x34 (war B2)
  B2' = 0x56 (war B1)
  B1' = 0x78 (war B0)
  B0' = 0x12 (war B3)

  BINÄR-BEISPIEL:

  W = 0x12345678 = 00010010 00110100 01010110 01111000

  Links-Shift um 8 Bits:
  W << 8 = 00110100 01010110 01111000 00000000

  Rechts-Shift um 24 Bits (bringt B3 nach B0):
  W >> 24 = 00000000 00000000 00000000 00010010

  OR-Verknüpfung:
  (W << 8) | (W >> 24) = 00110100 01010110 01111000 00010010
                        = 0x34567812 ✓

  IMPLEMENTIERUNG - Die Formel:

  Result := (W shl 8) or (W shr 24)

  Schritt für Schritt:
  1. (W shl 8): Schiebe alle Bits 8 Positionen nach links
     → Die oberen 8 Bits fallen weg
     → Die unteren 8 Bits werden zu 0

  2. (W shr 24): Schiebe alle Bits 24 Positionen nach rechts
     → Die unteren 24 Bits fallen weg
     → Die oberen 8 Bits (B3) landen in den unteren 8 Bit-Positionen

  3. OR-Verknüpfung kombiniert beide:
     → Die linke Shift bringt B2, B1, B0 an die richtige Position
     → Die rechte Shift bringt B3 an die niedrigste Position
     → OR fügt sie zusammen

  WARUM ROTATION STATT SHIFT?

  ROTATION (zyklisch):
  - Keine Bits gehen verloren
  - Alle 4 Bytes bleiben erhalten
  - Umkehrbar (durch Rotation in Gegenrichtung)

  SHIFT (nicht-zyklisch):
  - Bits gehen verloren
  - Nicht umkehrbar
  - Information geht verloren

  Für den Key Schedule ist Umkehrbarkeit wichtig für Analyse und
  Verifikation.

  ALTERNATIVE IMPLEMENTIERUNG:

  Man könnte auch byte-weise arbeiten:
```pascal
  B0 := W and $FF;
  B1 := (W shr 8) and $FF;
  B2 := (W shr 16) and $FF;
  B3 := (W shr 24) and $FF;
  Result := (B2 shl 24) or (B1 shl 16) or (B0 shl 8) or B3;
```

  Aber die Bitshift-Version ist:
  - Kürzer
  - Schneller (weniger Operationen)
  - Eleganter

  VERWENDUNG IM KEY SCHEDULE:

  RotWord wird in AES256InitKey verwendet, immer in Kombination mit SubWord:
```pascal
  Temp := W[I - 1];
  if (I mod 8) = 0 then
  begin
    Temp := SubWord(RotWord(Temp));  // ← HIER: RotWord dann SubWord
    Temp := Temp xor RconWord(I div 8);
  end
```

  Die Reihenfolge ist wichtig:
  1. RotWord: Bytes rotieren
  2. SubWord: S-Box auf jedes Byte anwenden
  3. XOR mit Rcon: Rundenkonstante hinzufügen

  DIFFUSION IM KEY SCHEDULE:

  RotWord trägt zur Diffusion bei:
  - Mischt die Byte-Positionen
  - In Kombination mit SubWord: Jedes Byte beeinflusst andere Positionen
  - Nach mehreren Iterationen: Vollständige Vermischung

  SYMMETRIE:

  Rotation um 8 Bits nach links = Rotation um 24 Bits nach rechts
  (bei 32-Bit-Wörtern)

  Umkehrung:
  RotWord(RotWord(RotWord(RotWord(W)))) = W
  (4× Rotation um 8 Bits = 32 Bits = zurück zum Original)

  PERFORMANCE:

  Extrem schnell:
  - 2 Bitshift-Operationen
  - 1 OR-Operation
  - Alles in einem CPU-Taktzyklus auf modernen Prozessoren

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.2: Key Expansion
  - FIPS 197, Figure 11: KeyExpansion Pseudo-Code
  - "The Design of Rijndael", Kapitel 3.8: Key Schedule
  - Bitwise Operations: "Hacker's Delight" (Henry S. Warren)

  ============================================================================
}
begin
   // Zyklische Rotation um 8 Bits nach links
  // (W shl 8): Schiebt alle Bits 8 Positionen nach links
  //            → B3 B2 B1 B0 wird zu B2 B1 B0 00
  // (W shr 24): Schiebt alle Bits 24 Positionen nach rechts
  //            → B3 B2 B1 B0 wird zu 00 00 00 B3
  // OR kombiniert: B2 B1 B0 00 | 00 00 00 B3 = B2 B1 B0 B3
  Result := (W shl 8) or (W shr 24);
   // Beispiel: 0x12345678 → 0x34567812
  // Byte 0x12 wandert von Position 3 (höchste) nach Position 0 (niedrigste)
  // Alle anderen Bytes rücken um eine Position auf

  // Diese einfache Operation ist essentiell für die Diffusion im Key Schedule
end;

function SubWord(W: LongWord): LongWord;
{
  ============================================================================
  SubWord - Wendet die S-Box auf alle 4 Bytes eines Wortes an
  ============================================================================

  ZWECK:
  Wendet die AES S-Box-Substitution auf jedes der 4 Bytes eines 32-Bit-Wortes
  an. Dies ist eine Hilfsfunktion für die AES Key Expansion und bringt
  Nichtlinearität in den Key Schedule.

  PARAMETER:
  - W: Das 32-Bit-Wort (4 Bytes), auf das die S-Box angewendet werden soll

  RÜCKGABEWERT:
  - LongWord: Das Wort mit S-Box-substituierten Bytes

  HINTERGRUND - Nichtlinearität im Key Schedule:

  Der Key Schedule muss kryptographisch stark sein. Ohne Nichtlinearität
  wäre er anfällig für:

  1. LINEARE KRYPTOANALYSE:
     → Angreifer könnten lineare Gleichungssysteme aufstellen
     → Schlüssel könnte berechnet werden

  2. RELATED-KEY ATTACKS:
     → Beziehungen zwischen verschiedenen Schlüsseln ausnutzbar
     → Schwächere Sicherheit

  SubWord bringt die gleiche Nichtlinearität in den Key Schedule, die
  SubBytes für den Hauptalgorithmus bringt.

  DIE OPERATION - Byte für Byte:

  Ein 32-Bit-Wort besteht aus 4 Bytes:
  W = [b3, b2, b1, b0]

  SubWord wendet die S-Box auf jedes Byte an:
  W' = [SubByte(b3), SubByte(b2), SubByte(b1), SubByte(b0)]

  BEISPIEL MIT HEX-WERTEN:

  W = 0x12345678

  Bytes extrahieren:
  b3 = 0x12 (Bits 24-31)
  b2 = 0x34 (Bits 16-23)
  b1 = 0x56 (Bits 8-15)
  b0 = 0x78 (Bits 0-7)

  S-Box anwenden:
  SubByte(0x12) = 0xC9  (Lookup in AES_SBOX)
  SubByte(0x34) = 0xA5  (Lookup in AES_SBOX)
  SubByte(0x56) = 0xF4  (Lookup in AES_SBOX)
  SubByte(0x78) = 0x41  (Lookup in AES_SBOX)

  Ergebnis:
  W' = 0xC9A5F441

  IMPLEMENTIERUNG - Schritt für Schritt:

  Die Funktion extrahiert jedes Byte, wendet SubByte an, und
  setzt das Wort wieder zusammen.

  Schritt 1: Bytes extrahieren
```
  b0 := (W shr 24) and $FF  → Oberstes Byte (Bits 24-31)
  b1 := (W shr 16) and $FF  → Zweites Byte (Bits 16-23)
  b2 := (W shr 8) and $FF   → Drittes Byte (Bits 8-15)
  b3 := W and $FF           → Unterstes Byte (Bits 0-7)
```

  Schritt 2: S-Box anwenden
```
  b0 := SubByte(b0)
  b1 := SubByte(b1)
  b2 := SubByte(b2)
  b3 := SubByte(b3)
```

  Schritt 3: Wort wieder zusammensetzen
```
  Result := (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
```

  WARUM DIESE REIHENFOLGE?

  Die Bytes werden in der Reihenfolge b0, b1, b2, b3 verarbeitet:
  - b0 ist das höchstwertige Byte (Bits 24-31)
  - b3 ist das niedrigstwertige Byte (Bits 0-7)

  Dies entspricht der Big-Endian Darstellung, wie sie in FIPS 197
  verwendet wird.

  BITMASKEN ERKLÄRT:

  (W shr 24) and $FF:
  → shr 24: Schiebt Bits 24-31 nach Position 0-7
  → and $FF: Maskiert nur die unteren 8 Bits (= 11111111 in binär)
  → Ergebnis: Nur das ursprüngliche Byte an Position 24-31

  Beispiel:
  W = 0x12345678
  W shr 24 = 0x00000012
  0x00000012 and $FF = 0x12 ✓

  VERWENDUNG IM KEY SCHEDULE:

  SubWord wird in AES256InitKey in Kombination mit RotWord verwendet:
```pascal
  if (I mod 8) = 0 then
  begin
    Temp := SubWord(RotWord(Temp));  // ← HIER
    Temp := Temp xor RconWord(I div 8);
  end
  else if (I mod 8) = 4 then
  begin
    Temp := SubWord(Temp);  // ← Auch HIER (ohne RotWord)
  end
```

  Bei AES-256 gibt es zwei Fälle, wo SubWord verwendet wird:
  1. Alle 8 Wörter (I mod 8 = 0): Mit RotWord und Rcon
  2. Nach 4 Wörtern (I mod 8 = 4): Nur SubWord, ohne Rotation

  Dies ist spezifisch für AES-256. AES-128 und AES-192 haben andere Muster.

  WARUM SUBWORD IM KEY SCHEDULE?

  SubWord bringt die S-Box (Nichtlinearität) in den Key Schedule:

  1. KONFUSION:
     → Komplexe Beziehung zwischen Hauptschlüssel und Rundenschlüsseln
     → Schwer, von Rundenschlüsseln auf Hauptschlüssel zu schließen

  2. DIFFUSION:
     → In Kombination mit RotWord und XOR: Jedes Bit des Hauptschlüssels
       beeinflusst viele Bits der Rundenschlüssel

  3. RELATED-KEY RESISTENZ:
     → Verhindert Angriffe, die Beziehungen zwischen verschiedenen
       Schlüsseln ausnutzen

  UNTERSCHIED ZU SUBBYTESSTATE:

  SubBytesState: Arbeitet auf der State-Matrix (16 Bytes)
  SubWord: Arbeitet auf einem Wort (4 Bytes)

  Aber: Beide verwenden die gleiche S-Box (AES_SBOX)!
  → Gleiche kryptographische Eigenschaften
  → Konsistente Nichtlinearität im gesamten AES

  PERFORMANCE:

  Schnell:
  - 4 Bitshift-Operationen (Extraktion)
  - 4 S-Box Lookups (sehr schnell)
  - 4 Bitshift-Operationen (Zusammensetzen)
  - 3 OR-Operationen

  Alles zusammen: Wenige Nanosekunden auf modernen CPUs

  SYMMETRIE:

  SubWord ist NICHT selbst-invers!
  → SubWord(SubWord(W)) ≠ W
  → Man bräuchte InvSubWord (mit AES_INV_SBOX)

  Dies ist okay, da der Key Schedule nur in eine Richtung läuft:
  → Bei Verschlüsselung: Hauptschlüssel → Rundenschlüssel generieren
  → Bei Entschlüsselung: Gleiche Rundenschlüssel, aber rückwärts verwendet

  DEBUGGING-TIPP:

  Test für korrekte Implementierung:
```pascal
  W := 0x12345678;
  W' := SubWord(W);

  // Manuell verifizieren:
  Expected := (LongWord(SubByte(0x12)) shl 24) or
              (LongWord(SubByte(0x34)) shl 16) or
              (LongWord(SubByte(0x56)) shl 8) or
              LongWord(SubByte(0x78));

  if W' <> Expected then
    WriteLn('FEHLER in SubWord!');
```

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.2: Key Expansion
  - FIPS 197, Sektion 5.1.1: SubBytes (gleiche S-Box wie SubWord)
  - "The Design of Rijndael", Kapitel 3.8.1: Key Schedule Details
  - Related-Key Attacks: "Key-Schedule Cryptanalysis of IDEA, G-DES..."

  ============================================================================
}
var
  b0, b1, b2, b3: Byte;     // Die 4 Bytes des Wortes
begin
   // -------------------------------------------------------------------------
  // Schritt 1: Die 4 Bytes aus dem 32-Bit-Wort extrahieren
  // -------------------------------------------------------------------------

  // Oberstes Byte (Bits 24-31) extrahieren
  // Shift um 24 Bits nach rechts bringt Bits 24-31 nach Position 0-7

  b0 := (W shr 24) and $FF;
   // Zweites Byte (Bits 16-23) extrahieren
  // Shift um 16 Bits nach rechts bringt Bits 16-23 nach Position 0-7
  b1 := (W shr 16) and $FF;
  // Drittes Byte (Bits 8-15) extrahieren
  // Shift um 8 Bits nach rechts bringt Bits 8-15 nach Position 0-7
  b2 := (W shr 8) and $FF;
   
  // Unterstes Byte (Bits 0-7) extrahieren
  // Keine Shift nötig, nur Maskierung
  b3 := W and $FF;
  // Nach diesem Schritt: b0, b1, b2, b3 enthalten die 4 Bytes
  // Beispiel: W = 0x12345678 → b0=0x12, b1=0x34, b2=0x56, b3=0x78

  // -------------------------------------------------------------------------
  // Schritt 2: S-Box Substitution auf jedes Byte anwenden
  // -------------------------------------------------------------------------

  // Jedes Byte durch seinen S-Box-Wert ersetzen
  // Dies bringt Nichtlinearität in den Key Schedule

  b0 := SubByte(b0);   // SubByte verwendet AES_SBOX Lookup-Tabelle
  b1 := SubByte(b1);
  b2 := SubByte(b2);
  b3 := SubByte(b3);
  // Nach diesem Schritt: Alle 4 Bytes wurden durch die S-Box transformiert
  // Beispiel: b0=0x12→0xC9, b1=0x34→0xA5, b2=0x56→0xF4, b3=0x78→0x41

  // -------------------------------------------------------------------------
  // Schritt 3: Die transformierten Bytes wieder zu einem 32-Bit-Wort kombinieren
  // -------------------------------------------------------------------------

  // Die 4 Bytes werden an ihre ursprünglichen Positionen zurückgeschoben:
  // b0: Shift um 24 Bits nach links → Bits 24-31
  // b1: Shift um 16 Bits nach links → Bits 16-23
  // b2: Shift um 8 Bits nach links → Bits 8-15
  // b3: Keine Shift → Bits 0-7
  // OR kombiniert alle zu einem 32-Bit-Wort
  Result :=
    (LongWord(b0) shl 24) or       // b0 nach Bits 24-31
    (LongWord(b1) shl 16) or       // b1 nach Bits 16-23
    (LongWord(b2) shl 8) or        // b2 nach Bits 8-15
    LongWord(b3);                  // b3 bleibt bei Bits 0-7

   // LongWord(...) Cast ist wichtig, um sicherzustellen, dass die
  // Shift-Operationen auf 32-Bit-Werten arbeiten, nicht auf 8-Bit Bytes

  // Ergebnis: Ein 32-Bit-Wort, bei dem jedes Byte durch die S-Box
  // substituiert wurde
  // Beispiel: 0x12345678 → 0xC9A5F441

  // Diese Operation ist fundamental für die Sicherheit des Key Schedule:
  // Sie bringt die gleiche Nichtlinearität, die SubBytes für den
  // Hauptalgorithmus bringt

end;

function RconWord(I: Integer): LongWord;

{
  ============================================================================
  RconWord - Erzeugt die Rundenkonstante (Rcon) für den Key Schedule
  ============================================================================

  ZWECK:
  Erzeugt die Rundenkonstante (Rcon - Round Constant) für einen gegebenen
  Rundenschritt im AES-256 Key Schedule. Dies verhindert, dass der
  Key Schedule symmetrisch wird.

  PARAMETER:
  - I: Die Rundennummer (1..10 für AES-256)

  RÜCKGABEWERT:
  - LongWord: Die Rundenkonstante als 32-Bit-Wort (nur oberstes Byte ist ≠ 0)

  HINTERGRUND - Warum Rundenkonstanten?

  Ohne Rundenkonstanten wäre der Key Schedule symmetrisch:
  - Gleiche Operationen in jeder Iteration
  - Musterbildung möglich
  - Anfällig für "Slide Attacks"

  Die Rundenkonstanten (Rcon) machen jede Iteration des Key Schedule
  EINZIGARTIG und ASYMMETRISCH.

  WAS SIND SLIDE ATTACKS?

  Slide Attacks (Alex Biryukov & David Wagner, 1999) nutzen Symmetrien
  in Verschlüsselungsalgorithmen aus:

  Wenn alle Runden identisch sind:
  → Angreifer kann Rundengrenzen "verschieben"
  → Effektive Sicherheit sinkt drastisch
  → AES ohne Rcon wäre anfällig!

  Rcon verhindert dies durch:
  → Jede Runde hat einzigartige Konstante
  → Keine zwei Runden sind identisch
  → Slide Attacks werden unmöglich

  DIE RCON-TABELLE:

  FIPS 197 definiert 10 Rundenkonstanten (Rcon[1] bis Rcon[10]):

  Rcon[1]  = 0x01
  Rcon[2]  = 0x02
  Rcon[3]  = 0x04
  Rcon[4]  = 0x08
  Rcon[5]  = 0x10
  Rcon[6]  = 0x20
  Rcon[7]  = 0x40
  Rcon[8]  = 0x80
  Rcon[9]  = 0x1B
  Rcon[10] = 0x36

  MUSTER ERKANNT?

  Die ersten 8 Werte sind Zweierpotenzen:
  0x01 = 2^0
  0x02 = 2^1
  0x04 = 2^2
  0x08 = 2^3
  0x10 = 2^4
  0x20 = 2^5
  0x40 = 2^6
  0x80 = 2^7

  Aber 0x1B und 0x36 passen nicht? Warum?

  GALOIS-FELD ARITHMETIK:

  Die Rcon-Werte sind keine normalen Zweierpotenzen, sondern
  Zweierpotenzen in GF(2^8) - dem gleichen Galois-Feld wie bei MixColumns!

  Die Berechnung:
  Rcon[1] = x^0 = 1
  Rcon[2] = x^1 = x = 2
  Rcon[3] = x^2 = 4
  ...
  Rcon[8] = x^7 = 128 = 0x80
  Rcon[9] = x^8 mod m(x)

  Wenn x^8 erreicht wird (größer als 8 Bit), wird modulo m(x) reduziert:
  m(x) = x^8 + x^4 + x^3 + x + 1 = 0x11B (das irreducible Polynom!)

  x^8 mod m(x) = x^4 + x^3 + x + 1 = 0x1B

  x^9 = x × x^8 mod m(x) = x × 0x1B mod m(x)

  In GF(2^8) mit unserem GFMul2:
  GFMul2(0x1B) = ?
  0x1B = 00011011, Bit 7 = 0
  → 0x1B << 1 = 00110110 = 0x36

  Also: Rcon[10] = 0x36

  Dies ist KEINE Willkür, sondern exakte Mathematik!

  WARUM NUR 10 WERTE?

  AES-256 benötigt maximal 10 Rcon-Werte, weil:
  - 60 Wörter werden erzeugt (8 original + 52 expandiert)
  - Rcon wird nur alle 8 Wörter verwendet (wenn I mod 8 = 0)
  - 52 / 8 = 6,5 → aber wir starten bei Wort 8 → 7 Verwendungen

  Aber FIPS 197 definiert trotzdem 10 Werte für Konsistenz mit
  AES-128 (braucht alle 10).

  DAS 32-BIT-WORT FORMAT:

  RconWord gibt nicht nur das Byte zurück, sondern ein 32-Bit-Wort:

  Rcon[I] wird zum Wort: [Rcon[I], 0x00, 0x00, 0x00]

  Beispiel:
  Rcon[1] = 0x01 → RconWord(1) = 0x01000000
  Rcon[5] = 0x10 → RconWord(5) = 0x10000000

  Nur das OBERSTE Byte ist ≠ 0, die anderen 3 Bytes sind 0.

  WARUM DIESE FORMATIERUNG?

  Im Key Schedule wird Rcon mit einem 32-Bit-Wort XOR-verknüpft:
```pascal
  Temp := SubWord(RotWord(Temp));
  Temp := Temp xor RconWord(I div 8);  // ← XOR mit 32-Bit-Wort
```

  Da nur das oberste Byte von Rcon ≠ 0 ist, wird nur das oberste
  Byte von Temp beeinflusst. Die anderen 3 Bytes bleiben unverändert.

  Dies ist Absicht! Es bringt Asymmetrie, ohne alle Bytes zu beeinflussen.

  IMPLEMENTIERUNG:

  Die Funktion verwendet eine Lookup-Tabelle (RconTable):
  - Einfach und schnell
  - Keine Berechnung zur Laufzeit nötig
  - Fehlerfrei (Werte sind aus FIPS 197)

  Alternative: Berechnung mit GFMul2:
```pascal
  Rcon := 1;
  for j := 1 to I-1 do
    Rcon := GFMul2(Rcon);
```
  Aber Lookup ist schneller!

  BEREICHSPRÜFUNG:

  Wenn I außerhalb 1..10 liegt:
  → Return 0

  Dies sollte nie passieren bei korrekter Verwendung, aber es ist
  defensive Programmierung.

  VERWENDUNG IM KEY SCHEDULE:
```pascal
  for I := 8 to 59 do
  begin
    Temp := W[I - 1];

    if (I mod 8) = 0 then
    begin
      Temp := SubWord(RotWord(Temp));
      Temp := Temp xor RconWord(I div 8);  // ← HIER
    end
    ...
```

  Rcon wird bei I = 8, 16, 24, 32, 40, 48, 56 verwendet:
  → I div 8 = 1, 2, 3, 4, 5, 6, 7
  → RconWord(1), RconWord(2), ..., RconWord(7)

  SICHERHEITSASPEKT:

  Die Rundenkonstanten sind PUBLIC KNOWLEDGE:
  - Jeder kennt die Werte
  - Sie sind in FIPS 197 veröffentlicht
  - Keine Geheimhaltung nötig

  Ihre Aufgabe ist NICHT Geheimhaltung, sondern:
  - Asymmetrie erzeugen
  - Muster verhinden
  - Kryptoanalytische Angriffe erschweren

  "Nothing up my sleeve numbers" - Die Werte kommen aus nachvollziehbarer
  Mathematik (GF(2^8) Potenzen), nicht aus Willkür. Dies schafft Vertrauen,
  dass keine Backdoors eingebaut sind.

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.2: Key Expansion, erwähnt Rcon
  - FIPS 197, Figure 11: KeyExpansion mit Rcon
  - "The Design of Rijndael", Kapitel 3.8.1: Rcon-Werte erklärt
  - Slide Attacks: Biryukov & Wagner (1999)
  - "Nothing up my sleeve numbers": NSA-Begriff für transparente Konstanten

  ============================================================================
}
const
   // Rundenkonstanten aus FIPS 197
  // Dies sind Zweierpotenzen in GF(2^8), nicht in normaler Arithmetik!
  // Berechnet als x^(I-1) in GF(2^8) mit m(x) = x^8 + x^4 + x^3 + x + 1

  RconTable: array[1..10] of Byte = (    $01,  // x^0 = 1
                                         $02,   // x^1 = 2
                                         $04,  // x^2 = 4
                                         $08,  // x^3 = 8
                                         $10,  // x^4 = 16
                                         $20,  // x^5 = 32
                                         $40,  // x^6 = 64
                                         $80,  // x^7 = 128
                                         $1B,  // x^8 mod m(x) = x^4 + x^3 + x + 1 = 27
                                         $36);  // x^9 mod m(x) = 54
begin
    // Bereichsprüfung: I sollte zwischen 1 und 10 liegen
  if (I < 1) or (I > 10) then
    // Außerhalb des gültigen Bereichs → Return 0
    // Dies sollte bei korrekter Verwendung nie passieren
    Result := 0
  else
    // Rcon-Wert aus der Tabelle holen und zum 32-Bit-Wort formatieren
    // Das Rcon-Byte wird ins oberste Byte (Bits 24-31) geschoben
    // Die unteren 3 Bytes bleiben 0
    // Beispiel: RconTable[1] = 0x01 → 0x01000000

  Result := LongWord(RconTable[I]) shl 24;

    // Ergebnis: Ein 32-Bit-Wort im Format [Rcon, 0x00, 0x00, 0x00]
    // Nur das oberste Byte ist ≠ 0
    // Dies wird mit einem Wort XOR-verknüpft und beeinflusst nur dessen oberstes Byte

    // Die Rundenkonstanten machen jede Iteration des Key Schedule einzigartig
    // und verhindern Symmetrien, die zu Slide Attacks führen könnten
end;

{$push}
{$HINTS OFF}   // Compiler-Hint für nicht verwendete Variablen unterdrücken

procedure AES256InitKey(const Key: TBytes; out Context: TAES256Context);
{
  ============================================================================
  AES256InitKey - AES-256 Key Schedule (Rundenschlüssel-Generierung)
  ============================================================================

  ZWECK:
  Generiert aus einem 32-Byte (256-Bit) Hauptschlüssel alle 15 Rundenschlüssel,
  die für die AES-256 Ver- und Entschlüsselung benötigt werden. Dies ist der
  "Key Schedule" oder "Key Expansion" Algorithmus.

  PARAMETER:
  - Key: Der 32-Byte (256-Bit) Hauptschlüssel als dynamisches Array
  - Context: OUT-Parameter - wird mit allen 15 Rundenschlüsseln gefüllt

  RÜCKGABEWERT:
  - Keiner (Context wird direkt befüllt)

  FEHLERBEHANDLUNG:
  - Wirft Exception, wenn Key kürzer als 32 Bytes ist

  HINTERGRUND - Der Key Schedule:

  Der Key Schedule ist eine der wichtigsten Komponenten von AES. Seine Aufgabe:

  AUS: 32 Bytes Hauptschlüssel (256 Bit)
  ERZEUGE: 15 × 16 Bytes = 240 Bytes Rundenschlüssel

  Jeder der 15 Rundenschlüssel (RoundKey[0..14]) ist eine 4×4-Matrix (16 Bytes):
  - RoundKey[0]: Wird VOR der ersten Runde verwendet (Initial AddRoundKey)
  - RoundKey[1..13]: Werden in Runden 1-13 verwendet
  - RoundKey[14]: Wird in Runde 14 verwendet (letzte Runde)

  WARUM 15 RUNDENSCHLÜSSEL?

  AES-256 hat 14 Runden PLUS eine initiale AddRoundKey-Operation:
```
  AddRoundKey(State, RoundKey[0])        ← #1 (Initial)

  for Round := 1 to 13 do                ← #2 bis #14 (Runden 1-13)
    SubBytes, ShiftRows, MixColumns
    AddRoundKey(State, RoundKey[Round])

  SubBytes, ShiftRows                    ← #15 (Runde 14)
  AddRoundKey(State, RoundKey[14])
```

  Insgesamt: 15× AddRoundKey → 15 Rundenschlüssel benötigt!

  DER ALGORITHMUS - Überblick:

  Der Key Schedule arbeitet in Schritten von 32-Bit-Wörtern (4 Bytes):

  1. INITIALISIERUNG (Wörter 0-7):
     Die ersten 8 Wörter (32 Bytes) werden direkt aus dem Hauptschlüssel kopiert

  2. EXPANSION (Wörter 8-59):
     Die nächsten 52 Wörter werden rekursiv berechnet:
     - Jedes neue Wort hängt vom vorherigen Wort ab
     - Alle 8 Wörter: Spezielle Transformation (RotWord, SubWord, Rcon)
     - Nach 4 Wörtern: Zusätzliches SubWord (nur bei AES-256!)

  3. KONVERTIERUNG:
     Die 60 Wörter werden in 15 Rundenschlüssel (je 4 Wörter) umgewandelt

  WARUM 60 WÖRTER?

  15 Rundenschlüssel × 4 Wörter pro Rundenschlüssel = 60 Wörter
  1 Wort = 4 Bytes → 60 Wörter = 240 Bytes

  AES-VARIANTEN IM VERGLEICH:

  AES-128: 44 Wörter (11 Rundenschlüssel, 10 Runden)
  AES-192: 52 Wörter (13 Rundenschlüssel, 12 Runden)
  AES-256: 60 Wörter (15 Rundenschlüssel, 14 Runden) ← Wir sind hier!

  SCHRITT 1: INITIALISIERUNG - Die ersten 8 Wörter:

  Der 32-Byte Hauptschlüssel wird in 8 Wörter aufgeteilt:

  Key[0..3]   → W[0] (erstes Wort)
  Key[4..7]   → W[1] (zweites Wort)
  Key[8..11]  → W[2] (drittes Wort)
  ...
  Key[28..31] → W[7] (achtes Wort)

  Jedes Wort wird im Big-Endian Format konstruiert:
  W[i] = (Key[4i] << 24) | (Key[4i+1] << 16) | (Key[4i+2] << 8) | Key[4i+3]

  Beispiel:
  Wenn Key[0..3] = [0x60, 0x3D, 0xEB, 0x10]:
  W[0] = (0x60 << 24) | (0x3D << 16) | (0xEB << 8) | 0x10
       = 0x603DEB10

  SCHRITT 2: EXPANSION - Die nächsten 52 Wörter:

  Für I = 8 bis 59 wird jedes neue Wort W[I] berechnet:

  FALL 1: Wenn (I mod 8) = 0  (alle 8 Wörter):
```
  Temp := W[I-1]
  Temp := RotWord(Temp)          // Bytes rotieren
  Temp := SubWord(Temp)          // S-Box anwenden
  Temp := Temp XOR RconWord(...)  // Rundenkonstante hinzufügen
  W[I] := W[I-8] XOR Temp
```

  FALL 2: Wenn (I mod 8) = 4  (nur bei AES-256!):
```
  Temp := W[I-1]
  Temp := SubWord(Temp)          // Nur S-Box, kein RotWord!
  W[I] := W[I-8] XOR Temp
```

  FALL 3: Alle anderen Positionen:
```
  W[I] := W[I-8] XOR W[I-1]      // Einfaches XOR
```

  WICHTIG - AES-256 Besonderheit:

  Der zusätzliche SubWord-Schritt bei (I mod 8) = 4 ist EINZIGARTIG für AES-256!
  AES-128 und AES-192 haben dies nicht.

  Warum? Mehr Diffusion im Key Schedule:
  - AES-256 hat einen längeren Schlüssel (32 Bytes)
  - Ohne zusätzliches SubWord: Schwächere Durchmischung
  - Mit SubWord: Bessere Diffusion, stärkere Rundenschlüssel

  Dies wurde von Daemen und Rijmen speziell für AES-256 hinzugefügt,
  um die Sicherheit zu maximieren.

  BEISPIEL - FALL 1 (I = 8, das erste expandierte Wort):

  I = 8, also (I mod 8) = 0

  1. Temp := W[7]  (letztes initialisiertes Wort)
  2. Temp := RotWord(Temp)  // Bytes rotieren
  3. Temp := SubWord(Temp)  // S-Box anwenden
  4. Temp := Temp XOR RconWord(8 div 8) = Temp XOR RconWord(1)
  5. W[8] := W[0] XOR Temp

  BEISPIEL - FALL 2 (I = 12):

  I = 12, also (I mod 8) = 4

  1. Temp := W[11]
  2. Temp := SubWord(Temp)  // Nur S-Box, KEIN RotWord!
  3. W[12] := W[4] XOR Temp

  BEISPIEL - FALL 3 (I = 9):

  I = 9, also (I mod 8) = 1

  1. W[9] := W[1] XOR W[8]  // Einfaches XOR

  SCHRITT 3: KONVERTIERUNG - Wörter zu Rundenschlüsseln:

  Die 60 Wörter werden in 15 Rundenschlüssel umgewandelt:

  RoundKey[0] ← W[0], W[1], W[2], W[3]
  RoundKey[1] ← W[4], W[5], W[6], W[7]
  RoundKey[2] ← W[8], W[9], W[10], W[11]
  ...
  RoundKey[14] ← W[56], W[57], W[58], W[59]

  Jedes Wort wird in eine Spalte der 4×4 Rundenschlüssel-Matrix konvertiert:

  Wort W = [B3, B2, B1, B0] wird zu Spalte:
  RoundKey[Round][0, Col] = B3  (oberstes Byte)
  RoundKey[Round][1, Col] = B2
  RoundKey[Round][2, Col] = B1
  RoundKey[Round][3, Col] = B0  (unterstes Byte)

  SICHERHEITSEIGENSCHAFTEN DES KEY SCHEDULE:

  1. DIFFUSION:
     → Jedes Bit des Hauptschlüssels beeinflusst viele Bits aller Rundenschlüssel
     → Nach wenigen Iterationen: Vollständige Vermischung

  2. NICHTLINEARITÄT:
     → SubWord bringt S-Box (nichtlinear) in den Key Schedule
     → Verhindert lineare Beziehungen zwischen Rundenschlüsseln

  3. ASYMMETRIE:
     → Rcon macht jede Iteration einzigartig
     → Keine zwei Rundenschlüssel werden gleich berechnet

  4. RELATED-KEY RESISTENZ:
     → Schwer, von ähnlichen Hauptschlüsseln auf Beziehungen zu schließen
     → Schutz gegen Related-Key Attacks

  BEKANNTE SCHWÄCHEN (Akademisch, nicht praktisch):

  Der AES-256 Key Schedule hat bekannte theoretische Schwächen:

  1. RELATED-KEY ATTACKS (Biryukov & Khovratovich, 2009):
     → Unter sehr speziellen Bedingungen angreifbar
     → Benötigt 2^99 Operationen (praktisch unmöglich)
     → Nur relevant, wenn Angreifer verwandte Schlüssel wählen kann

  2. KEY SCHEDULE KRITIK:
     → Einige Forscher fanden den Key Schedule "zu einfach"
     → AES-256 hat paradoxerweise schwächeren Key Schedule als AES-128
     → Aber: Kein praktischer Angriff bekannt!

  WICHTIG: Diese Schwächen sind rein akademisch. In der Praxis ist
  AES-256 absolut sicher bei korrekter Verwendung!

  WARUM LOKALER CONTEXT (LocalCtx)?

  Die Funktion verwendet eine lokale Variable LocalCtx:
```pascal
  var
    LocalCtx: TAES256Context;
  begin
    FillChar(LocalCtx, SizeOf(LocalCtx), 0);  // Initialisieren
    ... // Rundenschlüssel berechnen
    Context := LocalCtx;  // Erst am Ende kopieren
  end;
```

  Warum nicht direkt in Context schreiben?

  1. SICHERHEIT:
     → Falls Berechnung fehlschlägt (z.B. Exception), bleibt Context unverändert
     → Keine halb-initialisierten Daten

  2. KLARHEIT:
     → Deutlich macht, dass Context ein OUT-Parameter ist
     → Erst am Ende wird das Ergebnis übergeben

  3. DEBUGGING:
     → Lokale Variable kann inspiziert werden
     → Context wird nicht vorzeitig überschrieben

  PERFORMANCE:

  Der Key Schedule ist relativ langsam (verglichen mit einer Runde):
  - Viele S-Box Lookups (SubWord)
  - Viele XOR-Operationen
  - 52 Wort-Berechnungen

  Aber: Er wird nur EINMAL pro Schlüssel ausgeführt!

  Typische Zeiten:
  - Key Schedule: ~1-2 Mikrosekunden
  - Eine Runde: ~50-100 Nanosekunden
  - Komplette Verschlüsselung: ~700-1000 Nanosekunden

  Der Key Schedule ist ~10× langsamer als die Verschlüsselung, aber das
  ist egal, da er nur einmal ausgeführt wird.

  OPTIMIERUNGEN:

  In Produktivsystemen gibt es verschiedene Optimierungen:

  1. VORBERECHNUNG:
     → Rundenschlüssel vorberechnen und speichern
     → Bei vielen Verschlüsselungen mit gleichem Schlüssel

  2. ON-THE-FLY:
     → Rundenschlüssel während der Verschlüsselung berechnen
     → Spart Speicher, aber langsamer

  3. HARDWARE (AES-NI):
     → Moderne CPUs haben AESKEYGENASSIST Instruktion
     → Key Schedule in Hardware, extrem schnell

  Unsere Implementierung: Klar, korrekt, vollständig!

  VERWENDUNG:
```pascal
  var
    KeyBytes: TBytes;
    Ctx: TAES256Context;
  begin
    // 1. Hauptschlüssel erzeugen (z.B. aus Passwort via SHA-256)
    KeyBytes := SHA256(StringToBytesUTF8('MeinPasswort'));

    // 2. Key Schedule ausführen
    AES256InitKey(KeyBytes, Ctx);

    // 3. Ctx enthält jetzt alle 15 Rundenschlüssel
    // 4. Ctx kann für viele Ver-/Entschlüsselungen wiederverwendet werden
    AES256EncryptBlock(PlainBlock, CipherBlock, Ctx);
    AES256DecryptBlock(CipherBlock, PlainBlock, Ctx);
  end;
```

  DEBUGGING-TIPPS:

  1. TEST MIT NIST-VEKTOR:
     FIPS 197 Appendix A.3 enthält vollständige Key Schedule Beispiele
     → Alle 60 Wörter sind angegeben
     → Kann zur Verifikation verwendet werden

  2. WORT-INSPEKTION:
     Während der Entwicklung: W-Array ausgeben und mit FIPS 197 vergleichen

  3. RUNDENSCHLÜSSEL-DUMP:
     Nach Berechnung: Alle 15 RoundKeys als Hex ausgeben

  SICHERHEITSHINWEISE:

  1. SCHLÜSSEL LÖSCHEN:
     Nach Verwendung sollten KeyBytes und Context überschrieben werden:
```pascal
     FillChar(KeyBytes[0], Length(KeyBytes), 0);
     FillChar(Context, SizeOf(Context), 0);
```

  2. KEIN SCHLÜSSEL-REUSE:
     Jeder Schlüssel sollte nur für eine begrenzte Datenmenge verwendet werden

  3. ZUFÄLLIGE SCHLÜSSEL:
     Schlüssel sollten kryptographisch sicher zufällig sein
     (Passwort → SHA-256 ist okay für Demos, aber besser: PBKDF2/Argon2)

  WEITERFÜHRENDE INFORMATIONEN:
  - FIPS 197, Sektion 5.2: Key Expansion (offizieller Algorithmus)
  - FIPS 197, Appendix A.3: Vollständiges AES-256 Key Schedule Beispiel
  - FIPS 197, Figure 11: KeyExpansion Pseudo-Code
  - "The Design of Rijndael", Kapitel 3.8: Key Schedule Design-Rationale
  - Biryukov & Khovratovich (2009): "Related-Key Cryptanalysis of AES-256"
  - NIST: "Recommendation for Block Cipher Modes of Operation"

  ============================================================================
}
var
  LocalCtx: TAES256Context;              // Lokaler Kontext, wird am Ende nach Context kopiert
  W: array[0..59] of LongWord;           // 60 Wörter (4-Byte-Blöcke) für Key Expansion
  I: Integer;                            // Laufvariable für Schleifen
  Temp: LongWord;                        // Temporäres Wort für Berechnungen
  Round, Col: Integer;                   // Laufvariablen für Rundenschlüssel-Konvertierung
  WordIndex: Integer;                    // Index im W-Array beim Auslesen
begin

   // -------------------------------------------------------------------------
  // INITIALISIERUNG
  // -------------------------------------------------------------------------
  // Lokalen Kontext mit Nullen initialisieren (Sicherheit)
  // Dies stellt sicher, dass keine alten Daten im Speicher bleiben
  FillChar(LocalCtx, SizeOf(LocalCtx), 0);

  // AES-256 erwartet exakt 32 Byte Schlüsselmaterial.
  // (Für Lernzwecke ist es besser, hier strikt zu sein, damit keine stillen Kürzungen passieren.)

  // Validierung: Key muss mindestens 32 Bytes lang sein
  // AES-256 benötigt exakt einen 256-Bit (32-Byte) Schlüssel

  if Length(Key) <> 32 then
    raise Exception.Create('AES256InitKey: Key muss genau 32 Bytes (256 Bit) lang sein.');
    // -------------------------------------------------------------------------
  // SCHRITT 1: Initialisierung - Die ersten 8 Wörter (W[0..7])
  // -------------------------------------------------------------------------
  // Die ersten 8 Wörter werden direkt aus dem 32-Byte Hauptschlüssel kopiert
  // Jedes Wort besteht aus 4 aufeinanderfolgenden Bytes des Schlüssels


  for I := 0 to 7 do
  begin
     // Jedes Wort wird im Big-Endian Format konstruiert:
    // Die 4 Bytes Key[4*I] bis Key[4*I+3] werden zu einem 32-Bit-Wort kombiniert
    //
    // Byte-Positionen für Wort I:
    // - Key[4*I]     → Bits 24-31 (höchstwertigstes Byte)
    // - Key[4*I + 1] → Bits 16-23
    // - Key[4*I + 2] → Bits 8-15
    // - Key[4*I + 3] → Bits 0-7  (niedrigstwertigstes Byte)

    W[I] :=
      (LongWord(Key[4 * I]) shl 24) or       // Erstes Byte nach Position 24-31
      (LongWord(Key[4 * I + 1]) shl 16) or   // Zweites Byte nach Position 16-23
      (LongWord(Key[4 * I + 2]) shl 8) or    // Drittes Byte nach Position 8-15
      LongWord(Key[4 * I + 3]);              // Viertes Byte bleibt bei Position 0-7
     // Beispiel für I=0:
    // W[0] = (Key[0] << 24) | (Key[1] << 16) | (Key[2] << 8) | Key[3]
  end;

  // Nach dieser Schleife: W[0..7] enthalten die ersten 32 Bytes des Schlüssels
  // als 8 Wörter im Big-Endian Format

  // -------------------------------------------------------------------------
  // SCHRITT 2: Expansion - Die nächsten 52 Wörter (W[8..59])
  // -------------------------------------------------------------------------
  // Jedes neue Wort wird aus vorherigen Wörtern berechnet
  // Der Algorithmus unterscheidet 3 Fälle basierend auf der Position (I mod 8)


  for I := 8 to 59 do
  begin
    // Temp wird zunächst auf das vorherige Wort gesetzt
    // Dies ist die Basis für alle drei Fälle
    Temp := W[I - 1];
     // -----------------------------------------------------------------------
    // FALL 1: (I mod 8) = 0 → Alle 8 Wörter
    // -----------------------------------------------------------------------
    // Dies ist der komplexeste Fall mit maximaler Transformation
    // Tritt auf bei I = 8, 16, 24, 32, 40, 48, 56


    if (I mod 8) = 0 then
    begin
      // Schritt 1: RotWord - Bytes zyklisch rotieren
      // [B3, B2, B1, B0] → [B2, B1, B0, B3]

      Temp := SubWord(RotWord(Temp));
       // Schritt 2: SubWord - S-Box auf jedes Byte anwenden
      // Bringt Nichtlinearität in den Key Schedule
      // (SubWord ist bereits in der Zeile oben integriert)

      // Schritt 3: XOR mit Rundenkonstante (Rcon)
      // I div 8 ergibt 1, 2, 3, 4, 5, 6, 7 für I = 8, 16, 24, ...
      // RconWord(1), RconWord(2), ... bringen Asymmetrie
      Temp := Temp xor RconWord(I div 8);

      // Die Kombination RotWord + SubWord + Rcon bringt:
      // - Diffusion (RotWord)
      // - Nichtlinearität (SubWord)
      // - Asymmetrie (Rcon)

    end
     // -----------------------------------------------------------------------
    // FALL 2: (I mod 8) = 4 → Nur bei AES-256!
    // -----------------------------------------------------------------------
    // Dies ist eine Besonderheit von AES-256
    // Tritt auf bei I = 12, 20, 28, 36, 44, 52
    else if (I mod 8) = 4 then
    begin
      // Nur SubWord anwenden, KEIN RotWord, KEIN Rcon
      // Dies bringt zusätzliche Nichtlinearität für AES-256
      Temp := SubWord(Temp);
        // Warum nur bei AES-256?
      // - AES-256 hat längeren Schlüssel (32 Bytes)
      // - Ohne dieses zusätzliche SubWord: Schwächere Diffusion
      // - Mit SubWord: Stärkere Rundenschlüssel, bessere Sicherheit

    end;
     // -----------------------------------------------------------------------
    // FALL 3: Alle anderen Positionen
    // -----------------------------------------------------------------------
    // Keine Transformation von Temp nötig
    // Temp bleibt W[I-1]

    // -----------------------------------------------------------------------
    // Finales W[I] berechnen (für alle drei Fälle)
    // -----------------------------------------------------------------------
    // W[I] = W[I-8] XOR Temp
    // Dies verknüpft das neue Wort mit einem Wort von vor 8 Positionen
    // und sorgt für Rückkopplung im Key Schedule

    W[I] := W[I - 8] xor Temp;
     // Nach dieser Operation:
    // - W[I] ist berechnet und hängt von W[I-8] und W[I-1] ab
    // - Je nach Fall wurden unterschiedliche Transformationen angewendet
    // - Vollständige Diffusion über alle 60 Wörter nach dieser Schleife
  end;

  // Nach dieser Schleife: W[0..59] enthält alle 60 Wörter
  // Diese repräsentieren 240 Bytes = 15 Rundenschlüssel

  // -------------------------------------------------------------------------
  // SCHRITT 3: Konvertierung - Wörter zu Rundenschlüsseln
  // -------------------------------------------------------------------------
  // Die 60 Wörter werden in 15 Rundenschlüssel (je 4×4 Matrix) umgewandelt
  // Jeder Rundenschlüssel besteht aus 4 Wörtern (= 16 Bytes = 4×4 Matrix)

  WordIndex := 0;               // Startindex im W-Array

  for Round := 0 to 14 do          // Schleife über alle 15 Runden (0..14)
  begin
    for Col := 0 to 3 do         // Jeder Rundenschlüssel hat 4 Spalten
    begin
      Temp := W[WordIndex];      // Aktuelles Wort aus W-Array holen
      Inc(WordIndex);            // Index für nächstes Wort erhöhen

      // Ein 32-Bit-Wort wird in eine Spalte der Rundenschlüssel-Matrix konvertiert
      // Das Wort Temp = [B3, B2, B1, B0] wird aufgeteilt in 4 Bytes:


      LocalCtx.RoundKeys[Round][0, Col] := (Temp shr 24) and $FF;     // Zeile 0: Oberstes Byte (Bits 24-31)
      LocalCtx.RoundKeys[Round][1, Col] := (Temp shr 16) and $FF;      // Zeile 1: Zweites Byte (Bits 16-23)
      LocalCtx.RoundKeys[Round][2, Col] := (Temp shr 8) and $FF;      // Zeile 2: Drittes Byte (Bits 8-15)
      LocalCtx.RoundKeys[Round][3, Col] := Temp and $FF;              // Zeile 3: Unterstes Byte (Bits 0-7)

      // Nach dieser Spalte: Eine Spalte des aktuellen Rundenschlüssels ist gefüllt
    end;
        // Nach dieser inneren Schleife: Ein kompletter Rundenschlüssel ist gefüllt
  end;
  // Nach beiden Schleifen: Alle 15 Rundenschlüssel sind in LocalCtx gespeichert

  // -------------------------------------------------------------------------
  // SCHRITT 4: Ergebnis übergeben
  // -------------------------------------------------------------------------
  // Erst jetzt wird der lokale Kontext in den OUT-Parameter kopiert
  // Falls vorher ein Fehler auftrat (Exception), bleibt Context unverändert

  Context := LocalCtx;
   // Nach dieser Zuweisung:
  // - Context enthält alle 15 Rundenschlüssel
  // - Context.RoundKeys[0..14] können für Ver- und Entschlüsselung verwendet werden
  // - Der Key Schedule ist abgeschlossen

  // WICHTIG für die Sicherheit:
  // Nach Verwendung sollten die Schlüsseldaten gelöscht werden:
  // FillChar(W, SizeOf(W), 0);  // W-Array überschreiben
  // FillChar(LocalCtx, SizeOf(LocalCtx), 0);  // LocalCtx überschreiben
  // (In dieser Funktion geschieht das automatisch beim Verlassen des Scope)
end;

{$pop}    // Compiler-Hints wieder aktivieren

procedure AES256EncryptBlock(const InBlock: TByteArray16; out OutBlock: TByteArray16;
  const Context: TAES256Context);
var
  State: TAESState;
  Round: Integer;
begin
  BlockToState(InBlock, State);
  AddRoundKey(State, Context.RoundKeys[0]);

  for Round := 1 to 13 do
  begin
    SubBytesState(State);
    ShiftRowsState(State);
    MixColumnsState(State);
    AddRoundKey(State, Context.RoundKeys[Round]);
  end;

  SubBytesState(State);
  ShiftRowsState(State);
  AddRoundKey(State, Context.RoundKeys[14]);

  StateToBlock(State, OutBlock);
end;


procedure AES256DecryptBlock(const InBlock: TByteArray16; out OutBlock: TByteArray16;
  const Context: TAES256Context);
var
  State: TAESState;
  Round: Integer;
begin
  BlockToState(InBlock, State);
  AddRoundKey(State, Context.RoundKeys[14]);

  for Round := 13 downto 1 do
  begin
    InvShiftRowsState(State);
    InvSubBytesState(State);
    AddRoundKey(State, Context.RoundKeys[Round]);
    InvMixColumnsState(State);
  end;

  InvShiftRowsState(State);
  InvSubBytesState(State);
  AddRoundKey(State, Context.RoundKeys[0]);

  StateToBlock(State, OutBlock);
end;

function AES256EncryptECB_TEST(const PlainData: TBytes; const Context: TAES256Context): TBytes;
var
  DataLen: Integer;
  NumBlocks: Integer;
  BlockIndex: Integer;
  Offset: Integer;
  InBlock, OutBlock: TByteArray16;
  I: Integer;
begin
  Result := nil;

  DataLen := Length(PlainData);
  if DataLen = 0 then
    Exit;

  if (DataLen mod 16) <> 0 then
    raise Exception.Create('AES256EncryptECB: Datenlänge muss ein Vielfaches von 16 sein (zuerst PKCS7Pad anwenden).');

  NumBlocks := DataLen div 16;
  SetLength(Result, DataLen);

  Offset := 0;

  for BlockIndex := 0 to NumBlocks - 1 do
  begin
    for I := 0 to 15 do
      InBlock[I] := PlainData[Offset + I];

    AES256EncryptBlock(InBlock, OutBlock, Context);

    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    Inc(Offset, 16);
  end;
end;

function AES256DecryptECB_TEST(const CipherData: TBytes; const Context: TAES256Context): TBytes;
var
  DataLen: Integer;
  NumBlocks: Integer;
  BlockIndex: Integer;
  Offset: Integer;
  InBlock, OutBlock: TByteArray16;
  I: Integer;
begin
  Result := nil;

  DataLen := Length(CipherData);
  if DataLen = 0 then
    Exit;

  if (DataLen mod 16) <> 0 then
    raise Exception.Create('AES256DecryptECB: Datenlänge muss ein Vielfaches von 16 sein.');

  NumBlocks := DataLen div 16;
  SetLength(Result, DataLen);

  Offset := 0;

  for BlockIndex := 0 to NumBlocks - 1 do
  begin
    for I := 0 to 15 do
      InBlock[I] := CipherData[Offset + I];

    AES256DecryptBlock(InBlock, OutBlock, Context);

    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    Inc(Offset, 16);
  end;
end;

procedure XorBlockInPlace(var Block: TByteArray16; const Mask: TByteArray16);
var
  I: Integer;
begin
  for I := 0 to 15 do
    Block[I] := Block[I] xor Mask[I];
end;

function AES256EncryptCBC_TEST(const PlainData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
var
  DataLen: Integer;
  NumBlocks: Integer;
  BlockIndex: Integer;
  Offset: Integer;
  InBlock, OutBlock, PrevBlock: TByteArray16;
  I: Integer;
begin
  Result := nil;

  DataLen := Length(PlainData);
  if DataLen = 0 then
    Exit;

  if (DataLen mod 16) <> 0 then
    raise Exception.Create('AES256EncryptCBC: Datenlänge muss ein Vielfaches von 16 sein (zuerst PKCS7Pad anwenden).');

  NumBlocks := DataLen div 16;
  SetLength(Result, DataLen);

  PrevBlock := IV;
  Offset := 0;

  for BlockIndex := 0 to NumBlocks - 1 do
  begin
    for I := 0 to 15 do
      InBlock[I] := PlainData[Offset + I];

    XorBlockInPlace(InBlock, PrevBlock);
    AES256EncryptBlock(InBlock, OutBlock, Context);

    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    PrevBlock := OutBlock;
    Inc(Offset, 16);
  end;
end;

function AES256DecryptCBC_TEST(const CipherData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
var
  DataLen: Integer;
  NumBlocks: Integer;
  BlockIndex: Integer;
  Offset: Integer;
  InBlock, OutBlock, PrevBlock: TByteArray16;
  I: Integer;
begin
  Result := nil;

  DataLen := Length(CipherData);
  if DataLen = 0 then
    Exit;

  if (DataLen mod 16) <> 0 then
    raise Exception.Create('AES256DecryptCBC: Datenlänge muss ein Vielfaches von 16 sein.');

  NumBlocks := DataLen div 16;
  SetLength(Result, DataLen);

  PrevBlock := IV;
  Offset := 0;

  for BlockIndex := 0 to NumBlocks - 1 do
  begin
    for I := 0 to 15 do
      InBlock[I] := CipherData[Offset + I];

    AES256DecryptBlock(InBlock, OutBlock, Context);
    XorBlockInPlace(OutBlock, PrevBlock);

    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    PrevBlock := InBlock;
    Inc(Offset, 16);
  end;
end;

initialization
  InitAESInverseTables;

end.

