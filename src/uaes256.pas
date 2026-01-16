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
var
  Row, Col: Integer;
begin
  for Row := 0 to 3 do
    for Col := 0 to 3 do
      State[Row, Col] := SubByte(State[Row, Col]);
end;

procedure InvSubBytesState(var State: TAESState);
var
  Row, Col: Integer;
begin
  for Row := 0 to 3 do
    for Col := 0 to 3 do
      State[Row, Col] := InvSubByte(State[Row, Col]);
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
var
  Row, Col: Integer;
  Index: Integer;
begin
  Index := 0;

  for Col := 0 to 3 do
    for Row := 0 to 3 do
    begin
      State[Row, Col] := Block[Index];
      Inc(Index);
    end;
end;

procedure StateToBlock(const State: TAESState; out Block: TByteArray16);
var
  Row, Col: Integer;
  Index: Integer;
begin
  Index := 0;

  for Col := 0 to 3 do
    for Row := 0 to 3 do
    begin
      Block[Index] := State[Row, Col];
      Inc(Index);
    end;
end;

procedure ShiftRowsState(var State: TAESState);
var
  Temp: Byte;
begin
  // Zeile 0 bleibt

  // Zeile 1
  Temp := State[1,0];
  State[1,0] := State[1,1];
  State[1,1] := State[1,2];
  State[1,2] := State[1,3];
  State[1,3] := Temp;

  // Zeile 2
  Temp := State[2,0];
  State[2,0] := State[2,2];
  State[2,2] := Temp;

  Temp := State[2,1];
  State[2,1] := State[2,3];
  State[2,3] := Temp;

  // Zeile 3
  Temp := State[3,3];
  State[3,3] := State[3,2];
  State[3,2] := State[3,1];
  State[3,1] := State[3,0];
  State[3,0] := Temp;
end;

procedure InvShiftRowsState(var State: TAESState);
var
  Temp: Byte;
begin
  // Zeile 0 bleibt

  // Zeile 1: nach rechts
  Temp := State[1,3];
  State[1,3] := State[1,2];
  State[1,2] := State[1,1];
  State[1,1] := State[1,0];
  State[1,0] := Temp;

  // Zeile 2: 2er swap
  Temp := State[2,0];
  State[2,0] := State[2,2];
  State[2,2] := Temp;

  Temp := State[2,1];
  State[2,1] := State[2,3];
  State[2,3] := Temp;

  // Zeile 3: nach links 1
  Temp := State[3,0];
  State[3,0] := State[3,1];
  State[3,1] := State[3,2];
  State[3,2] := State[3,3];
  State[3,3] := Temp;
end;

procedure AddRoundKey(var State: TAESState; const RoundKey: TAESRoundKey);
var
  Row, Col: Integer;
begin
  for Row := 0 to 3 do
    for Col := 0 to 3 do
      State[Row, Col] := State[Row, Col] xor RoundKey[Row, Col];
end;

function GFMul2(B: Byte): Byte;
begin
  if (B and $80) <> 0 then
    Result := ((B shl 1) xor $1B) and $FF
  else
    Result := (B shl 1) and $FF;
end;

function GFMul3(B: Byte): Byte;
begin
  Result := GFMul2(B) xor B;
end;

function GFMul4(B: Byte): Byte;
begin
  Result := GFMul2(GFMul2(B));
end;

function GFMul8(B: Byte): Byte;
begin
  Result := GFMul2(GFMul4(B));
end;

function GFMul9(B: Byte): Byte;
begin
  Result := GFMul8(B) xor B;
end;

function GFMul11(B: Byte): Byte;
begin
  Result := GFMul8(B) xor GFMul2(B) xor B;
end;

function GFMul13(B: Byte): Byte;
begin
  Result := GFMul8(B) xor GFMul4(B) xor B;
end;

function GFMul14(B: Byte): Byte;
begin
  Result := GFMul8(B) xor GFMul4(B) xor GFMul2(B);
end;

procedure MixSingleColumn(var S0, S1, S2, S3: Byte);
var
  T0, T1, T2, T3: Byte;
begin
  T0 := GFMul2(S0) xor GFMul3(S1) xor S2 xor S3;
  T1 := S0 xor GFMul2(S1) xor GFMul3(S2) xor S3;
  T2 := S0 xor S1 xor GFMul2(S2) xor GFMul3(S3);
  T3 := GFMul3(S0) xor S1 xor S2 xor GFMul2(S3);

  S0 := T0; S1 := T1; S2 := T2; S3 := T3;
end;

procedure InvMixSingleColumn(var S0, S1, S2, S3: Byte);
var
  T0, T1, T2, T3: Byte;
begin
  T0 := GFMul14(S0) xor GFMul11(S1) xor GFMul13(S2) xor GFMul9(S3);
  T1 := GFMul9(S0)  xor GFMul14(S1) xor GFMul11(S2) xor GFMul13(S3);
  T2 := GFMul13(S0) xor GFMul9(S1)  xor GFMul14(S2) xor GFMul11(S3);
  T3 := GFMul11(S0) xor GFMul13(S1) xor GFMul9(S2)  xor GFMul14(S3);

  S0 := T0; S1 := T1; S2 := T2; S3 := T3;
end;

procedure MixColumnsState(var State: TAESState);
var
  Col: Integer;
  S0, S1, S2, S3: Byte;
begin
  for Col := 0 to 3 do
  begin
    S0 := State[0, Col];
    S1 := State[1, Col];
    S2 := State[2, Col];
    S3 := State[3, Col];

    MixSingleColumn(S0, S1, S2, S3);

    State[0, Col] := S0;
    State[1, Col] := S1;
    State[2, Col] := S2;
    State[3, Col] := S3;
  end;
end;

procedure InvMixColumnsState(var State: TAESState);
var
  Col: Integer;
  S0, S1, S2, S3: Byte;
begin
  for Col := 0 to 3 do
  begin
    S0 := State[0, Col];
    S1 := State[1, Col];
    S2 := State[2, Col];
    S3 := State[3, Col];

    InvMixSingleColumn(S0, S1, S2, S3);

    State[0, Col] := S0;
    State[1, Col] := S1;
    State[2, Col] := S2;
    State[3, Col] := S3;
  end;
end;

{ Hilfsfunktionen für die Key-Expansion }

function RotWord(W: LongWord): LongWord;
begin
  Result := (W shl 8) or (W shr 24);
end;

function SubWord(W: LongWord): LongWord;
var
  b0, b1, b2, b3: Byte;
begin
  b0 := (W shr 24) and $FF;
  b1 := (W shr 16) and $FF;
  b2 := (W shr 8) and $FF;
  b3 := W and $FF;

  b0 := SubByte(b0);
  b1 := SubByte(b1);
  b2 := SubByte(b2);
  b3 := SubByte(b3);

  Result :=
    (LongWord(b0) shl 24) or
    (LongWord(b1) shl 16) or
    (LongWord(b2) shl 8) or
    LongWord(b3);
end;

function RconWord(I: Integer): LongWord;
const
  RconTable: array[1..10] of Byte = ($01, $02, $04, $08, $10, $20, $40, $80, $1B, $36);
begin
  if (I < 1) or (I > 10) then
    Result := 0
  else
    Result := LongWord(RconTable[I]) shl 24;
end;

{$push}
{$HINTS OFF}

procedure AES256InitKey(const Key: TBytes; out Context: TAES256Context);
var
  LocalCtx: TAES256Context;
  W: array[0..59] of LongWord;
  I: Integer;
  Temp: LongWord;
  Round, Col: Integer;
  WordIndex: Integer;
begin
  FillChar(LocalCtx, SizeOf(LocalCtx), 0);

  // AES-256 erwartet exakt 32 Byte Schlüsselmaterial.
  // (Für Lernzwecke ist es besser, hier strikt zu sein, damit keine stillen Kürzungen passieren.)
  if Length(Key) <> 32 then
    raise Exception.Create('AES256InitKey: Key muss genau 32 Bytes (256 Bit) lang sein.');

  for I := 0 to 7 do
  begin
    W[I] :=
      (LongWord(Key[4 * I]) shl 24) or
      (LongWord(Key[4 * I + 1]) shl 16) or
      (LongWord(Key[4 * I + 2]) shl 8) or
      LongWord(Key[4 * I + 3]);
  end;

  for I := 8 to 59 do
  begin
    Temp := W[I - 1];

    if (I mod 8) = 0 then
    begin
      Temp := SubWord(RotWord(Temp));
      Temp := Temp xor RconWord(I div 8);
    end
    else if (I mod 8) = 4 then
    begin
      Temp := SubWord(Temp);
    end;

    W[I] := W[I - 8] xor Temp;
  end;

  WordIndex := 0;

  for Round := 0 to 14 do
  begin
    for Col := 0 to 3 do
    begin
      Temp := W[WordIndex];
      Inc(WordIndex);

      LocalCtx.RoundKeys[Round][0, Col] := (Temp shr 24) and $FF;
      LocalCtx.RoundKeys[Round][1, Col] := (Temp shr 16) and $FF;
      LocalCtx.RoundKeys[Round][2, Col] := (Temp shr 8) and $FF;
      LocalCtx.RoundKeys[Round][3, Col] := Temp and $FF;
    end;
  end;

  Context := LocalCtx;
end;

{$pop}

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

