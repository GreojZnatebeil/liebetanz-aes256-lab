unit uSHA256;

{$mode objfpc}{$H+}

interface
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
  SysUtils;  // Für Byte-Operationen und allgemeine Utilities

type
  TSHA256State = array[0..7] of LongWord;   // 8 interne 32-Bit-Werte
  TSHA256Buffer = array[0..63] of Byte;     // 512-Bit Block

function SHA256(const Data: TBytes): TBytes;
// Berechnet SHA-256 über die Byte-Daten und liefert 32 Bytes zurück.

implementation

// --- Hilfsfunktionen für 32-Bit Operationen ---

function ROTR(x: LongWord; n: LongWord): LongWord;
{
  ============================================================================
  ROTR - Rotate Right (32-Bit Rechts-Rotation)
  ============================================================================

  ZWECK:
  Rotiert ein 32-Bit-Wort um n Positionen nach rechts (zyklisch).
  Fundamentale Operation für SHA-256.

  BEISPIEL:
  ROTR(10110011, 2) = 11101100
  Die letzten 2 Bits wandern nach vorne.

  ============================================================================
}
begin
  // Rechtsrotation: dreht die Bits nach rechts
  Result := (x shr n) or (x shl (32 - n));
end;

function SHR32(x: LongWord; n: LongWord): LongWord;
{
  ============================================================================
  SHR32 - Logisches Rechts-Schieben (Shift Right)
  ============================================================================

  ZWECK:
  Schiebt Bits nach rechts, füllt links mit Nullen auf.
  Im Gegensatz zu ROTR gehen Bits verloren.

  ============================================================================
}
begin
  // Logisches Rechts-Schieben
  Result := x shr n;
end;

// --- SHA-256 Konstanten (aus FIPS-180-4) ---
const
  K: array[0..63] of LongWord = (
    $428A2F98,$71374491,$B5C0FBCF,$E9B5DBA5,$3956C25B,$59F111F1,$923F82A4,$AB1C5ED5,
    $D807AA98,$12835B01,$243185BE,$550C7DC3,$72BE5D74,$80DEB1FE,$9BDC06A7,$C19BF174,
    $E49B69C1,$EFBE4786,$0FC19DC6,$240CA1CC,$2DE92C6F,$4A7484AA,$5CB0A9DC,$76F988DA,
    $983E5152,$A831C66D,$B00327C8,$BF597FC7,$C6E00BF3,$D5A79147,$06CA6351,$14292967,
    $27B70A85,$2E1B2138,$4D2C6DFC,$53380D13,$650A7354,$766A0ABB,$81C2C92E,$92722C85,
    $A2BFE8A1,$A81A664B,$C24B8B70,$C76C51A3,$D192E819,$D6990624,$F40E3585,$106AA070,
    $19A4C116,$1E376C08,$2748774C,$34B0BCB5,$391C0CB3,$4ED8AA4A,$5B9CCA4F,$682E6FF3,
    $748F82EE,$78A5636F,$84C87814,$8CC70208,$90BEFFFA,$A4506CEB,$BEF9A3F7,$C67178F2
  );

// --- Startwerte (H0..H7) ---
const
  H0: array[0..7] of LongWord = (
    $6A09E667, $BB67AE85, $3C6EF372, $A54FF53A,
    $510E527F, $9B05688C, $1F83D9AB, $5BE0CD19
  );

// --- Verarbeitet einen 512-Bit Block ---
procedure SHA256Transform(var State: TSHA256State; const Block: TSHA256Buffer);
{
  ============================================================================
  SHA256Transform - Verarbeitet einen 512-Bit-Block
  ============================================================================

  ZWECK:
  Kern-Funktion von SHA-256. Verarbeitet einen 512-Bit (64-Byte) Block
  und aktualisiert den internen Zustand (8× 32-Bit Wörter).

  HINTERGRUND:
  SHA-256 wurde von der NSA entwickelt und 2001 von NIST standardisiert.
  Es ist Teil der SHA-2 Familie und gilt als sicher.

  DER ALGORITHMUS (vereinfacht):
  1. Erweitere 16 Wörter auf 64 Wörter (Message Schedule)
  2. 64 Runden mit Bit-Operationen und Addition
  3. Ergebnis zum State addieren

  ============================================================================
}
var
  W: array[0..63] of LongWord;      // Message Schedule (erweiterte Nachricht)
  a,b,c,d,e,f,g,h: LongWord;        // Arbeitsvariablen
  t1, t2: LongWord;                  // Temporäre Werte
  i: Integer;
begin
  // 1. Erste 16 Wörter direkt aus Block einlesen (Big-Endian)
  for i := 0 to 15 do
    W[i] :=
      (LongWord(Block[4*i]) shl 24) or
      (LongWord(Block[4*i+1]) shl 16) or
      (LongWord(Block[4*i+2]) shl 8) or
      (LongWord(Block[4*i+3]));

   // 2. Restliche Wörter berechnen (Message Schedule)
  for i := 16 to 63 do
  begin
    W[i] :=
      (ROTR(W[i-15], 7) xor ROTR(W[i-15], 18) xor SHR32(W[i-15], 3)) +
      W[i-7] +
      (ROTR(W[i-2],17) xor ROTR(W[i-2],19) xor SHR32(W[i-2],10)) +
      W[i-16];
  end;

  // 3. Arbeitsvariablen initialisieren
  a := State[0];
  b := State[1];
  c := State[2];
  d := State[3];
  e := State[4];
  f := State[5];
  g := State[6];
  h := State[7];

  // 4. 64 Runden
  for i := 0 to 63 do
  begin
    t1 := h + (ROTR(e,6) xor ROTR(e,11) xor ROTR(e,25))
            + ((e and f) xor ((not e) and g))
            + K[i] + W[i];

    t2 := (ROTR(a,2) xor ROTR(a,13) xor ROTR(a,22))
            + ((a and b) xor (a and c) xor (b and c));

    h := g;
    g := f;
    f := e;
    e := d + t1;
    d := c;
    c := b;
    b := a;
    a := t1 + t2;
  end;

  // 5. Ergebnis zum State addieren (Diffusion)
  State[0] += a;
  State[1] += b;
  State[2] += c;
  State[3] += d;
  State[4] += e;
  State[5] += f;
  State[6] += g;
  State[7] += h;
end;

// --- Hauptfunktion ---
function SHA256(const Data: TBytes): TBytes;
{
  ============================================================================
  SHA256 - Berechnet SHA-256 Hash über beliebige Daten
  ============================================================================

  ZWECK:
  Berechnet den SHA-256 Hash (256 Bit = 32 Bytes) über beliebige Eingabedaten.
  SHA-256 ist eine kryptographische Hash-Funktion.

  EIGENSCHAFTEN:
  - Einweg-Funktion: Aus Hash kann man nicht auf Input schließen
  - Kollisions-resistent: Praktisch unmöglich, zwei Inputs mit gleichem Hash zu finden
  - Lawineneffekt: 1 Bit Änderung → ~50% Hash-Bits ändern sich

  VERWENDUNG IN DIESEM PROJEKT:
  Passwort → SHA-256 → 32-Byte AES-Schlüssel

  SICHERHEIT:
  SHA-256 gilt als sicher (Stand 2025). Keine praktischen Angriffe bekannt.
  Für Passwort-Hashing: Besser PBKDF2, Argon2 oder bcrypt verwenden!

  ============================================================================
}
var
  State: TSHA256State;                  // Interner Zustand mit 8 32-Bit-Werten
  Len: Int64;                           // Gesamtlänge der Daten in Bit
  Buffer: TSHA256Buffer;                // 512-Bit-Puffer (64 Bytes) für Blockverarbeitung
  i: Integer;                           // Laufvariable für Schleifen
begin
  Result := nil;                        // Initialisiert das Ergebnis explizit (beruhigt den Compiler)
  Result := nil;                        // Initialisiert das Ergebnis explizit (beruhigt den Compiler)

  // Explizite Initialisierung des Puffers, damit der Compiler sicher ist,
  // dass alle Elemente von Buffer einen definierten Wert haben.
  for i := 0 to High(Buffer) do         // Schleife über alle Bytes im Buffer (0..63)
    Buffer[i] := 0;                     // Setzt jedes Byte des Puffers auf 0

  // 1. Startwerte setzen (Initial Hash Values H0..H7)
  for i := 0 to 7 do                    // Schleife über die 8 State-Werte
    State[i] := H0[i];                  // Übernimmt die vordefinierten Initialwerte in den State

{
  // 1. Startwerte setzen (Initial Hash Values H0..H7)
  for i := 0 to 7 do                    // Schleife über die 8 State-Werte
    State[i] := H0[i];                  // Übernimmt die vordefinierten Initialwerte in den State
}
  // 2. Daten blockweise verarbeiten (512-Bit Blöcke)

  i := 0;                               // Startindex im Eingabearray
  while (i + 64) <= Length(Data) do     // Solange noch mindestens 64 Bytes (ein voller Block) übrig sind
  begin
    Move(Data[i], Buffer[0], 64);       // Kopiert 64 Bytes aus den Eingabedaten in den Blockpuffer
    SHA256Transform(State, Buffer);     // Verarbeitet diesen Block und aktualisiert den State
    Inc(i, 64);                         // Erhöht den Index um 64, um den nächsten Block zu verarbeiten
  end;

  // 3. Padding vorbereiten (FIPS 180-4)

  Len := Length(Data) * 8;              // Gesamtlänge der Originaldaten in Bit

  FillChar(Buffer, SizeOf(Buffer), 0);  // Setzt den Puffer auf 0, bevor der letzte Block vorbereitet wird
  Move(Data[i], Buffer[0], Length(Data)-i);
  // Kopiert die restlichen (weniger als 64) Bytes in den Anfang des Puffers

  Buffer[Length(Data)-i] := $80;        // Fügt das Padding-Startbyte 0x80 an (Bit '1' gefolgt von Nullen)

  // Falls im aktuellen Block kein Platz mehr für die Längenangabe ist:
  if (Length(Data)-i >= 56) then        // 56 = 64 - 8, Platz für die 64-Bit-Länge
  begin
    SHA256Transform(State, Buffer);     // Verarbeitet den (fast) vollen Block
    FillChar(Buffer, SizeOf(Buffer),0); // Setzt den Puffer erneut auf 0 für den letzten Block
  end;

   // 4. Länge in letzte 8 Bytes schreiben (Big-Endian)

  Buffer[63] := Len and $FF;            // Niedrigstwertiges Byte der Länge
  Buffer[62] := (Len shr 8) and $FF;    // Nächstes Byte
  Buffer[61] := (Len shr 16) and $FF;   // ...
  Buffer[60] := (Len shr 24) and $FF;
  Buffer[59] := (Len shr 32) and $FF;
  Buffer[58] := (Len shr 40) and $FF;
  Buffer[57] := (Len shr 48) and $FF;
  Buffer[56] := (Len shr 56) and $FF;   // Höchstwertiges Byte der Länge

  SHA256Transform(State, Buffer);       // Verarbeitet den letzten Block mit der Längenangabe

   // 5. Ausgabe erzeugen (32 Bytes)

  SetLength(Result, 32);                // Reserviert 32 Bytes für den Hash-Wert (256 Bit)
  for i := 0 to 7 do                    // Schleife über die 8 32-Bit-Wörter im State
  begin
    Result[i*4]   := (State[i] shr 24) and $FF; // Oberes Byte nach Result kopieren
    Result[i*4+1] := (State[i] shr 16) and $FF; // Nächstes Byte
    Result[i*4+2] := (State[i] shr 8) and $FF;  // Nächstes Byte
    Result[i*4+3] := State[i] and $FF;          // Niedrigstwertiges Byte
  end;
end;

end.

