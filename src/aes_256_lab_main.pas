unit AES_256_Lab_Main;                             // Haupt-Unit mit der Form

{$mode objfpc}{$H+}                     // Lazarus-Standard: Objekt-Pascal, lange Strings

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
*)

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ComCtrls,ExtCtrls,

   // Core (Blockcipher + Tools + SelfTest)

  uAES256,               // Basis: Typen + Hilfsfunktionen (UTF8, Hex, Padding, KeySchedule, Block-Funktionen)
  uSHA256,
  uAES256_Container,     // Container + Random-IV

  // Modes (ECB/CBC) used by the GUI
  uAES256_ECB,           // ECB-spezifisch (Encrypt/Decrypt ECB)
  uAES256_CBC;           // CBC-spezifisch (Encrypt/Decrypt CBC)


type
  { TAES_256_Lab }
  TAES_256_Lab = class(TForm)
    NIST_CBC: TButton;
    CBCModus_Button: TButton;

    // getrennte Entschlüssel-Buttons
    entschluesseln_ECB: TButton;
    entschluesseln_CBC: TButton;
    Laden: TButton;

    // Laden/Speichern Buttons
    LadenButton: TButton;
    NIST_Test: TButton;
    Speichern: TButton;
    SpeichernButton: TButton;

    OpenDialog1: TOpenDialog;
    SaveDialog1: TSaveDialog;

    decrypted_Memo: TMemo;
    MemoCipher: TMemo;
    Memo_control: TPageControl;
    StatusBar1: TStatusBar;
    StatusMemo: TMemo;
    Status: TTabSheet;
    Verschluesselung: TTabSheet;
    Entschluesselung: TTabSheet;

    Verschluesseln_Button: TButton;     // Verschlüsseln (ECB)
    Selftest_Button: TButton;

    Edit2: TEdit;
    Label_Key: TLabel;
    Label_Text: TLabel;
    MemoPlain: TMemo;

    procedure CBCModus_ButtonClick(Sender: TObject);
    procedure Entschluesseln_ButtonClick(Sender: TObject);
    procedure entschluesseln_ECBClick(Sender: TObject);
    procedure entschluesseln_CBCClick(Sender: TObject);
    procedure LadenClick(Sender: TObject);
    procedure NIST_CBCClick(Sender: TObject);
    procedure NIST_TestClick(Sender: TObject);
    procedure SpeichernClick(Sender: TObject);

    procedure Memo_controlChange(Sender: TObject);
    procedure Selftest_ButtonClick(Sender: TObject);
    procedure Verschluesseln_ButtonClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    FCipherBytes: TBytes;               // Cipher (binär)
    FCipherMode: TAESContainerMode;     // acmECB / acmCBC
    FCipherIV: TByteArray16;            // gültig bei CBC, bei ECB = ZERO_IV
  public
  end;

var
  AES_256_Lab: TAES_256_Lab;

const
  ZERO_IV: TByteArray16 = (
    $00,$00,$00,$00,$00,$00,$00,$00,
    $00,$00,$00,$00,$00,$00,$00,$00
  );

  // Fester 16-Byte-IV zum Testen (Lehrmodus) – aktuell NICHT benutzt:
  (*
  TEST_CBC_IV: TByteArray16 = (
    $00,$11,$22,$33,$44,$55,$66,$77,
    $88,$99,$AA,$BB,$CC,$DD,$EE,$FF
  );
  *)

implementation

{$R *.lfm}

{ TAES_256_Lab }

procedure TAES_256_Lab.Verschluesseln_ButtonClick(Sender: TObject);
{
  ============================================================================
  Verschluesseln_ButtonClick - ECB-Verschlüsselung (Button-Event-Handler)
  ============================================================================

  ZWECK:
  Event-Handler für den "Verschlüsseln (ECB)"-Button. Führt eine komplette
  AES-256-ECB-Verschlüsselung durch und zeigt alle Zwischenschritte an.

  DIDAKTISCHER ANSATZ:
  Diese Funktion ist bewusst ausführlich und zeigt jeden Schritt:
  - Klartext einlesen
  - UTF-8 Konvertierung
  - PKCS#7 Padding
  - Lehr-Test: Rundenkern (SubBytes+ShiftRows+MixColumns) auf Block 0
  - Passwort → SHA-256 → AES-Key
  - Key Schedule (Roundkeys generieren)
  - ECB-Verschlüsselung
  - Anzeige in Hex-Format

  FÜR LEHRZWECKE:
  Jeder Schritt wird im StatusMemo dokumentiert, damit Schüler den
  Ablauf nachvollziehen können.

  SICHERHEITSHINWEIS:
  Dies ist LEHRCODE! ECB-Modus ist für Produktivsysteme NICHT geeignet.
  Siehe Kommentare in uAES256_ECB.pas für Details.

  ============================================================================
}
var
  PlainText: string;           // Text, den der Benutzer in MemoPlain eingibt
  PlainBytes: TBytes;           // Klartext als UTF-8-Byte-Array
  PaddedBytes: TBytes;          // Klartext nach PKCS#7-Padding
  HexText: string;              // Hex-Darstellung der gepaddeten Daten

  Block: TByteArray16;         // Erster 16-Byte-Block für Lehr-Test
  State: TAESState;            // AES-State-Matrix (4×4)
  RoundBytes: TBytes;           // Block nach SubBytes+ShiftRows+MixColumns
  HexRound: string;             // Hex-Darstellung des transformierten Blocks

  KeyBytes: TBytes;            // AES-256 Key (32 Bytes)
  Ctx: TAES256Context;         // Roundkeys (15 Rundenschlüssel)
  CipherBytes: TBytes;         // Verschlüsselte Daten (ECB)
  HexCipher: string;            // Hex-Darstellung der verschlüsselten Daten

  I: Integer;                   // Laufvariable für Schleifen

begin
   // -------------------------------------------------------------------------
  // VORBEREITUNG: Alle dynamischen Arrays auf nil setzen
  // -------------------------------------------------------------------------
  // Dies ist defensive Programmierung - verhindert Zugriff auf nicht
  // initialisierte Speicherbereiche

  RoundBytes   := nil;
  KeyBytes     := nil;
  CipherBytes  := nil;
  PaddedBytes  := nil;
  PlainBytes   := nil;

  // -------------------------------------------------------------------------
  // AUSGABE VORBEREITEN: Memos leeren
  // -------------------------------------------------------------------------
  // StatusMemo zeigt den Fortschritt, MemoCipher die Zwischenergebnisse

  StatusMemo.Clear;
  MemoCipher.Clear;
   // Startmeldung für den Benutzer
  StatusMemo.Lines.Add('Warnung: ECB ist unsicher und nur zum Lernen gedacht.');
  StatusMemo.Lines.Add('--- Verschlüsselung (ECB) gestartet ---');
  StatusMemo.Lines.Add('Hinweis: Passwort->Key erfolgt didaktisch via SHA-256 (nicht produktionssicher).');


  // -------------------------------------------------------------------------
  // SCHRITT 1: Klartext aus dem Memo lesen
  // -------------------------------------------------------------------------
  // MemoPlain ist das Eingabefeld, in das der Benutzer den zu
  // verschlüsselnden Text eingibt

  PlainText := MemoPlain.Text;
  if PlainText = '' then    // Validierung: Wenn kein Text eingegeben wurde, Abbruch
  begin
    StatusMemo.Lines.Add('Hinweis: Kein Klartext in MemoPlain vorhanden, Vorgang abgebrochen.');
    Exit;                  // Frühzeitiger Ausstieg aus der Prozedur
  end;

  // -------------------------------------------------------------------------
  // SCHRITT 2: String nach UTF-8-Bytes umwandeln
  // -------------------------------------------------------------------------
  // AES arbeitet mit Bytes, nicht mit Strings. UTF-8 garantiert:
  // - Plattformunabhängigkeit (Windows, Linux, Mac)
  // - Korrekte Behandlung von Umlauten, Sonderzeichen, Emojis
  // - Konsistente Byte-Darstellung des gleichen Textes

  PlainBytes := StringToBytesUTF8(PlainText);
  StatusMemo.Lines.Add('Klartext wurde in UTF-8-Bytes umgewandelt.');

  // -------------------------------------------------------------------------
  // SCHRITT 3: PKCS#7-Padding anwenden
  // -------------------------------------------------------------------------
  // AES arbeitet nur mit 16-Byte-Blöcken. PKCS#7-Padding füllt die Daten
  // auf ein Vielfaches von 16 Bytes auf.
  //
  // Beispiel: "Hallo" (5 Bytes) → 16 Bytes mit 11 Padding-Bytes (Wert 0x0B)
  //
  // WICHTIG: Auch wenn die Daten bereits ein Vielfaches von 16 sind,
  // wird ein kompletter Padding-Block (16 Bytes) hinzugefügt!
  // → Dies ermöglicht eindeutige Entfernung des Paddings

  PaddedBytes := PKCS7Pad(PlainBytes, 16);
  StatusMemo.Lines.Add('PKCS#7-Padding angewendet.');

  // -------------------------------------------------------------------------
  // SCHRITT 4: Gepaddete Daten als Hex-Darstellung anzeigen
  // -------------------------------------------------------------------------
  // Hex-Format ist lesbar für Menschen und zeigt die exakten Bytes
  // Beispiel: [48 65 6C 6C 6F] = "Hello" in ASCII/UTF-8

  HexText := BytesToHex(PaddedBytes);
  MemoCipher.Lines.Add('Gepaddete Daten (Hex):');
  MemoCipher.Lines.Add(HexText);
  MemoCipher.Lines.Add('');        // Leerzeile für bessere Lesbarkeit

  // -------------------------------------------------------------------------
  // SCHRITT 5: Prüfen, ob mindestens ein 16-Byte-Block vorhanden ist
  // -------------------------------------------------------------------------
  // Dies sollte durch PKCS7Pad garantiert sein, aber defensive Programmierung
  // schadet nie. Ohne mindestens 16 Bytes können wir nichts verschlüsseln.

  if Length(PaddedBytes) < 16 then
  begin
    StatusMemo.Lines.Add('Fehler: Zu wenige Daten für einen 16-Byte-Block trotz Padding.');
    Exit;             // Sollte nie passieren, aber Sicherheit geht vor
  end;

  // =========================================================================
  // LEHR-TEST: Rundenkern (SubBytes + ShiftRows + MixColumns) auf Block 0
  // =========================================================================
  // DIDAKTISCHER ZWECK:
  // Zeigt den Schülern, was INNERHALB einer AES-Runde passiert (ohne AddRoundKey).
  // Dies sind die drei Transformationen, die für Diffusion und Konfusion sorgen.

  // -------------------------------------------------------------------------
  // Schritt A: Ersten 16-Byte-Block extrahieren
  // -------------------------------------------------------------------------

  for I := 0 to 15 do
    Block[I] := PaddedBytes[I];
   // Nach dieser Schleife: Block enthält die ersten 16 Bytes der gepaddeten Daten

  // -------------------------------------------------------------------------
  // Schritt B: Block in State-Matrix konvertieren
  // -------------------------------------------------------------------------
  // AES arbeitet intern mit einer 4×4-Matrix (Column-Major Order)
  // Block (linear): [B0, B1, B2, ..., B15]
  // State (Matrix):
  //     [B0, B4, B8,  B12]
  //     [B1, B5, B9,  B13]
  //     [B2, B6, B10, B14]
  //     [B3, B7, B11, B15]

  BlockToState(Block, State);
  // -------------------------------------------------------------------------
  // Schritt C: SubBytes - S-Box Substitution
  // -------------------------------------------------------------------------
  // Jedes Byte der State-Matrix wird durch die S-Box ersetzt
  // Dies ist die EINZIGE nichtlineare Operation in AES
  // Sorgt für Konfusion (komplexe Beziehung zwischen Input und Output)

  SubBytesState(State);
  // -------------------------------------------------------------------------
  // Schritt D: ShiftRows - Zeilen verschieben
  // -------------------------------------------------------------------------
  // Zeile 0: keine Verschiebung
  // Zeile 1: 1 Position nach links
  // Zeile 2: 2 Positionen nach links
  // Zeile 3: 3 Positionen nach links
  // Sorgt für horizontale Diffusion (zwischen den Spalten)

  ShiftRowsState(State);

   // -------------------------------------------------------------------------
  // Schritt E: MixColumns - Spalten mischen
  // -------------------------------------------------------------------------
  // Jede Spalte wird durch Matrix-Multiplikation in GF(2^8) gemischt
  // Jedes Byte einer Spalte beeinflusst alle anderen Bytes der Spalte
  // Sorgt für vertikale Diffusion (innerhalb der Spalten)
  // In Kombination mit ShiftRows: Vollständige 2D-Diffusion!

  MixColumnsState(State);

  // -------------------------------------------------------------------------
  // Schritt F: State zurück in Block konvertieren
  // -------------------------------------------------------------------------
  StateToBlock(State, Block);

  // -------------------------------------------------------------------------
  // Schritt G: Ergebnis als Byte-Array und Hex-String speichern
  // -------------------------------------------------------------------------

  SetLength(RoundBytes, 16);
  Move(Block[0], RoundBytes[0], 16);
  HexRound := BytesToHex(RoundBytes);

  // -------------------------------------------------------------------------
  // Schritt H: Lehr-Ergebnis anzeigen
  // -------------------------------------------------------------------------
  MemoCipher.Lines.Add('Erster Block nach SubBytes + ShiftRows + MixColumns (Hex):');
  MemoCipher.Lines.Add(HexRound);
  MemoCipher.Lines.Add('');

   // =========================================================================
  // ENDE LEHR-TEST
  // =========================================================================

  // -------------------------------------------------------------------------
  // SCHRITT 6: Passwort → SHA-256 → 32-Byte-Key
  // -------------------------------------------------------------------------
  // Das Benutzer-Passwort (aus Edit2) wird zu einem 32-Byte-AES-Schlüssel:
  // 1. Passwort als UTF-8-Bytes konvertieren
  KeyBytes := StringToBytesUTF8(Edit2.Text);

   // 2. SHA-256 Hash berechnen
  // SHA-256 erzeugt immer genau 32 Bytes (256 Bit), perfekt für AES-256
  //
  // WICHTIG FÜR LEHRZWECKE:
  // In der Praxis sollte man PBKDF2, Argon2 oder bcrypt verwenden!
  // SHA-256 alleine ist zu schnell und anfällig für Brute-Force.
  // Aber für Lehrzwecke ist es einfach und verständlich.
  KeyBytes := SHA256(KeyBytes);

   // Hex-Darstellung des Schlüssels anzeigen (zu Lehrzwecken)
  MemoCipher.Lines.Add('SHA-256 Hash des Passworts (AES-256 Key):');
  MemoCipher.Lines.Add(BytesToHex(KeyBytes));
  MemoCipher.Lines.Add('');

  // -------------------------------------------------------------------------
  // SCHRITT 7: AES-256 Kontext initialisieren (Key Schedule)
  // -------------------------------------------------------------------------
  // Der Key Schedule generiert aus dem 32-Byte Hauptschlüssel alle
  // 15 Rundenschlüssel (RoundKey[0..14]), die für AES-256 benötigt werden.
  //
  // Dies ist ein komplexer Prozess mit:
  // - RotWord (Byte-Rotation)
  // - SubWord (S-Box)
  // - Rcon (Rundenkonstanten)
  //
  // Siehe Kommentare in AES256InitKey für Details!
  AES256InitKey(KeyBytes, Ctx);

  // -------------------------------------------------------------------------
  // SCHRITT 8: ECB-Verschlüsselung
  // -------------------------------------------------------------------------
  // Jetzt kommt die eigentliche Verschlüsselung!
  //
  // ECB (Electronic Codebook) Modus:
  // - Jeder 16-Byte-Block wird UNABHÄNGIG verschlüsselt
  // - Gleicher Plaintext-Block → Gleicher Ciphertext-Block
  // - UNSICHER für Produktivsysteme (zeigt Muster)
  // - Aber einfach zu verstehen für Lehrzwecke
  //
  // AES256EncryptECB macht:
  // - Schleife über alle Blöcke
  // - Jeden Block mit AES256EncryptBlock verschlüsseln
  // - Ergebnisse zusammenfügen
  CipherBytes := AES256EncryptECB(PaddedBytes, Ctx);
  StatusMemo.Lines.Add('Daten wurden im AES-256-ECB-Modus verschlüsselt.');

   // -------------------------------------------------------------------------
  // SCHRITT 9: Verschlüsselte Daten als Hex anzeigen
  // -------------------------------------------------------------------------
  HexCipher := BytesToHex(CipherBytes);
  MemoCipher.Lines.Add('AES-256 ECB verschlüsselte Daten (Hex):');
  MemoCipher.Lines.Add(HexCipher);

  // -------------------------------------------------------------------------
  // SCHRITT 10: WICHTIG - CipherBytes in FCipherBytes übernehmen
  // -------------------------------------------------------------------------
  // FCipherBytes ist eine Instanzvariable der Form (private-Sektion)
  // Sie speichert die verschlüsselten Daten für:
  // - Entschlüsseln-Button (braucht die Daten)
  // - Speichern-Button (braucht die Daten)
  //
  // WICHTIG: Copy() macht eine echte Kopie, nicht nur eine Referenz!
  FCipherBytes := Copy(CipherBytes);
   // Zusätzlich merken wir uns den Modus und IV für späteres Speichern
  FCipherMode  := acmECB;       // ECB-Modus
  FCipherIV    := ZERO_IV;

  StatusMemo.Lines.Add('Cipher-Text wurde in FCipherBytes übernommen (MemoCipher ist nur Anzeige).');
  StatusMemo.Lines.Add('--- Verschlüsselung (ECB) erfolgreich abgeschlossen ---');
end;

procedure TAES_256_Lab.CBCModus_ButtonClick(Sender: TObject);
{
  ============================================================================
  CBCModus_ButtonClick - CBC-Verschlüsselung (Button-Event-Handler)
  ============================================================================

  ZWECK:
  Event-Handler für den "Verschlüsseln (CBC)"-Button. Führt eine komplette
  AES-256-CBC-Verschlüsselung durch - der SICHERE Modus im Gegensatz zu ECB.

  UNTERSCHIED ZU ECB:
  CBC (Cipher Block Chaining) verkettet die Blöcke:
  - Jeder Block wird mit dem vorherigen Ciphertext-Block XOR-verknüpft
  - Erster Block wird mit IV (Initialization Vector) XOR-verknüpft
  - Gleiche Plaintext-Blöcke → UNTERSCHIEDLICHE Ciphertext-Blöcke
  - Keine Mustererkennung möglich

  DER IV (INITIALIZATION VECTOR):
  - MUSS für jede Nachricht NEU und ZUFÄLLIG sein
  - DARF mit gleichem Key NIEMALS wiederverwendet werden
  - In diesem Lehrcode: Fester TEST_CBC_IV (NUR zu Demonstrationszwecken!)
  - In Produktivsystemen: Kryptographisch sicherer Zufalls-IV

  SICHERHEITSHINWEIS FÜR LEHRZWECKE:
  Der feste IV ist ABSICHTLICH unsicher, um den Code einfach zu halten.
  In echten Anwendungen MUSS der IV zufällig generiert werden:
```pascal
  // Produktiv-Code (NICHT in diesem Lehrprojekt):
  Randomize;
  for I := 0 to 15 do
    IV[I] := Random(256);  // Oder besser: Kryptographisch sicherer RNG
```

  ============================================================================
}
var
  PlainText: string;                     // Klartext aus MemoPlain
  PlainBytes: TBytes;                     // Klartext als UTF-8-Bytes
  PaddedBytes: TBytes;                    // Gepaddeter Klartext (Vielfaches von 16 Bytes)
  HexText: string;                       // Hex-Darstellung der gepaddeten Daten

  KeyBytes: TBytes;                        // Passwort → SHA-256 → 32-Byte AES-Key
  Ctx: TAES256Context;                      // AES-256 Kontext (15 Rundenschlüssel)
  CipherBytes: TBytes;                    // Verschlüsselte Daten (CBC-Modus)
  HexCipher: string;                      // Hex-Darstellung des Ciphertexts

  IVBytes: TBytes;                       // Nur für Hex-Anzeige des IV (temporär)
  LocalIV: TByteArray16;

  I: Integer;                            // Laufvariable für Schleifen
begin

    // -------------------------------------------------------------------------
  // VORBEREITUNG: Alle dynamischen Arrays auf nil setzen
  // -------------------------------------------------------------------------
  // Defensive Programmierung - verhindert Zugriff auf uninitialisierte Daten
  PlainBytes   := nil;
  PaddedBytes  := nil;
  KeyBytes     := nil;
  CipherBytes  := nil;
  IVBytes      := nil;
  LocalIV[0] := 0;

  // -------------------------------------------------------------------------
  // AUSGABE VORBEREITEN: Memos leeren
  // -------------------------------------------------------------------------
  StatusMemo.Clear;
  MemoCipher.Clear;

    // Startmeldung - zeigt, dass CBC-Modus verwendet wird
  StatusMemo.Lines.Add('--- CBC-Verschlüsselung gestartet ---');
   StatusMemo.Lines.Add('Hinweis: IV ist bei CBC zwingend und wird im Container gespeichert.');
   StatusMemo.Lines.Add('Hinweis: Passwort->Key erfolgt didaktisch via SHA-256 (nicht produktionssicher).');


  // -------------------------------------------------------------------------
  // SCHRITT 1: Klartext aus dem Memo lesen
  // -------------------------------------------------------------------------
  PlainText := MemoPlain.Text;
  if PlainText = '' then    // Validierung: Wenn kein Text eingegeben wurde, Abbruch
  begin
    StatusMemo.Lines.Add('Hinweis: Kein Klartext in MemoPlain vorhanden, Vorgang abgebrochen.');
    Exit;                 // Frühzeitiger Ausstieg
  end;

 // -------------------------------------------------------------------------
  // SCHRITT 2: String → UTF-8-Bytes
  // -------------------------------------------------------------------------
  // Konvertierung zu UTF-8 garantiert:
  // - Plattformunabhängigkeit
  // - Korrekte Behandlung von internationalen Zeichen
  // - Konsistente Byte-Darstellung

  PlainBytes := StringToBytesUTF8(PlainText);
  StatusMemo.Lines.Add('Klartext wurde in UTF-8-Bytes umgewandelt.');

   // -------------------------------------------------------------------------
  // SCHRITT 3: PKCS#7 Padding anwenden
  // -------------------------------------------------------------------------
  // PKCS#7-Padding ist NOTWENDIG, weil:
  // - AES nur mit 16-Byte-Blöcken arbeitet
  // - Nachricht selten exakt ein Vielfaches von 16 Bytes ist
  // - Padding eindeutig entfernbar sein muss
  //
  // Beispiel: "Test" (4 Bytes) → [54 65 73 74 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C 0C]
  //           12 Padding-Bytes mit Wert 0x0C (= 12 in dezimal)
  PaddedBytes := PKCS7Pad(PlainBytes, 16);
  StatusMemo.Lines.Add('PKCS#7-Padding angewendet.');

   // -------------------------------------------------------------------------
  // SCHRITT 4: Gepaddete Daten als Hex anzeigen
  // -------------------------------------------------------------------------
  // Zeigt den Schülern die exakten Bytes, die verschlüsselt werden
  HexText := BytesToHex(PaddedBytes);
  MemoCipher.Lines.Add('Gepaddete Daten (Hex):');
  MemoCipher.Lines.Add(HexText);
  MemoCipher.Lines.Add('');      // Leerzeile für bessere Lesbarkeit

   // -------------------------------------------------------------------------
  // SCHRITT 5: IV anzeigen (zur Kontrolle und zum Lernen)
  // -------------------------------------------------------------------------
  // Der IV (Initialization Vector) ist essentiell für CBC:
  // - 16 Bytes lang
  // - Wird für den ersten Block benötigt
  // - In diesem Lehrcode: Fest definiert als TEST_CBC_IV (siehe Konstanten)
  //
  // WICHTIG FÜR SCHÜLER:
  // In echten Anwendungen MUSS der IV:
  // - Zufällig sein
  // - Für jede Nachricht NEU sein
  // - Mit dem Ciphertext gespeichert werden (nicht geheim!)

  FillChar(LocalIV, SizeOf(LocalIV), 0);
  if not GenerateRandomIV(LocalIV) then
  begin
    StatusMemo.Lines.Add('Warnung: Konnte keinen zufälligen IV erzeugen, nutze Null-IV.');
    FillChar(LocalIV, SizeOf(LocalIV), 0);
  end;

 // IV von TByteArray16 in TBytes konvertieren (für BytesToHex)
  MemoCipher.Lines.Add('Zufällig erzeugter IV für CBC (Hex):');

  SetLength(IVBytes, 16);
  for I := 0 to 15 do
    IVBytes[I] := LocalIV[I];

  MemoCipher.Lines.Add(BytesToHex(IVBytes));
  MemoCipher.Lines.Add('');


  // 6) IV anzeigen (zur Kontrolle)
  MemoCipher.Lines.Add('Verwendeter IV für CBC (Hex):');
  SetLength(IVBytes, 16);
  for I := 0 to 15 do
  IVBytes[I] := LocalIV[I];
  MemoCipher.Lines.Add(BytesToHex(IVBytes));
  MemoCipher.Lines.Add('');

   // -------------------------------------------------------------------------
  // SCHRITT 6: Passwort → SHA-256 → AES-Key
  // -------------------------------------------------------------------------
  // Der Ablauf ist identisch zur ECB-Verschlüsselung:
  // 1. Passwort aus Edit2 (Eingabefeld) lesen
  KeyBytes := StringToBytesUTF8(Edit2.Text);

  // 2. SHA-256 Hash berechnen
  // Erzeugt deterministisch 32 Bytes aus beliebigem Passwort
  // Gleicher Input → Immer gleicher Output
  //
  // LEHRHINWEIS:
  // SHA-256 ist für Passwort-Hashing zu schnell!
  // Besser: PBKDF2 mit vielen Iterationen, Argon2, bcrypt
  // Aber für Lehrzwecke ist SHA-256 einfach verständlich
  KeyBytes := SHA256(KeyBytes);


  // -------------------------------------------------------------------------
  // SCHRITT 7: AES-256 Kontext initialisieren
  // -------------------------------------------------------------------------
  // Key Schedule: Generiert alle 15 Rundenschlüssel aus dem Hauptschlüssel
  //
  // Was passiert intern (siehe AES256InitKey):
  // - Erste 8 Wörter (32 Bytes) = Hauptschlüssel
  // - Wörter 8-59 werden durch Expansion erzeugt
  // - Verwendet RotWord, SubWord, Rcon für Diffusion
  // - Ergebnis: 60 Wörter = 15 Rundenschlüssel × 4 Wörter
  AES256InitKey(KeyBytes, Ctx);

 // -------------------------------------------------------------------------
  // SCHRITT 8: CBC-Verschlüsselung - DER HAUPTUNTERSCHIED ZU ECB!
  // -------------------------------------------------------------------------
  // AES256EncryptCBC macht:
  //
  // Für Block 0:
  //   InBlock = PlainBlock[0] ⊕ IV
  //   CipherBlock[0] = AES_Encrypt(InBlock)
  //
  // Für Block 1:
  //   InBlock = PlainBlock[1] ⊕ CipherBlock[0]  ← Verkettung!
  //   CipherBlock[1] = AES_Encrypt(InBlock)
  //
  // Für Block 2:
  //   InBlock = PlainBlock[2] ⊕ CipherBlock[1]  ← Verkettung!
  //   CipherBlock[2] = AES_Encrypt(InBlock)
  //
  // usw.
  //
  // EFFEKT:
  // - Jeder Block beeinflusst alle folgenden Blöcke
  // - Gleiche Plaintext-Blöcke ergeben unterschiedliche Ciphertext-Blöcke
  // - Muster werden verschleiert
  // - VIEL sicherer als ECB!
  CipherBytes := AES256EncryptCBC(PaddedBytes, LocalIV, Ctx);
  StatusMemo.Lines.Add('Daten wurden im AES-256-CBC-Modus verschlüsselt.');

  // -------------------------------------------------------------------------
  // SCHRITT 9: Verschlüsselte Daten als Hex ausgeben (Anzeige)
  // -------------------------------------------------------------------------
  HexCipher := BytesToHex(CipherBytes);
  MemoCipher.Lines.Add('AES-256 CBC verschlüsselte Daten (Hex):');
  MemoCipher.Lines.Add(HexCipher);

  // -------------------------------------------------------------------------
  // SCHRITT 10: WICHTIG - CipherBytes in FCipherBytes übernehmen
  // -------------------------------------------------------------------------
  // FCipherBytes ist eine Instanzvariable (private-Sektion der Form)
  // Sie speichert die verschlüsselten Daten im Arbeitsspeicher für:
  // - Entschlüsseln-Button (braucht die Daten zur Entschlüsselung)
  // - Speichern-Button (braucht die Daten zum Speichern in Datei)
  //
  // Copy() macht eine ECHTE Kopie (nicht nur Referenz):
  // - CipherBytes kann danach freigegeben werden
  // - FCipherBytes bleibt erhalten
  FCipherBytes := Copy(CipherBytes);
    // Zusätzlich speichern wir Metadaten für späteres Speichern/Entschlüsseln:
  FCipherMode  := acmCBC;     // Merken, dass CBC-Modus verwendet wurde
  FCipherIV    := LocalIV;    // Merken, welcher IV verwendet wurde
   //
  // WARUM WICHTIG?
  // - Beim Speichern: Container enthält Modus + IV
  // - Beim Entschlüsseln: Muss gleicher Modus + IV verwendet werden
  // - CBC ohne korrekten IV → Entschlüsselung schlägt fehl!

  StatusMemo.Lines.Add('Cipher-Text wurde in FCipherBytes übernommen (MemoCipher ist nur Anzeige).');
  StatusMemo.Lines.Add('--- CBC-Verschlüsselung erfolgreich abgeschlossen ---');
  // =========================================================================
  // ENDE DER CBC-VERSCHLÜSSELUNG
  // =========================================================================
  //
  // WICHTIGE LEHRPUNKTE FÜR SCHÜLER:
  //
  // 1. CBC vs ECB:
  //    - CBC: Blöcke verkettet, sicher, keine Muster
  //    - ECB: Blöcke unabhängig, unsicher, zeigt Muster
  //
  // 2. Der IV:
  //    - Muss bei jeder Nachricht NEU sein
  //    - Muss NICHT geheim sein (kann mit Ciphertext gespeichert werden)
  //    - DARF mit gleichem Key NIEMALS wiederverwendet werden
  //
  // 3. Warum CBC sicherer ist:
  //    - Gleiche Plaintext-Blöcke → unterschiedliche Ciphertext-Blöcke
  //    - Ein Block beeinflusst alle folgenden
  //    - Muster im Plaintext werden verschleiert
  //
  // 4. Noch sicherer:
  //    - Moderne Modi: GCM (mit Authentifizierung)
  //    - Oder: ChaCha20-Poly1305
  //    - Diese bieten Authenticated Encryption (Verschlüsselung + MAC)
  //
  // WEITERFÜHRENDE INFORMATIONEN:
  // - NIST SP 800-38A: Empfehlung für Block Cipher Modi
  // - "Cryptography Engineering" (Ferguson, Schneier, Kohno)
  // - Padding Oracle Attacks: Vaudenay (2002)

end;

procedure TAES_256_Lab.Entschluesseln_ButtonClick(Sender: TObject);
begin

end;

{ ---------------------------------------------------------------------------
  ENTschlüsseln (ECB) – nutzt NUR FCipherBytes
  Ziel: keine Exceptions bei ungültigem Padding -> Debugger bleibt still
  --------------------------------------------------------------------------- }
procedure TAES_256_Lab.entschluesseln_ECBClick(Sender: TObject);
var
  KeyBytes: TBytes;
  Ctx: TAES256Context;
  DecryptedPadded: TBytes;
  PlainBytes: TBytes;
  PlainText: string;
  PadLen: Integer;
  OutLen: Integer;
begin
  KeyBytes        := nil;
  DecryptedPadded := nil;
  PlainBytes      := nil;
  PlainText       := '';

  StatusMemo.Clear;
  StatusMemo.Lines.Add('--- Entschlüsselung (ECB) gestartet ---');

  if Length(FCipherBytes) = 0 then
  begin
    StatusMemo.Lines.Add('Fehler: Kein Cipher im Speicher (FCipherBytes ist leer).');
    StatusMemo.Lines.Add('Hinweis: Bitte zuerst verschlüsseln oder laden.');
    Exit;
  end;

  if (Length(FCipherBytes) mod 16) <> 0 then
  begin
    StatusMemo.Lines.Add('Fehler: Cipher-Datenlänge ist kein Vielfaches von 16.');
    Exit;
  end;

  // Passwort -> SHA-256 -> Key
  KeyBytes := StringToBytesUTF8(Edit2.Text);
  KeyBytes := SHA256(KeyBytes);

  AES256InitKey(KeyBytes, Ctx);

  // ECB entschlüsseln
  DecryptedPadded := AES256DecryptECB(FCipherBytes, Ctx);
  StatusMemo.Lines.Add('ECB-Entschlüsselung durchgeführt.');

  // Padding vorab prüfen (ohne Exception)
  if not TryGetPKCS7PadLen(DecryptedPadded, PadLen, 16) then
  begin
    StatusMemo.Lines.Add('FEHLER: Padding ungültig.');
    StatusMemo.Lines.Add('→ Sehr wahrscheinlich falsches Passwort oder falscher Modus.');
    ShowMessage('ECB-Entschlüsselung fehlgeschlagen.');
    Exit;
  end;

  OutLen := Length(DecryptedPadded) - PadLen;
  if OutLen < 0 then
  begin
    StatusMemo.Lines.Add('FEHLER: Interner Padding-Fehler (OutLen < 0).');
    ShowMessage('ECB-Entschlüsselung fehlgeschlagen.');
    Exit;
  end;

  SetLength(PlainBytes, OutLen);
  if OutLen > 0 then
    Move(DecryptedPadded[0], PlainBytes[0], OutLen);

  PlainText := BytesToStringUTF8(PlainBytes);

  decrypted_Memo.Clear;
  decrypted_Memo.Lines.Add(PlainText);

  StatusMemo.Lines.Add('--- Entschlüsselung (ECB) erfolgreich abgeschlossen ---');
end;

{ ---------------------------------------------------------------------------
  ENTschlüsseln (CBC) – nutzt FCipherBytes + FCipherIV
  Ziel: keine Exceptions bei ungültigem Padding -> Debugger bleibt still
  --------------------------------------------------------------------------- }
procedure TAES_256_Lab.entschluesseln_CBCClick(Sender: TObject);
var
  KeyBytes: TBytes;
  Ctx: TAES256Context;
  DecryptedPadded: TBytes;
  PlainBytes: TBytes;
  PlainText: string;
  PadLen: Integer;
  OutLen: Integer;
begin
  KeyBytes        := nil;
  DecryptedPadded := nil;
  PlainBytes      := nil;
  PlainText       := '';

  StatusMemo.Clear;
  StatusMemo.Lines.Add('--- Entschlüsselung (CBC) gestartet ---');

  if Length(FCipherBytes) = 0 then
  begin
    StatusMemo.Lines.Add('Fehler: Kein Cipher im Speicher (FCipherBytes ist leer).');
    StatusMemo.Lines.Add('Hinweis: Bitte zuerst CBC verschlüsseln oder laden.');
    Exit;
  end;

  if (Length(FCipherBytes) mod 16) <> 0 then
  begin
    StatusMemo.Lines.Add('Fehler: Cipher-Datenlänge ist kein Vielfaches von 16.');
    Exit;
  end;

  if FCipherMode <> acmCBC then
    StatusMemo.Lines.Add('Hinweis: Cipher ist nicht als CBC markiert (Testen ist möglich, aber vermutlich falsch).');

  // Passwort -> SHA-256 -> Key
  KeyBytes := StringToBytesUTF8(Edit2.Text);
  KeyBytes := SHA256(KeyBytes);

  AES256InitKey(KeyBytes, Ctx);

  // CBC entschlüsseln
  DecryptedPadded := AES256DecryptCBC(FCipherBytes, FCipherIV, Ctx);
  StatusMemo.Lines.Add('CBC-Entschlüsselung durchgeführt.');

  // Padding prüfen (ohne Exception)
  if not TryGetPKCS7PadLen(DecryptedPadded, PadLen, 16) then
  begin
    StatusMemo.Lines.Add('FEHLER: Padding ungültig.');
    StatusMemo.Lines.Add('→ Sehr wahrscheinlich falsches Passwort oder falscher Modus.');
    ShowMessage('CBC-Entschlüsselung fehlgeschlagen.');
    Exit;
  end;

  OutLen := Length(DecryptedPadded) - PadLen;
  if OutLen < 0 then
  begin
    StatusMemo.Lines.Add('FEHLER: Interner Padding-Fehler (OutLen < 0).');
    ShowMessage('CBC-Entschlüsselung fehlgeschlagen.');
    Exit;
  end;

  SetLength(PlainBytes, OutLen);
  if OutLen > 0 then
    Move(DecryptedPadded[0], PlainBytes[0], OutLen);

  PlainText := BytesToStringUTF8(PlainBytes);

  decrypted_Memo.Clear;
  decrypted_Memo.Lines.Add(PlainText);

  StatusMemo.Lines.Add('--- Entschlüsselung (CBC) erfolgreich abgeschlossen ---');
end;

procedure TAES_256_Lab.SpeichernClick(Sender: TObject);
var
  Container: TBytes;
begin
  if Length(FCipherBytes) = 0 then
  begin
    StatusMemo.Lines.Add('Hinweis: Es gibt keine CipherBytes zum Speichern.');
    Exit;
  end;

  if not SaveDialog1.Execute then
  begin
    StatusMemo.Lines.Add('Speichern abgebrochen.');
    Exit;
  end;

  // ECB: IV egal -> ZERO_IV, CBC: FCipherIV wird gespeichert
  if FCipherMode = acmCBC then
    Container := BuildContainerBytes(FCipherBytes, FCipherMode, FCipherIV)
  else
    Container := BuildContainerBytes(FCipherBytes, acmECB, ZERO_IV);

  if SaveContainerToFile(SaveDialog1.FileName, Container) then
  begin
    StatusMemo.Lines.Add('Container gespeichert: ' + SaveDialog1.FileName);
    StatusMemo.Lines.Add('Cipher-Länge: ' + IntToStr(Length(FCipherBytes)) + ' Bytes');
  end
  else
    StatusMemo.Lines.Add('Fehler: Konnte Container nicht speichern.');
end;

procedure TAES_256_Lab.LadenClick(Sender: TObject);
var
  Container: TBytes;
  Mode: TAESContainerMode;
  IV: TByteArray16;
  Cipher: TBytes;
begin
  if not OpenDialog1.Execute then
  begin
    StatusMemo.Lines.Add('Laden abgebrochen.');
    Exit;
  end;

  if not LoadContainerFromFile(OpenDialog1.FileName, Container) then
  begin
    StatusMemo.Lines.Add('Fehler: Konnte Datei nicht laden.');
    Exit;
  end;

  if not ParseContainerBytes(Container, Cipher, Mode, IV) then
  begin
    StatusMemo.Lines.Add('Fehler: Datei ist kein gültiger Container oder beschädigt.');
    Exit;
  end;

  FCipherBytes := Copy(Cipher);
  FCipherMode  := Mode;
  FCipherIV    := IV;

  StatusMemo.Lines.Add('Container geladen: ' + OpenDialog1.FileName);
  if FCipherMode = acmCBC then
    StatusMemo.Lines.Add('Mode: CBC (IV im Container gespeichert)')
  else
    StatusMemo.Lines.Add('Mode: ECB');

  MemoCipher.Clear;
  MemoCipher.Lines.Add('Geladener Cipher (Hex, nur Anzeige):');
  MemoCipher.Lines.Add(BytesToHex(FCipherBytes));
end;

procedure TAES_256_Lab.NIST_CBCClick(Sender: TObject);
{------------------------------------------------------------------------------
  NIST-Test (AES-256 CBC, 1 Block) – Known Answer Test (KAT)

  Was wird hier getestet?
  - Dieser Button testet die AES-256 Verschlüsselung im CBC-Modus anhand
    eines bekannten Referenzbeispiels (NIST-Testvektor).
  - CBC bedeutet: Vor der Verschlüsselung wird der Klartextblock mit einem IV
    (Initialisierungsvektor) per XOR verknüpft, erst dann wird der Block mit AES
    verschlüsselt.

  Verwendete Testdaten (als HEX-Strings)
  - KEY_HEX: 32 Bytes (256 Bit) AES-Schlüssel
  - IV_HEX:  16 Bytes (128 Bit) Initialisierungsvektor
  - PT_HEX:  16 Bytes (128 Bit) Klartextblock
  - CT_HEX:  16 Bytes (128 Bit) erwarteter Ciphertext (Referenz)

  Ablauf (Schritt für Schritt)
  1) Alle HEX-Strings werden in Byte-Arrays umgewandelt (HexToBytes).
  2) Das IV wird als 16-Byte-Block (TByteArray16) vorbereitet.
  3) Aus dem Key wird der AES-KeySchedule erzeugt:
     - AES256InitKey(KeyBytes, Ctx)
  4) CBC-Verschlüsselung für GENAU EINEN Block:
     - CtActual := AES256EncryptCBC(PtBytes, IV, Ctx)
     Das Ergebnis wird als HEX ausgegeben und mit CT_HEX verglichen.
  5) Optional wird zur Kontrolle direkt wieder entschlüsselt:
     - PtDecrypted := AES256DecryptCBC(CtActual, IV, Ctx)
     Das Ergebnis muss wieder PT_HEX ergeben.

  Warum ist dieser Test wichtig?
  - Er zeigt, dass CBC (inklusive IV-Verwendung) für bekannte Referenzdaten
    korrekt arbeitet. Damit kann man Implementierungsfehler sehr schnell finden.

  Quelle der Testvektoren
  - NIST SP 800-38A (Modes of Operation, u.a. CBC-Beispiele für AES-256)
------------------------------------------------------------------------------}
const
  KEY_HEX = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
  IV_HEX  = '000102030405060708090a0b0c0d0e0f';
  PT_HEX  = '6bc1bee22e409f96e93d7e117393172a';
  CT_HEX  = 'f58c4c04d6e5f1ba779eabfb5f7bfbd6';
var
  KeyBytes, PtBytes, CtExpected, CtActual, PtDecrypted: TBytes;
  Ctx: TAES256Context;
  IV: TByteArray16;

  procedure BytesToBlock16(const Src: TBytes; out Dst: TByteArray16);
  begin
    if Length(Src) <> 16 then
      raise Exception.Create('NIST-CBC-Test: Blocklänge ist nicht 16 Byte.');
    Dst[0] := 0; // Compiler-Hinweis beruhigen
    Move(Src[0], Dst[0], 16);
  end;

begin
  StatusMemo.Clear;
  MemoCipher.Clear;

  StatusMemo.Lines.Add('--- NIST AES-256 CBC (Single Block) Test ---');

  // Hex -> Bytes
  KeyBytes   := HexToBytes(KEY_HEX);
  PtBytes    := HexToBytes(PT_HEX);
  CtExpected := HexToBytes(CT_HEX);

  // IV vorbereiten
  BytesToBlock16(HexToBytes(IV_HEX), IV);

  // AES KeySchedule
  AES256InitKey(KeyBytes, Ctx);

  // CBC Encrypt (1 Block)
  CtActual := AES256EncryptCBC(PtBytes, IV, Ctx);

  // Ausgabe
  MemoCipher.Lines.Add('Key:       ' + KEY_HEX);
  MemoCipher.Lines.Add('IV:        ' + IV_HEX);
  MemoCipher.Lines.Add('Plaintext: ' + PT_HEX);
  MemoCipher.Lines.Add('Expected:  ' + CT_HEX);
  MemoCipher.Lines.Add('Actual:    ' + BytesToHex(CtActual));

  if SameText(BytesToHex(CtActual), CT_HEX) then
    StatusMemo.Lines.Add('OK: CBC-Verschlüsselung stimmt mit NIST-Testvektor.')
  else
    StatusMemo.Lines.Add('FEHLER: CBC-Ausgabe weicht vom NIST-Testvektor ab!');

  // Optional: CBC Decrypt (zur Kontrolle zurück)
  PtDecrypted := AES256DecryptCBC(CtActual, IV, Ctx);
  MemoCipher.Lines.Add('Decrypted: ' + BytesToHex(PtDecrypted));

  if SameText(BytesToHex(PtDecrypted), PT_HEX) then
    StatusMemo.Lines.Add('OK: CBC-Entschlüsselung liefert wieder den Klartext.')
  else
    StatusMemo.Lines.Add('FEHLER: CBC-Entschlüsselung liefert NICHT den Klartext.');
end;

procedure TAES_256_Lab.NIST_TestClick(Sender: TObject);
    {------------------------------------------------------------------------------
  NIST-Test (AES-256 Single-Block / Known Answer Test)

  Was wird hier getestet?
  - Dieser Button führt einen sogenannten "Known Answer Test" (KAT) aus.
    Dabei werden feste, bekannte Testdaten (Key, Plaintext und erwarteter
    Ciphertext) verwendet, die in vielen Referenzen (NIST-Testvektoren)
    veröffentlicht sind.
    Testvektoren-Quelle: NIST (CAVP AES Known Answer Tests) und NIST SP 800-38A / FIPS 197.

  Ablauf (Schritt für Schritt)
  1) Wir definieren die Testwerte als HEX-Strings:
     - KEY_HEX:    32 Bytes (256 Bit) AES-Schlüssel
     - PT_HEX:     16 Bytes (128 Bit) Klartext-Block
     - CT_HEX:     16 Bytes (128 Bit) erwarteter Ciphertext

  2) Die HEX-Strings werden in Byte-Arrays umgewandelt (HexToBytes).

  3) Der Klartext wird als 16-Byte-Block (TByteArray16) vorbereitet.

  4) AES-KeySchedule wird aufgebaut:
     - AES256InitKey(KeyBytes, Ctx)

  5) Es wird exakt EIN Block AES-256 verschlüsselt (ohne Modus wie CBC/ECB-Loop):
     - AES256EncryptBlock(InBlock, OutBlock, Ctx)

     Hinweis:
     Der Begriff "ECB" taucht bei vielen Testvektoren auf, weil ein einzelner
     Block ohne Verkettung dem ECB-Fall entspricht. Für diesen Test ist nur
     wichtig: "Single Block rein -> Single Block raus".

  6) Das Ergebnis (Actual) wird wieder als HEX ausgegeben und mit dem
     erwarteten Wert (Expected) verglichen.
     - Wenn gleich: OK (AES-Kern arbeitet korrekt für diesen Testvektor)
     - Wenn ungleich: Fehler (Implementierung oder Datenumwandlung prüfen)

  Warum ist dieser Test wichtig?
  - Kryptografie testet man nicht "nach Gefühl".
    Der Test zeigt sofort, ob der AES-Kern für bekannte Referenzwerte stimmt.
------------------------------------------------------------------------------}
   const
  KEY_HEX = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
  PT_HEX  = '6bc1bee22e409f96e93d7e117393172a';
  CT_HEX  = 'f3eed1bdb5d2a03c064b5a7e3db181f8';
var
  KeyBytes, PtBytes, CtExpected, CtActual: TBytes;
  Ctx: TAES256Context;
  InBlock, OutBlock: TByteArray16;

  procedure BytesToBlock16(const Src: TBytes; out Dst: TByteArray16);
  begin
    if Length(Src) <> 16 then
      raise Exception.Create('NIST-Test: Blocklänge ist nicht 16 Byte.');
    Dst[0] := 0; // Compiler-Hinweis beruhigen
    Move(Src[0], Dst[0], 16);
  end;

  function Block16ToBytes(const B: TByteArray16): TBytes;
  begin
    result:=nil;
    SetLength(Result, 16);
    Move(B[0], Result[0], 16);
  end;

begin
  StatusMemo.Clear;
  MemoCipher.Clear;

  StatusMemo.Lines.Add('--- NIST AES-256 ECB (Single Block) Test ---');

  // Hex -> Bytes
  KeyBytes   := HexToBytes(KEY_HEX);
  PtBytes    := HexToBytes(PT_HEX);
  CtExpected := HexToBytes(CT_HEX);

  // Bytes -> 16-Byte Block
  BytesToBlock16(PtBytes, InBlock);

  // AES Core
  AES256InitKey(KeyBytes, Ctx);
  AES256EncryptBlock(InBlock, OutBlock, Ctx);

  CtActual := Block16ToBytes(OutBlock);

  // Ausgabe
  MemoCipher.Lines.Add('Key:       ' + KEY_HEX);
  MemoCipher.Lines.Add('Plaintext: ' + PT_HEX);
  MemoCipher.Lines.Add('Expected:  ' + CT_HEX);
  MemoCipher.Lines.Add('Actual:    ' + BytesToHex(CtActual));

 if SameText(BytesToHex(CtActual), CT_HEX) then
    StatusMemo.Lines.Add('OK: AES-256 Blocktest bestanden.')
  else
    StatusMemo.Lines.Add('FEHLER: Ausgabe weicht vom NIST-Testvektor ab!');
end;


procedure TAES_256_Lab.Selftest_ButtonClick(Sender: TObject);
var
  Report: string;
  Ok: Boolean;
begin
  StatusMemo.Clear;
  MemoCipher.Clear;

  StatusMemo.Lines.Add('--- AES-256 Selftest gestartet ---');

  Report := '';
  Ok := AES256SelfTest(Report);

  // Report ins Memo (für Lernzwecke)
  MemoCipher.Lines.Add(Report);

  if Ok then
    StatusMemo.Lines.Add('--- AES-256 Selftest ERFOLGREICH abgeschlossen ---')
  else
    StatusMemo.Lines.Add('--- AES-256 Selftest FEHLGESCHLAGEN: Implementierung prüfen! ---');
end;




procedure TAES_256_Lab.Memo_controlChange(Sender: TObject);
begin
  // optional: später Tabs/StatusBar synchronisieren
end;




procedure TAES_256_Lab.FormCreate(Sender: TObject);
begin
  Label_Text.Caption := 'Eingabe Klartext';
  Label_Key.Caption  := 'Eingabe Key';

  Verschluesseln_Button.Caption := 'Verschlüsseln (ECB)';
  CBCModus_Button.Caption       := 'Verschlüsseln (CBC)';

  entschluesseln_ECB.Caption    := 'Entschlüsseln (ECB)';
  entschluesseln_CBC.Caption    := 'Entschlüsseln (CBC)';

  Selftest_Button.Caption       := 'Selbsttest'   ;
  NIST_Test.Caption             := 'NIST_Test'    ;
  NIST_CBC.Caption              := 'NIST_CBC'     ;
  speichern.Caption             := 'Chiffre Speichern'   ;
  laden.Caption                 := 'Chiffre Laden'       ;
  if Assigned(Memo_Control) then
    Memo_Control.ActivePageIndex := 0;

  FCipherBytes := nil;
  FCipherMode  := acmECB;
  FCipherIV    := ZERO_IV;

  StatusMemo.Clear;
  StatusMemo.Lines.Add('Init- OK');
end;

end.

