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
var
  PlainText: string;
  PlainBytes: TBytes;
  PaddedBytes: TBytes;
  HexText: string;

  Block: TByteArray16;
  State: TAESState;
  RoundBytes: TBytes;
  HexRound: string;

  KeyBytes: TBytes;
  Ctx: TAES256Context;
  CipherBytes: TBytes;
  HexCipher: string;

  I: Integer;
begin
  RoundBytes   := nil;
  KeyBytes     := nil;
  CipherBytes  := nil;
  PaddedBytes  := nil;
  PlainBytes   := nil;

  StatusMemo.Clear;
  MemoCipher.Clear;
  StatusMemo.Lines.Add('Warnung: ECB ist unsicher und nur zum Lernen gedacht.');
  StatusMemo.Lines.Add('--- Verschlüsselung (ECB) gestartet ---');
  StatusMemo.Lines.Add('Hinweis: Passwort->Key erfolgt didaktisch via SHA-256 (nicht produktionssicher).');

  // 1) Klartext lesen
  PlainText := MemoPlain.Text;
  if PlainText = '' then
  begin
    StatusMemo.Lines.Add('Hinweis: Kein Klartext in MemoPlain vorhanden, Vorgang abgebrochen.');
    Exit;
  end;

  // 2) String -> UTF-8-Bytes
  PlainBytes := StringToBytesUTF8(PlainText);
  StatusMemo.Lines.Add('Klartext wurde in UTF-8-Bytes umgewandelt.');

  // 3) PKCS#7 Padding
  PaddedBytes := PKCS7Pad(PlainBytes, 16);
  StatusMemo.Lines.Add('PKCS#7-Padding angewendet.');

  // 4) Gepaddete Daten anzeigen (Hex)
  HexText := BytesToHex(PaddedBytes);
  MemoCipher.Lines.Add('Gepaddete Daten (Hex):');
  MemoCipher.Lines.Add(HexText);
  MemoCipher.Lines.Add('');

  // 5) Lehr-Test: Rundenkern auf Block 0
  if Length(PaddedBytes) < 16 then
  begin
    StatusMemo.Lines.Add('Fehler: Zu wenige Daten für einen 16-Byte-Block trotz Padding.');
    Exit;
  end;

  for I := 0 to 15 do
    Block[I] := PaddedBytes[I];

  BlockToState(Block, State);
  SubBytesState(State);
  ShiftRowsState(State);
  MixColumnsState(State);
  StateToBlock(State, Block);

  SetLength(RoundBytes, 16);
  Move(Block[0], RoundBytes[0], 16);
  HexRound := BytesToHex(RoundBytes);

  MemoCipher.Lines.Add('Erster Block nach SubBytes + ShiftRows + MixColumns (Hex):');
  MemoCipher.Lines.Add(HexRound);
  MemoCipher.Lines.Add('');

  // 6) Passwort -> SHA-256 -> 32-Byte-Key
  KeyBytes := StringToBytesUTF8(Edit2.Text);
  KeyBytes := SHA256(KeyBytes);

  MemoCipher.Lines.Add('SHA-256 Hash des Passworts (AES-256 Key):');
  MemoCipher.Lines.Add(BytesToHex(KeyBytes));
  MemoCipher.Lines.Add('');

  // 7) AES-256 Kontext
  AES256InitKey(KeyBytes, Ctx);

  // 8) ECB verschlüsseln
  CipherBytes := AES256EncryptECB(PaddedBytes, Ctx);
  StatusMemo.Lines.Add('Daten wurden im AES-256-ECB-Modus verschlüsselt.');

  // 9) Anzeige (Hex)
  HexCipher := BytesToHex(CipherBytes);
  MemoCipher.Lines.Add('AES-256 ECB verschlüsselte Daten (Hex):');
  MemoCipher.Lines.Add(HexCipher);

  // 10) State übernehmen (für Speichern/Entschlüsseln)
  FCipherBytes := Copy(CipherBytes);
  FCipherMode  := acmECB;
  FCipherIV    := ZERO_IV;

  StatusMemo.Lines.Add('Cipher-Text wurde in FCipherBytes übernommen (MemoCipher ist nur Anzeige).');
  StatusMemo.Lines.Add('--- Verschlüsselung (ECB) erfolgreich abgeschlossen ---');
end;

procedure TAES_256_Lab.CBCModus_ButtonClick(Sender: TObject);
var
  PlainText: string;
  PlainBytes: TBytes;
  PaddedBytes: TBytes;
  HexText: string;

  KeyBytes: TBytes;
  Ctx: TAES256Context;
  CipherBytes: TBytes;
  HexCipher: string;

  IVBytes: TBytes;                      // nur Anzeige
  LocalIV: TByteArray16;

  I: Integer;
begin
  PlainBytes   := nil;
  PaddedBytes  := nil;
  KeyBytes     := nil;
  CipherBytes  := nil;
  IVBytes      := nil;
    LocalIV[0] := 0;


  StatusMemo.Clear;
  MemoCipher.Clear;

  StatusMemo.Lines.Add('--- CBC-Verschlüsselung gestartet ---');
   StatusMemo.Lines.Add('Hinweis: IV ist bei CBC zwingend und wird im Container gespeichert.');
   StatusMemo.Lines.Add('Hinweis: Passwort->Key erfolgt didaktisch via SHA-256 (nicht produktionssicher).');

  // 1) Klartext lesen
  PlainText := MemoPlain.Text;
  if PlainText = '' then
  begin
    StatusMemo.Lines.Add('Hinweis: Kein Klartext in MemoPlain vorhanden, Vorgang abgebrochen.');
    Exit;
  end;

  // 2) String -> UTF-8-Bytes
  PlainBytes := StringToBytesUTF8(PlainText);
  StatusMemo.Lines.Add('Klartext wurde in UTF-8-Bytes umgewandelt.');

  // 3) PKCS#7 Padding
  PaddedBytes := PKCS7Pad(PlainBytes, 16);
  StatusMemo.Lines.Add('PKCS#7-Padding angewendet.');

  // 4) Gepaddete Daten anzeigen (Hex)
  HexText := BytesToHex(PaddedBytes);
  MemoCipher.Lines.Add('Gepaddete Daten (Hex):');
  MemoCipher.Lines.Add(HexText);
  MemoCipher.Lines.Add('');

  // 5) Random IV erzeugen

  FillChar(LocalIV, SizeOf(LocalIV), 0);
  if not GenerateRandomIV(LocalIV) then
  begin
    StatusMemo.Lines.Add('Warnung: Konnte keinen zufälligen IV erzeugen, nutze Null-IV.');
    FillChar(LocalIV, SizeOf(LocalIV), 0);
  end;

  // --- IV anzeigen (zur Kontrolle / Lernprojekt) ---
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

  // 7) Passwort -> SHA-256 -> AES-Key
  KeyBytes := StringToBytesUTF8(Edit2.Text);
  KeyBytes := SHA256(KeyBytes);

  // 8) AES-256 Kontext
  AES256InitKey(KeyBytes, Ctx);

  // 9) CBC verschlüsseln (WICHTIG: LocalIV verwenden!)
  CipherBytes := AES256EncryptCBC(PaddedBytes, LocalIV, Ctx);
  StatusMemo.Lines.Add('Daten wurden im AES-256-CBC-Modus verschlüsselt.');

  // 10) Anzeige (Hex)
  HexCipher := BytesToHex(CipherBytes);
  MemoCipher.Lines.Add('AES-256 CBC verschlüsselte Daten (Hex):');
  MemoCipher.Lines.Add(HexCipher);

  // 11) State übernehmen
  FCipherBytes := Copy(CipherBytes);
  FCipherMode  := acmCBC;
  FCipherIV    := LocalIV;

  StatusMemo.Lines.Add('Cipher-Text wurde in FCipherBytes übernommen (MemoCipher ist nur Anzeige).');
  StatusMemo.Lines.Add('--- CBC-Verschlüsselung erfolgreich abgeschlossen ---');
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




{const
  TestKey256: array[0..31] of Byte = (
    $60,$3D,$EB,$10,$15,$CA,$71,$BE,$2B,$73,$AE,$F0,$85,$7D,$77,$81,
    $1F,$35,$2C,$07,$3B,$61,$08,$D7,$2D,$98,$10,$A3,$09,$14,$DF,$F4
  );

  TestPlain: TByteArray16 = (
    $6B,$C1,$BE,$E2,$2E,$40,$9F,$96,$E9,$3D,$7E,$11,$73,$93,$17,$2A
  );

  ExpectedCipher: TByteArray16 = (
    $F3,$EE,$D1,$BD,$B5,$D2,$A0,$3C,$06,$4B,$5A,$7E,$3D,$B1,$81,$F8
  );
var
  KeyBytes: TBytes;
  Ctx: TAES256Context;

  PlainBlock: TByteArray16;
  CipherBlock: TByteArray16;
  DecryptedBlock: TByteArray16;

  ActualCipherBytes: TBytes;
  ExpectedCipherBytes: TBytes;
  PlainBytes: TBytes;
  DecryptedBytes: TBytes;

  I: Integer;
  OkEncrypt, OkDecrypt: Boolean;
begin
  KeyBytes            := nil;
  ActualCipherBytes   := nil;
  ExpectedCipherBytes := nil;
  PlainBytes          := nil;
  DecryptedBytes      := nil;

  StatusMemo.Clear;
  MemoCipher.Clear;

  StatusMemo.Lines.Add('--- AES-256 Selftest gestartet ---');
  StatusMemo.Lines.Add('Verwende festen NIST-Testvektor (Key + Plaintext + erwarteter Cipher).');
  StatusMemo.Lines.Add('');

  SetLength(KeyBytes, 32);
  for I := 0 to 31 do
    KeyBytes[I] := TestKey256[I];

  PlainBlock := TestPlain;

  AES256InitKey(KeyBytes, Ctx);

  AES256EncryptBlock(PlainBlock, CipherBlock, Ctx);

  OkEncrypt := True;
  for I := 0 to 15 do
    if CipherBlock[I] <> ExpectedCipher[I] then
    begin
      OkEncrypt := False;
      Break;
    end;

  AES256DecryptBlock(CipherBlock, DecryptedBlock, Ctx);

  OkDecrypt := True;
  for I := 0 to 15 do
    if DecryptedBlock[I] <> TestPlain[I] then
    begin
      OkDecrypt := False;
      Break;
    end;

  SetLength(ActualCipherBytes,   16);
  SetLength(ExpectedCipherBytes, 16);
  SetLength(PlainBytes,          16);
  SetLength(DecryptedBytes,      16);

  Move(CipherBlock[0],    ActualCipherBytes[0],   16);
  Move(ExpectedCipher[0], ExpectedCipherBytes[0], 16);
  Move(TestPlain[0],      PlainBytes[0],          16);
  Move(DecryptedBlock[0], DecryptedBytes[0],      16);

  MemoCipher.Lines.Add('=== AES-256 Selftest (1 Block) ===');
  MemoCipher.Lines.Add('Test-Plaintext (Hex):');
  MemoCipher.Lines.Add(BytesToHex(PlainBytes));
  MemoCipher.Lines.Add('');
  MemoCipher.Lines.Add('Erwarteter Cipher (Hex):');
  MemoCipher.Lines.Add(BytesToHex(ExpectedCipherBytes));
  MemoCipher.Lines.Add('');
  MemoCipher.Lines.Add('Berechneter Cipher (Hex):');
  MemoCipher.Lines.Add(BytesToHex(ActualCipherBytes));
  MemoCipher.Lines.Add('');
  MemoCipher.Lines.Add('Entschlüsselter Block (Hex):');
  MemoCipher.Lines.Add(BytesToHex(DecryptedBytes));
  MemoCipher.Lines.Add('================================');
  MemoCipher.Lines.Add('');

  if OkEncrypt then
    StatusMemo.Lines.Add('Verschlüsselungs-Test: OK (Cipher entspricht dem erwarteten NIST-Vektor).')
  else
    StatusMemo.Lines.Add('Verschlüsselungs-Test: FEHLER (Cipher weicht vom erwarteten NIST-Vektor ab).');

  if OkDecrypt then
    StatusMemo.Lines.Add('Entschlüsselungs-Test: OK (Entschlüsselter Block entspricht dem Plaintext).')
  else
    StatusMemo.Lines.Add('Entschlüsselungs-Test: FEHLER (Entschlüsselter Block weicht vom Plaintext ab).');

  if OkEncrypt and OkDecrypt then
    StatusMemo.Lines.Add('--- AES-256 Selftest ERFOLGREICH abgeschlossen ---')
  else
    StatusMemo.Lines.Add('--- AES-256 Selftest FEHLGESCHLAGEN: Implementierung prüfen! ---');
end;
}
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

  Selftest_Button.Caption       := 'Selbsttest';

  if Assigned(Memo_Control) then
    Memo_Control.ActivePageIndex := 0;

  FCipherBytes := nil;
  FCipherMode  := acmECB;
  FCipherIV    := ZERO_IV;

  StatusMemo.Clear;
  StatusMemo.Lines.Add('Init- OK');
end;

end.

