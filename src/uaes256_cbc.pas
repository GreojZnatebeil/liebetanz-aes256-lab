unit uAES256_CBC;

{$mode objfpc}{$H+}

interface
   (*
  ----------------------------------------------------------------------------
  AES-Projekt / Lazarus / FreePascal – CBC-Modus (separierte Unit)
  ----------------------------------------------------------------------------
  Diese Unit enthält ausschließlich CBC-spezifische Funktionen.
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
  SysUtils,uAES256;                              // Core-Unit: Typen + Blockfunktionen + XOR-Hilfe

function AES256EncryptCBC(const PlainData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
  // Verschlüsselt Daten im CBC-Modus mit AES-256.
  // PlainData muss vorher PKCS#7-gepaddet sein (Vielfaches von 16 Byte).

function AES256DecryptCBC(const CipherData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
  // Entschlüsselt AES-256-CBC-Daten. CipherData-Länge muss Vielfaches von 16 sein.

implementation

function AES256EncryptCBC(const PlainData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
var
  DataLen: Integer;                     // Länge der Eingabedaten
  NumBlocks: Integer;                   // Anzahl 16-Byte-Blöcke
  BlockIndex: Integer;                  // Index für den aktuellen Block
  Offset: Integer;                      // Offset im PlainData-Array
  InBlock, OutBlock, PrevBlock: TByteArray16; // Arbeitsblöcke für CBC
  I: Integer;                           // Laufvariable
begin
  Result := nil;                        // Ergebnis zunächst leeren

  DataLen := Length(PlainData);         // Länge der Eingabedaten ermitteln

  if DataLen = 0 then                   // Falls keine Daten vorliegen
    Exit;                               // nichts zu tun

  if (DataLen mod 16) <> 0 then         // CBC erwartet ebenfalls Vielfaches von 16 Byte
    raise Exception.Create('AES256EncryptCBC: Datenlänge muss ein Vielfaches von 16 sein (zuerst PKCS7Pad anwenden).');

  NumBlocks := DataLen div 16;          // Anzahl der 16-Byte-Blöcke berechnen
  SetLength(Result, DataLen);           // Ergebnis-Array bekommt gleiche Länge wie PlainData

  // Initialen "vorherigen Block" auf das IV setzen
  PrevBlock := IV;                      // Beim ersten Block ist "previous" = Initialisierungsvektor

  Offset := 0;                          // Start-Offset im PlainData-Array

  for BlockIndex := 0 to NumBlocks - 1 do // Schleife über alle Blöcke
  begin
    // 1. 16 Bytes aus PlainData in InBlock kopieren
    for I := 0 to 15 do
      InBlock[I] := PlainData[Offset + I];

    // 2. InBlock mit PrevBlock XORen (CBC-Kettenbildung)
    XorBlockInPlace(InBlock, PrevBlock);

    // 3. Den so kombinierten Block verschlüsseln
    AES256EncryptBlock(InBlock, OutBlock, Context);

    // 4. Verschlüsselten Block in das Ergebnis kopieren
    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    // 5. Für den nächsten Durchlauf wird der aktuelle Cipherblock zum "PrevBlock"
    PrevBlock := OutBlock;

    Inc(Offset, 16);                    // Offset für den nächsten Block erhöhen
  end;
end;

function AES256DecryptCBC(const CipherData: TBytes; const IV: TByteArray16;
  const Context: TAES256Context): TBytes;
var
  DataLen: Integer;                     // Länge der Cipher-Daten
  NumBlocks: Integer;                   // Anzahl 16-Byte-Blöcke
  BlockIndex: Integer;                  // Index des aktuellen Blocks
  Offset: Integer;                      // Offset im CipherData-Array
  InBlock, OutBlock, PrevBlock: TByteArray16; // Arbeitsblöcke
  I: Integer;                           // Laufvariable
begin
  Result := nil;                        // Ergebnis initialisieren

  DataLen := Length(CipherData);        // Länge der Eingangsdaten ermitteln

  if DataLen = 0 then                   // Keine Daten → nichts zu tun
    Exit;

  if (DataLen mod 16) <> 0 then         // CBC verlangt Vielfaches von 16 Byte
    raise Exception.Create('AES256DecryptCBC: Datenlänge muss ein Vielfaches von 16 sein.');

  NumBlocks := DataLen div 16;          // Anzahl der 16-Byte-Blöcke berechnen
  SetLength(Result, DataLen);           // Ergebnis-Array bekommt gleiche Länge wie CipherData

  // Initialer "vorheriger Block" ist das IV
  PrevBlock := IV;

  Offset := 0;                          // Start-Offset im CipherData-Array

  for BlockIndex := 0 to NumBlocks - 1 do
  begin
    // 1. 16 Bytes Ciphertext in InBlock kopieren
    for I := 0 to 15 do
      InBlock[I] := CipherData[Offset + I];

    // 2. Cipherblock mit AES entschlüsseln → OutBlock (noch mit CBC-Pre-XOR)
    AES256DecryptBlock(InBlock, OutBlock, Context);

    // 3. Entschlüsselten Block mit PrevBlock XORen, um den ursprünglichen Plaintextblock zu erhalten
    XorBlockInPlace(OutBlock, PrevBlock);

    // 4. Ergebnis-Block in Result schreiben
    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    // 5. Für den nächsten Block wird der aktuelle Cipherblock zum neuen PrevBlock
    PrevBlock := InBlock;

    Inc(Offset, 16);                    // Offset für den nächsten Block erhöhen
  end;
end;

end.
