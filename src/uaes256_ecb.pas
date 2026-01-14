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
var
  DataLen: Integer;                     // Länge der Eingabedaten
  NumBlocks: Integer;                   // Anzahl 16-Byte-Blöcke
  BlockIndex: Integer;                  // Index für den aktuellen Block
  Offset: Integer;                      // Offset im Byte-Array
  InBlock, OutBlock: TByteArray16;      // Eingabe- und Ausgabe-Block
  I: Integer;                           // Laufvariable für Schleifen
begin
  Result := nil;                        // Initialisiert das Ergebnis

  DataLen := Length(PlainData);         // Ermittelt die Länge der Eingabedaten

  if DataLen = 0 then                   // Wenn keine Daten vorliegen, gibt es nichts zu verschlüsseln
    Exit;

  if (DataLen mod 16) <> 0 then         // ECB erwartet Datenlänge als Vielfaches von 16
    raise Exception.Create('AES256EncryptECB: Datenlänge muss ein Vielfaches von 16 sein (zuerst PKCS7Pad anwenden).');

  NumBlocks := DataLen div 16;          // Anzahl 16-Byte-Blöcke berechnen

  SetLength(Result, DataLen);           // Ergebnis-Array hat die gleiche Länge wie die Eingabedaten

  Offset := 0;                          // Start-Offset im Eingabearray

  for BlockIndex := 0 to NumBlocks - 1 do // Schleife über alle Blöcke
  begin
    // 1. 16 Bytes aus PlainData in InBlock kopieren
    for I := 0 to 15 do
      InBlock[I] := PlainData[Offset + I];

    // 2. Einzelnen Block mit AES-256 verschlüsseln
    AES256EncryptBlock(InBlock, OutBlock, Context);

    // 3. Verschlüsselten Block in das Ergebnis-Array kopieren
    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    Inc(Offset, 16);                    // Offset für den nächsten Block erhöhen
  end;
end;

function AES256DecryptECB(const CipherData: TBytes; const Context: TAES256Context): TBytes;
var
  DataLen: Integer;                     // Länge der Eingangsdaten
  NumBlocks: Integer;                   // Anzahl der 16-Byte-Blöcke
  BlockIndex: Integer;                  // Index des aktuellen Blocks
  Offset: Integer;                      // Offset im Byte-Array
  InBlock, OutBlock: TByteArray16;      // Eingabe- und Ausgabe-Block
  I: Integer;                           // Laufvariable
begin
  Result := nil;                        // Initialisiert das Ergebnis

  DataLen := Length(CipherData);        // Ermittelt die Länge der Cipher-Daten

  if DataLen = 0 then                   // Nichts zu entschlüsseln
    Exit;

  if (DataLen mod 16) <> 0 then         // ECB erwartet Vielfaches von 16
    raise Exception.Create('AES256DecryptECB: Datenlänge muss ein Vielfaches von 16 sein.');

  NumBlocks := DataLen div 16;          // Anzahl Blöcke berechnen
  SetLength(Result, DataLen);           // Ergebnis bekommt gleiche Länge wie CipherData

  Offset := 0;                          // Startoffset

  for BlockIndex := 0 to NumBlocks - 1 do
  begin
    // 1. 16 Bytes aus CipherData in InBlock kopieren
    for I := 0 to 15 do
      InBlock[I] := CipherData[Offset + I];

    // 2. Block entschlüsseln
    AES256DecryptBlock(InBlock, OutBlock, Context);

    // 3. Entschlüsselten Block ins Ergebnis kopieren
    for I := 0 to 15 do
      Result[Offset + I] := OutBlock[I];

    Inc(Offset, 16);                    // Offset für den nächsten Block erhöhen
  end;
end;

end.
