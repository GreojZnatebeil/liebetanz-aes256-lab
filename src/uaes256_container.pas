unit uAES256_Container;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, uAES256;

type
  TAESContainerMode = (acmECB, acmCBC);

function BuildContainerBytes(const CipherBytes: TBytes;
  Mode: TAESContainerMode; const IV: TByteArray16): TBytes;

function ParseContainerBytes(const Container: TBytes;
  out CipherBytes: TBytes; out Mode: TAESContainerMode; out IV: TByteArray16): Boolean;

function SaveContainerToFile(const FileName: string; const Container: TBytes): Boolean;
function LoadContainerFromFile(const FileName: string; out Container: TBytes): Boolean;
//function GenerateRandomIV(out IV: TByteArray16): Boolean;
function GenerateRandomIV(out IV: TByteArray16): Boolean;
implementation

const
  // 8 Bytes Magic: "LAES256" + #0
  CONTAINER_MAGIC: array[0..7] of Byte = (
    Ord('L'), Ord('A'), Ord('E'), Ord('S'), Ord('2'), Ord('5'), Ord('6'), 0
  );

  // Untyped consts -> garantiert "case label"-tauglich in FPC 3.2.2
  CONTAINER_VERSION = 1;
  MODE_ECB = 1;
  MODE_CBC = 2;


  function GenerateRandomIV(out IV: TByteArray16): Boolean;
  var

    I: Integer;
    FS: TFileStream;
    BytesRead: LongInt;
   const
  ZERO_IV: TByteArray16 = (
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

  begin
    Result := False;
      IV := ZERO_IV;
  try
    FS := TFileStream.Create('/dev/urandom', fmOpenRead or fmShareDenyNone);
    try
      BytesRead := FS.Read(IV[0], SizeOf(IV));
      Result := (BytesRead = SizeOf(IV));
      if Result then
        Exit;
    finally
      FS.Free;
    end;
  except
    // Ignorieren -> Fallback unten
  end;

  // 2) Fallback (Demo/Notfall, nicht kryptografisch stark)
  Randomize;
  for I := 0 to High(IV) do
    IV[I] := Byte(Random(256));
  Result := True;
end;




procedure WriteUInt32LE(var Buf: TBytes; Offset: Integer; Value: LongWord);
  {
  ============================================================================
  WriteUInt32LE - Schreibt 32-Bit-Wert als Little-Endian in Byte-Array
  ============================================================================

  ZWECK:
  Konvertiert einen 32-Bit-Wert in 4 Bytes (Little-Endian Format) und
  schreibt sie an eine bestimmte Position im Byte-Array.

  Little-Endian: Niedrigstwertiges Byte zuerst
  Beispiel: 0x12345678 → [78, 56, 34, 12]

  ============================================================================
}

begin
  Buf[Offset + 0] := Byte(Value and $FF);
  Buf[Offset + 1] := Byte((Value shr 8) and $FF);
  Buf[Offset + 2] := Byte((Value shr 16) and $FF);
  Buf[Offset + 3] := Byte((Value shr 24) and $FF);
end;

function ReadUInt32LE(const Buf: TBytes; Offset: Integer): LongWord;
{
  ============================================================================
  ReadUInt32LE - Liest 32-Bit-Wert aus Byte-Array (Little-Endian)
  ============================================================================

  ZWECK:
  Rekonstruiert einen 32-Bit-Wert aus 4 Bytes im Little-Endian Format.
  Umkehrung von WriteUInt32LE.

  ============================================================================
}
begin
  Result :=
    LongWord(Buf[Offset + 0]) or
    (LongWord(Buf[Offset + 1]) shl 8) or
    (LongWord(Buf[Offset + 2]) shl 16) or
    (LongWord(Buf[Offset + 3]) shl 24);
end;

function ModeToByte(Mode: TAESContainerMode): Byte;
{
  ============================================================================
  ModeToByte / ByteToMode - Konvertierung Modus ↔ Byte
  ============================================================================

  ZWECK:
  Konvertiert zwischen TAESContainerMode Enum und Byte-Wert.
  Für Speicherung im Container-Header.

  MODE_ECB = 1, MODE_CBC = 2

  ============================================================================
}
begin
  case Mode of
    acmECB: Result := MODE_ECB;
    acmCBC: Result := MODE_CBC;
  else
    Result := MODE_ECB;
  end;
end;

function ByteToMode(B: Byte; out Mode: TAESContainerMode): Boolean;
begin
  Result := True;
  case B of
    MODE_ECB: Mode := acmECB;
    MODE_CBC: Mode := acmCBC;
  else
    Result := False;
  end;
end;

function BuildContainerBytes(const CipherBytes: TBytes;
  Mode: TAESContainerMode; const IV: TByteArray16): TBytes;
{
  ============================================================================
  BuildContainerBytes - Erstellt Container-Byteformat
  ============================================================================

  ZWECK:
  Verpackt verschlüsselte Daten in ein standardisiertes Container-Format:

  CONTAINER-STRUKTUR (32 Bytes Header + Cipher):
  [0..7]   Magic: "LAES256\0" (8 Bytes)
  [8]      Version: 1
  [9]      Modus: 1=ECB, 2=CBC
  [10..11] Reserved: 0x00 0x00
  [12..27] IV: 16 Bytes (bei ECB: Nullen)
  [28..31] Cipher-Länge (Little-Endian)
  [32..]   Verschlüsselte Daten

  WARUM CONTAINER?
  - Selbst-dokumentierend (enthält Modus und IV)
  - Versionierung möglich
  - Einfach erweiterbar

  ============================================================================
}
const
  // Header:
  // Magic 8 + Version 1 + Mode 1 + Reserved 2 + IV 16 + CipherLen 4 = 32 Bytes
  HEADER_LEN = 32;
var
  HeaderBytes: TBytes;
  CipherLen: LongWord;
  I: Integer;
  ModeByte: Byte;
  LocalIV: TByteArray16;
begin
  HeaderBytes := nil;
  Result := nil;
   LocalIV[0]:=0;
  // IV definiert machen (bei ECB: Nullen)


  FillChar(LocalIV, SizeOf(LocalIV), 0);

if Mode = acmCBC then  LocalIV := IV;


  CipherLen := LongWord(Length(CipherBytes));
  ModeByte := ModeToByte(Mode);

  SetLength(HeaderBytes, HEADER_LEN);

  // Magic "LAES256\0"
  for I := 0 to 7 do
    HeaderBytes[I] := CONTAINER_MAGIC[I];

 // Version, Modus, Reserved
  HeaderBytes[8] := Byte(CONTAINER_VERSION);
  HeaderBytes[9] := ModeByte;
  HeaderBytes[10] := 0;
  HeaderBytes[11] := 0;

  // IV (16 Bytes)
  for I := 0 to 15 do
    HeaderBytes[12 + I] := LocalIV[I];

  // Cipher-Länge
  WriteUInt32LE(HeaderBytes, 28, CipherLen);

  // Zusammenfügen: Header + Cipher
  SetLength(Result, HEADER_LEN + Length(CipherBytes));

  // Header kopieren
  Move(HeaderBytes[0], Result[0], HEADER_LEN);

  // Cipher kopieren
  if Length(CipherBytes) > 0 then
    Move(CipherBytes[0], Result[HEADER_LEN], Length(CipherBytes));
end;

function ParseContainerBytes(const Container: TBytes;
  out CipherBytes: TBytes; out Mode: TAESContainerMode; out IV: TByteArray16): Boolean;

{
  ============================================================================
  ParseContainerBytes - Parst Container und extrahiert Daten
  ============================================================================

  ZWECK:
  Liest Container-Format und extrahiert:
  - Verschlüsselte Daten
  - Modus (ECB/CBC)
  - IV

  VALIDIERUNG:
  - Prüft Magic "LAES256\0"
  - Prüft Version
  - Prüft Längenplausibilität

  ============================================================================
}
const
  HEADER_LEN = 32;
var
  I: Integer;
  Version: Byte;
  ModeByte: Byte;
  CipherLen: LongWord;
  TotalLen: Integer;
begin
  CipherBytes := nil;
  Mode := acmECB;
  IV[0]:=0;
  FillChar(IV, SizeOf(IV), 0);


  Result := False;

  TotalLen := Length(Container);
  if TotalLen < HEADER_LEN then Exit;

  // Magic prüfen
  for I := 0 to 7 do
    if Container[I] <> CONTAINER_MAGIC[I] then Exit;

  Version := Container[8];
  if Version <> Byte(CONTAINER_VERSION) then Exit;

  ModeByte := Container[9];
  if not ByteToMode(ModeByte, Mode) then Exit;

  // IV lesen
  for I := 0 to 15 do
    IV[I] := Container[12 + I];

  CipherLen := ReadUInt32LE(Container, 28);

   // Robustheit: erst prüfen, dann casten
   if CipherLen > LongWord(High(Integer)) then Exit;

   // Plausibilität
   if (HEADER_LEN + Integer(CipherLen)) > TotalLen then Exit;

   SetLength(CipherBytes, Integer(CipherLen));
   if CipherLen > 0 then
     Move(Container[HEADER_LEN], CipherBytes[0], Integer(CipherLen));




  Result := True;
end;

function SaveContainerToFile(const FileName: string; const Container: TBytes): Boolean;
 {
  ============================================================================
  SaveContainerToFile / LoadContainerFromFile - Datei-I/O
  ============================================================================

  ZWECK:
  Speichert/Lädt Container-Bytes in/aus Datei.
  Einfache Wrapper um TFileStream.

  ============================================================================
}
var
  FS: TFileStream;
begin
  Result := False;
  try
    FS := TFileStream.Create(FileName, fmCreate);
    try
      if Length(Container) > 0 then
        FS.WriteBuffer(Container[0], Length(Container));
    finally
      FS.Free;
    end;
    Result := True;
  except
    Result := False;
  end;
end;

function LoadContainerFromFile(const FileName: string; out Container: TBytes): Boolean;
var
  FS: TFileStream;
  Size: Int64;
begin
  Container := nil;
  Result := False;

  if not FileExists(FileName) then Exit;

  try
    FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
      Size := FS.Size;
      if Size > High(Integer) then Exit;

      SetLength(Container, Size);
      FS.ReadBuffer(Container[0], Size);


    finally
      FS.Free;
    end;
    Result := True;
  except
    Container := nil;
    Result := False;
  end;
end;

end.

