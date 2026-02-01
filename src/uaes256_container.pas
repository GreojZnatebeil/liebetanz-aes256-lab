unit uAES256_Container;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, uAES256;
  // uAES256 liefert den AES-Kern (z.B. TByteArray16) – dieser Container baut darauf auf.
  // Classes/SysUtils: Datei-I/O, Exceptions, Streams, Hilfsfunktionen.

type
  TAESContainerMode = (acmECB, acmCBC);
  // Container-internes Modus-Enum: bewusst klein gehalten (nur die Modi, die das Projekt aktuell kann).
  // DIDAKTIK: Der Container speichert nicht „nur Ciphertext“, sondern auch Kontext (Modus + ggf. IV),
  // damit spätere Entschlüsselung reproduzierbar ist.

function BuildContainerBytes(const CipherBytes: TBytes;
  Mode: TAESContainerMode; const IV: TByteArray16): TBytes;
  // Baut aus CipherBytes + Metadaten (Mode/IV) eine Bytefolge im Containerformat.
  // DIDAKTIK: „Speichern“ bedeutet in der Praxis fast immer: Nutzdaten + Header/Metadaten.
  // Typische Fehlerquelle: Modus/IV nicht mitspeichern → später keine korrekte Entschlüsselung möglich.

function ParseContainerBytes(const Container: TBytes;
  out CipherBytes: TBytes; out Mode: TAESContainerMode; out IV: TByteArray16): Boolean;
  // Zerlegt/validiert einen Container:
  // - prüft Magic/Version/Längen
  // - extrahiert Mode, IV, CipherBytes
  // Boolean als Ergebnis: Parser kann sauber „Format ungültig/beschädigt“ signalisieren,
  // ohne sofort Exceptions erzwingen zu müssen (didaktisch gut für kontrollierte Fehlerpfade).

function SaveContainerToFile(const FileName: string; const Container: TBytes): Boolean;
  // Kapselt Datei-Schreibzugriff (I/O) – getrennt von Kryptologik/Containeraufbau.

function LoadContainerFromFile(const FileName: string; out Container: TBytes): Boolean;
  // Kapselt Datei-Lesezugriff (I/O) – liefert Rohbytes für ParseContainerBytes.

function GenerateRandomIV(out IV: TByteArray16): Boolean;
  // Erzeugt einen IV für CBC (16 Byte).
  // DIDAKTIK: IV muss nicht geheim sein, aber sollte pro Nachricht einzigartig und idealerweise
  // zufällig/unvorhersehbar sein, um Muster/Angriffe zu erschweren (CBC-Startwert).
implementation

const
  // 8 Bytes Magic: "LAES256" + #0
  // DIDAKTIK:
  // - Ein „Magic Header“ ist eine Signatur am Dateianfang, die hilft zu erkennen:
  //   „Ist das überhaupt unser Format?“
  // - Vorteil: Frühe, eindeutige Fehlererkennung statt „irgendwie parsen“ und später crashen.
  // - Die Null (#0) am Ende macht die Sequenz robust als C-String/Marker und hält Länge konstant.
  CONTAINER_MAGIC: array[0..7] of Byte = (
    Ord('L'), Ord('A'), Ord('E'), Ord('S'), Ord('2'), Ord('5'), Ord('6'), 0
  );

  // Untyped consts -> garantiert "case label"-tauglich in FPC 3.2.2
  // HINWEIS (FPC-Details / typische Stolperfalle):
  // - In FreePascal können typisierte Konstanten (z.B. Byte/Word) je nach Kontext bei case-of
  //   unerwartet Probleme machen (Range/Typkompatibilität).
  // - „Untyped const“ zwingt FPC, diese Werte als reine Konstanten zu behandeln, die zuverlässig
  //   als case labels funktionieren (besonders wichtig, wenn du beim Parsen ein Mode-Byte ausliest).
  CONTAINER_VERSION = 1;
  // Versionierung ist Best Practice: erlaubt später Formatänderungen (z.B. zusätzliche Felder),
  // ohne alte Dateien unlesbar zu machen. Parser kann je nach Version anders reagieren.

  MODE_ECB = 1;
  MODE_CBC = 2;
  // DIDAKTIK:
  // - Diese Werte sind die „On-Disk“-Repräsentation (Byte/Integer) im Container.
  // - Warum nicht direkt TAESContainerMode speichern?
  //   → On-Disk-Format soll stabil und explizit sein (unabhängig von Enum-Ordinals/Compiler-Details).
  // Typische Fehlerquelle: Enum-Reihenfolge ändern → plötzlich andere Werte auf Platte.

 // MODE_CTR =3;  // ist in Vorbereitung
 // MODE_GCM =4;  // ist in Vorbereitung
 // HINWEIS: Sobald du neue Modi einführst, MUSS ParseContainerBytes sauber „unbekannte Modi“
 // behandeln (z.B. False zurückgeben), sonst entstehen gefährliche Fehlinterpretationen.


 function GenerateRandomIV(out IV: TByteArray16): Boolean;
  {
  ============================================================================
  FUNKTION: GenerateRandomIV
  ============================================================================
  TITEL/NAME
  - GenerateRandomIV – Erzeugt einen 16-Byte Initialization Vector (IV) für AES-CBC

  ZWECK
  - Erzeugt ein 16 Byte langes IV (entspricht der AES-Blockgröße) zur Verwendung
    in CBC-Verschlüsselung.
  - Primäres Ziel: kryptographisch starke Zufallsbytes aus dem Betriebssystem
    beziehen (/dev/urandom). Falls das nicht möglich ist, wird als Notlösung ein
    Fallback (Random()) verwendet.

  EIGENSCHAFTEN (stichpunktartig)
  - Output-Parameter: IV wird als TByteArray16 direkt gefüllt (kein Rückgabe-Array nötig).
  - Pessimistischer Start: Result := False; IV := ZERO_IV (definierter Zustand, auch bei Fehler).
  - Methode 1 (bevorzugt): /dev/urandom via TFileStream, liest exakt 16 Bytes.
  - Methode 2 (Fallback): Randomize + Random(256) für 16 Bytes (NICHT kryptographisch sicher).
  - Ressourcen-sicher: TFileStream wird im finally immer freigegeben.

  VERWENDUNG IM PROJEKT
  - Vor einer CBC-Verschlüsselung aufrufen, um einen frischen IV zu erzeugen.
  - Der IV wird anschließend zusammen mit dem Ciphertext gespeichert (z.B. im Container),
    da CBC ohne den ursprünglichen IV nicht korrekt entschlüsselt werden kann.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - CBC erfordert einen IV, der pro Nachricht eindeutig sein muss; idealerweise zufällig/
    unvorhersehbar. Der IV ist nicht geheim, aber Wiederverwendung (besonders mit gleichem Key)
    ist gefährlich, weil sie Muster über Nachrichtenanfänge sichtbar machen kann.
  - /dev/urandom ist auf Unix/Linux/macOS die übliche Quelle für kryptographisch starke Bytes.
  - Der Random()-Fallback ist nur für Lehr-/Notfallbetrieb geeignet (vorhersagbarer PRNG).
    In produktiver Software sollte unter Windows eine OS-CSPRNG-API genutzt werden.
  - Hinweis: Ohne Integritätsschutz (MAC/AEAD) bleibt CBC manipulierbar; IV-Handling ist nur ein Teil.

  REFERENZEN / HINWEISE
  - NIST SP 800-38A: Anforderungen/Einordnung von IVs für CBC.
  - AES-Kontext: NIST FIPS 197 (AES / Rijndael von Joan Daemen & Vincent Rijmen).
  - OS-Zufallsquellen: Unix /dev/urandom; Windows: BCryptGenRandom/RtlGenRandom (Konzeptuell).
  ============================================================================
}
  var

    I: Integer;          // Laufvariable für Fallback-Schleife (0..15)
    FS: TFileStream;      // Stream zum Lesen aus /dev/urandom (OS-CSPRNG auf Unix-Systemen)
    BytesRead: LongInt;   // Anzahl der tatsächlich gelesenen Bytes (muss exakt 16 sein)
   const
     // Null-IV als definierte Initialisierung (wird im Erfolgsfall überschrieben)
     // DIDAKTIK: ZERO_IV ist KEIN „guter IV“, sondern ein Platzhalter, damit IV niemals „undefiniert“ ist.
     // Typische Fehlerquelle: uninitialisierte Arrays führen zu schwer nachvollziehbaren Zuständen.
  ZERO_IV: TByteArray16 = (
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

  begin
    Result := False;    // Initialisierung: pessimistisch starten (erst nach Erfolg True setzen)
      IV := ZERO_IV;    // definierter Zustand: falls alles fehlschlägt, ist IV nicht „zufällig-müllig“

     // -------------------------------------------------------------------------
     // METHODE 1: /dev/urandom (Linux/Unix - kryptographisch sicher)
     // ------------------------------------------------------------------------
     // Warum zuerst diese Methode?
     // - /dev/urandom liefert Bytes aus dem Kernel-CSPRNG (cryptographically secure PRNG).
     // - Das ist (auf Unix-Systemen) der Standardweg für kryptographische Nonces/IVs.
     // Typische Fehlerquelle: weniger als 16 Bytes lesen oder Fehler still ignorieren und trotzdem „OK“ melden.

  try
    // Versuche /dev/urandom zu öffnen
    // Dies ist unter Linux/macOS/BSD die Standard-Zufallsquelle
    FS := TFileStream.Create('/dev/urandom', fmOpenRead or fmShareDenyNone);
    // fmShareDenyNone: andere Prozesse dürfen ebenfalls lesen – üblich und unkritisch für urandom.

    try
      // Lese genau 16 Bytes (SizeOf(IV)) direkt in das IV-Array
      // /dev/urandom liefert unbegrenzt kryptographisch starke Zufallsbytes
      BytesRead := FS.Read(IV[0], SizeOf(IV));
      // HINWEIS: FS.Read kann theoretisch weniger Bytes liefern (z.B. bei I/O-Problemen).
      // Deshalb folgt der explizite Vergleich mit SizeOf(IV) – wichtig, um Teilreads zu erkennen.

        // Prüfe, ob wirklich 16 Bytes gelesen wurden
      Result := (BytesRead = SizeOf(IV));
      // Typische Fehlerquelle: BytesRead mit 16 vergleichen, obwohl sich die Blockgröße ändern könnte.
      // Hier ist SizeOf(IV) korrekt, weil es immer der echte Array-Size entspricht (bei AES: 16).

      // Bei Erfolg: Funktion beenden (IV ist jetzt gefüllt)
      if Result then
        Exit; // Frühzeitiger Exit ist hier sinnvoll: Erfolgspfad endet sofort, Fallback wird übersprungen.
    finally
      // Stelle sicher, dass der FileStream IMMER geschlossen wird
      // Dies verhindert Ressourcen-Lecks
      FS.Free;
      // HINWEIS: Ohne finally könnte bei Exceptions ein Handle-Leak entstehen (schlecht in Langläufern/GUI).
    end;
  except
    // Falls /dev/urandom nicht verfügbar ist (z.B. unter Windows) oder
    // ein anderer Fehler auftritt, ignorieren wir die Exception und
    // verwenden den Fallback unten
    // (Exception wird stillschweigend behandelt)
    // HINWEIS (Qualität/Sicherheit): „stille“ Exceptions sind didaktisch ok, aber produktiv würde man
    // meist mindestens loggen, warum die sichere Quelle nicht verfügbar war.
  end;

  // -------------------------------------------------------------------------
  // METHODE 2: Fallback - Pascal Random() (NUR für Demo/Notfall!)
  // -------------------------------------------------------------------------
  // Dieser Code wird nur erreicht, wenn /dev/urandom fehlgeschlagen ist.
  // WARNUNG: Random() ist ein PRNG, in der Regel vorhersagbar (abhängig vom Seed),
  // daher NICHT für echte Kryptografie geeignet. Hier nur, um das Lehrprojekt
  // auch ohne OS-CSPRNG (z.B. unter Windows ohne zusätzliche API) lauffähig zu halten.

  // Initialisiere den Pseudo-Zufallsgenerator mit der aktuellen Zeit
  Randomize;
  // Typische Fehlerquelle: Randomize vergessen → gleiche „zufällige“ Sequenz bei jedem Start.

  for I := 0 to High(IV) do    // Fülle alle 16 Bytes des IV mit Pseudo-Zufallswerten
    IV[I] := Byte(Random(256));  // Random(256) liefert Werte 0..255
    // HINWEIS: Byte(...) stellt sicher, dass der Wertebereich 0..255 im Byte landet.
    // High(IV) ist 15 → genau 16 Iterationen (0..15). Off-by-one wäre hier fatal.

  // Fallback ist "erfolgreich" (aber nicht kryptographisch sicher!)
  Result := True;
  // HINWEIS (Qualität/Sicherheit): Diese True-Rückgabe bedeutet nur „IV wurde irgendwie gefüllt“.
  // Kryptographisch „sicher“ ist es im Fallback nicht. In produktivem Code würde man hier eher
  // Result := False setzen oder eine klarere Statusmeldung/Plattform-API nutzen.

  // Nach dieser Funktion:
  // - IV enthält 16 zufällige Bytes
  // - Unter Linux/macOS: Kryptographisch sicher von /dev/urandom
  // - Unter Windows: Pseudo-zufällig von Random() (nur für Tests!)
end;




procedure WriteUInt32LE(var Buf: TBytes; Offset: Integer; Value: LongWord);
  {
  ============================================================================
  PROZEDUR: WriteUInt32LE
  ============================================================================
  TITEL/NAME
  - WriteUInt32LE – Schreibt einen 32-Bit-Wert explizit im Little-Endian-Format in ein Byte-Array

  ZWECK
  - Zerlegt einen 32-Bit-Unsigned-Wert (LongWord) in vier einzelne Bytes und schreibt diese
    ab einer gegebenen Position (Offset) in ein TBytes-Array.
  - Wird im Containerformat genutzt, um feste Integer-Felder (z.B. Längen) plattformunabhängig
    abzulegen – unabhängig davon, ob die CPU intern Little- oder Big-Endian ist.

  EIGENSCHAFTEN (stichpunktartig)
  - Explizite Endianness: garantiert Little-Endian-Ausgabe (LSB zuerst).
  - Keine Speicher-/Format-Abhängigkeit: vermeidet „Move(Value, ...)“-Fallen.
  - Schneller, deterministischer Bit-Shift/Mask-Ansatz.
  - Keine Bounds-Checks: Aufrufer muss sicherstellen, dass Buf groß genug ist.

  VERWENDUNG IM PROJEKT
  - Typisch beim Container-Header: Längenfelder und andere 32-Bit-Werte werden an festen Offsets
    geschrieben (z.B. Cipher-Länge im Header).
  - Gegenstück beim Lesen: ReadUInt32LE(...) rekonstruiert aus 4 Bytes wieder den LongWord.

  SICHERHEIT/ EINORDNUNG
  - Diese Prozedur ist kein Kryptoschritt, aber extrem wichtig für *Format-Korrektheit*.
  - Fehler in Offsets/Endianness führen zu „kaputten“ Containerdateien, die nicht mehr sauber
    geparst werden können – selbst wenn AES korrekt implementiert ist.
  - Da keine Bounds-Checks erfolgen, kann ein falscher Offset/zu kleiner Buffer zu
    Speicherzugriffsfehlern führen (Access Violation). In Produktcode würde man hier
    oft prüfen und ggf. eine Exception werfen.

  REFERENZEN / HINWEISE
  - Begriff: Endianness (Little-Endian vs Big-Endian).
  - Viele Dateiformate nutzen Little-Endian; Netzwerk-Byte-Order ist oft Big-Endian.
  - Merksatz: „Writer und Reader müssen denselben Byte-Vertrag einhalten.“
  ============================================================================
   ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Vorbedingungen und typische Fehlerquellen
  ----------------------------------------------------------------------------

  VORAUSSETZUNGEN / VERTRAG DIESER PROZEDUR (Preconditions)
  - Offset ist 0-basiert (wie TBytes üblich) und bezeichnet das *erste* Byte,
    an das geschrieben wird.
  - Im Byte-Array müssen ab Offset mindestens 4 Bytes Platz vorhanden sein:
      (Offset >= 0) und (Offset + 3 < Length(Buf))
  - Diese Prozedur erweitert Buf NICHT. Das Array muss vorher passend dimensioniert sein
    (z.B. SetLength(Buf, ...) im Container-Builder).

  TYPISCHE FEHLERQUELLEN
  - Off-by-one in Offset-Rechnung (z.B. 27 statt 28) → Feld überschreibt Nachbarfeld im Header.
  - Zu kleiner Buffer → schreibt außerhalb des Arrays → Laufzeitfehler/undefiniertes Verhalten.
  - Endianness-Verwechslung: Reader erwartet Big-Endian, Writer schreibt Little-Endian (oder umgekehrt).
  - Versehentlich signed statt unsigned: Für Längenfelder sind negative Werte unsinnig → LongWord ist korrekt.

  WARUM 32 BIT (UInt32) HIER SINNVOLL SIND
  - 32 Bit reichen für viele Lehr-/Praxisfälle (bis ~4 GiB).
  - Als unsigned sind sie logisch korrekt für Längen und Größenangaben.

  MERKSATZ FÜR STUDIERENDE
  - „Ein Containerformat ist ein Vertrag: Byte-Reihenfolge + Feld-Offsets müssen exakt stimmen.“
  ----------------------------------------------------------------------------

}

begin
  // Byte 0 (LSB): Niedrigstwertiges Byte
  // - Value and $FF maskiert exakt die unteren 8 Bits (Bits 0..7).
  // - Byte(...) stellt sicher, dass wirklich nur 0..255 geschrieben werden.
  Buf[Offset + 0] := Byte(Value and $FF);

  // Byte 1: Bits 8-15
  // - (Value shr 8) schiebt das zweite Byte nach unten in die Bits 0..7,
  //   anschließend wieder maskieren mit $FF.
  Buf[Offset + 1] := Byte((Value shr 8) and $FF);

  // Byte 2: Bits 16-23
  // - Analog: 16 Bits nach rechts schieben, dann die unteren 8 Bits übernehmen.
  Buf[Offset + 2] := Byte((Value shr 16) and $FF);

  // Byte 3 (MSB): Höchstwertiges Byte (Bits 24-31)
  // - 24 Bits nach rechts schieben → das ehemals höchste Byte landet unten und wird maskiert.
  Buf[Offset + 3] := Byte((Value shr 24) and $FF);

  // Nach dieser Prozedur gilt:
  // - Buf[Offset..Offset+3] enthält Value im Little-Endian-Format.
  //   Beispiel: Value=$12345678 → [ $78, $56, $34, $12 ]
  //
  // HINWEIS: Diese Prozedur macht absichtlich keine Plausibilitätsprüfung,
  // weil sie oft in sehr „engen“ Schreibschleifen (Header-Builder) verwendet wird.
  // Der sichere Umgang damit liegt in der Verantwortung des Aufrufers (korrekte Buffergröße/Offsets).
end;

function ReadUInt32LE(const Buf: TBytes; Offset: Integer): LongWord;
{
  ============================================================================
  FUNKTION: ReadUInt32LE
  ============================================================================
  TITEL/NAME
  - ReadUInt32LE – Liest einen 32-Bit-Unsigned-Wert (LongWord) aus einem Byte-Array (Little-Endian)

  ZWECK
  - Rekonstruiert einen 32-Bit-Wert aus vier aufeinanderfolgenden Bytes im Little-Endian-Format.
  - Diese Funktion ist die exakte Umkehrung von WriteUInt32LE(...) und wird beim Parsen des
    Container-Headers benötigt (z.B. um Längenfelder zuverlässig zu lesen).

  EIGENSCHAFTEN (stichpunktartig)
  - Explizite Endianness: interpretiert Bytes immer als Little-Endian (LSB zuerst).
  - Plattformunabhängig: funktioniert identisch auf Little- und Big-Endian-CPUs.
  - Low-Level-Primitive: klein/schnell, ohne eigene Bounds-Checks.
  - Sichere Bitkombination: nutzt shl + or (keine Übertragsprobleme wie bei Addition).

  VERWENDUNG IM PROJEKT
  - In ParseContainerBytes(...) zum Auslesen fester 32-Bit-Felder (z.B. Cipher-Länge).
  - Symmetrie-Prinzip:
      ReadUInt32LE(Buf, Off) liefert genau den Wert, der vorher mit
      WriteUInt32LE(Buf, Off, Value) geschrieben wurde.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Nicht kryptografisch, aber kritisch für die Robustheit des Container-Parsers:
    falsche Endianness oder falsche Offsets führen zu komplett falschen Längen/Offsets.
  - Keine Bounds-Checks: falscher Offset oder zu kleines Buf kann zu Access Violations führen.
    In einem „defensiven Parser“ prüft man daher vor dem Lesen, ob genügend Bytes vorhanden sind.
  - Merksatz: „ReadUInt32LE liest blind – der Parser muss die Eingabe validieren.“

  REFERENZEN / HINWEISE
  - Begriff: Endianness (Little-Endian vs Big-Endian).
  - Containerformat: feste Offsets + feste Byte-Reihenfolge = „Vertrag“ zwischen Writer und Reader.
  - AES-Kontext (Einordnung, nicht direkt Endianness): NIST FIPS 197; Modi: NIST SP 800-38A.
  ============================================================================
   ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Typische Fehlerquellen beim Parsen
  ----------------------------------------------------------------------------
  - Off-by-one: Offset um 1 Byte verschoben → alle Felder danach „sehen falsch aus“.
  - Endianness verwechselt: 0x00000400 (1024) wird als 0x00040000 (262144) gelesen.
  - Fehlender Cast: Byte shl 8 würde in 8 Bit überlaufen → deshalb LongWord(...) vor dem Shift.
  - Fehlende Längenprüfung: Zugriff außerhalb von Buf → Laufzeitfehler.
  ----------------------------------------------------------------------------
}
begin
  // Kombiniere 4 Bytes zu einem 32-Bit-Wert (Little-Endian)
  // Little-Endian bedeutet: niedrigstwertiges Byte steht zuerst im Buffer.
  //
  // Wichtig: Jedes Buf[...] ist ein Byte (8 Bit). Damit shl 8/16/24 korrekt auf 32 Bit arbeitet,
  // wird jedes Byte vor dem Shiften zu LongWord gecastet. Ohne diesen Cast wären Überläufe möglich.

  Result :=
    LongWord(Buf[Offset + 0]) or             // Byte 0: Bits 0-7  (LSB, keine Verschiebung)
    (LongWord(Buf[Offset + 1]) shl 8) or     // Byte 1: Bits 8-15 (8 Bit nach links)
    (LongWord(Buf[Offset + 2]) shl 16) or    // Byte 2: Bits 16-23 (16 Bit nach links)
    (LongWord(Buf[Offset + 3]) shl 24);      // Byte 3: Bits 24-31 (MSB, 24 Bit nach links)

  // Nach dieser Funktion:
  // - Result enthält den rekonstruierten 32-Bit-Wert.
  // - Beispiel: Buf=[ $78, $56, $34, $12 ] → Result=$12345678
  //
  // HINWEIS (Quality-Gate): Keine Bounds-Checks hier – das ist Absicht.
  // Diese Funktion ist ein Low-Level-Baustein; ParseContainerBytes(...) sollte vorab sicherstellen:
  //   (Offset >= 0) und (Offset + 3 < Length(Buf)).
end;

function ModeToByte(Mode: TAESContainerMode): Byte;

{
  ============================================================================
  FUNKTION: ModeToByte
  ============================================================================
  TITEL/NAME
  - ModeToByte – Konvertiert TAESContainerMode (Enum) in einen stabilen Byte-Wert fürs Dateiformat

  ZWECK
  - Wandelt den im Programm typsicheren Enum-Wert (acmECB / acmCBC) in einen
    expliziten Byte-Code (MODE_ECB / MODE_CBC) um, der im Container-Header
    gespeichert werden kann.
  - Damit wird der verwendete Betriebsmodus zusammen mit Ciphertext/IV abgelegt,
    sodass beim Laden klar ist, wie zu entschlüsseln ist.

  EIGENSCHAFTEN (stichpunktartig)
  - Stabile On-Disk-Repräsentation: nutzt feste Konstanten (MODE_ECB=1, MODE_CBC=2),
    statt Ord(Mode) direkt zu serialisieren.
  - Erweiterbar: case-Struktur ist leicht um weitere Modi (CTR/GCM) ergänzbar.
  - Defensiver Fallback: liefert bei unerwarteten Werten einen definierten Code.

  VERWENDUNG IM PROJEKT
  - Wird beim Containeraufbau (BuildContainerBytes) genutzt, um das Mode-Feld im Header
    zu setzen (z.B. Header[9]).
  - Gegenstück beim Parsen: ByteToMode(...) interpretiert den gespeicherten Byte-Code
    wieder als TAESContainerMode.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Das Speichern des Modus ist funktional notwendig, aber kein Sicherheitsmerkmal.
  - Wichtiger als der Moduscode selbst ist die Parser-Entscheidung:
    Unbekannte Moduswerte sollten beim Laden typischerweise als Fehler behandelt werden,
    damit man nicht „still“ mit falschen Parametern entschlüsselt.
  - Der hier gewählte Fallback ist defensiv, sollte aber im Normalbetrieb nie greifen
    (Enum ist typsicher – außer durch explizite Casts oder Speicherfehler).

  REFERENZEN / HINWEISE
  - NIST FIPS 197: AES (Rijndael von Joan Daemen & Vincent Rijmen) – definiert den Blockcipher.
  - NIST SP 800-38A: ECB/CBC und weitere Modi – separat vom AES-Kern beschrieben.
  - Merksatz: „Enums sind typsicher im Code, aber nicht automatisch stabil als Dateiformat.“
  ============================================================================
   ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Warum explizite Byte-Werte im Containerformat wichtig sind
  ----------------------------------------------------------------------------
  - Ein Containerformat ist ein „Vertrag“ zwischen Writer und Reader – auch über Versionen hinweg.
  - Ord(Mode) ist zwar bequem, kann aber bei späteren Enum-Änderungen inkompatibel werden
    (neue Einträge, Reihenfolgeänderungen).
  - Mit MODE_ECB/MODE_CBC sind die Werte unabhängig von Compiler/Enum-Layout stabil.
  ----------------------------------------------------------------------------
}
begin
  // case-Struktur ist hier bewusst gewählt:
  // - selbstdokumentierend (klar: welcher Modus → welcher Bytecode)
  // - leicht erweiterbar (CTR/GCM später)
  // - kontrolliert: jeder Modus bekommt einen expliziten, stabilen Wert
  case Mode of
    acmECB: Result := MODE_ECB; // 1 → „ECB“ im Containerheader
    acmCBC: Result := MODE_CBC; // 2 → „CBC“ im Containerheader
  else
     // Fallback für ungültige Werte (sollte nie eintreten)
    // Gibt ECB als "sichersten" Fallback zurück
    // HINWEIS (Quality-Gate / Robustheit):
    // - Dieser Else-Zweig schützt gegen „kaputte“ Eingaben (z.B. durch Casts wie TAESContainerMode(99)).
    // - In einem strengen Parser würde man unbekannte Werte eher als Fehler behandeln, statt „still“
    //   auf ECB zu fallen. Hier geht es aber um das Schreiben eines definierten Bytecodes.
    Result := MODE_ECB;
  end;
end;

function ByteToMode(B: Byte; out Mode: TAESContainerMode): Boolean;

{
  ============================================================================
  FUNKTION: ByteToMode
  ============================================================================
  TITEL/NAME
  - ByteToMode – Konvertiert den im Container gespeicherten Modus-Bytecode zurück in TAESContainerMode

  ZWECK
  - Interpretiert einen Byte-Wert aus dem Container-Header (z.B. Header[9]) als
    Verschlüsselungsmodus und setzt daraus den passenden Enum-Wert (acmECB/acmCBC).
  - Liefert zusätzlich einen Boolean zurück, damit der Aufrufer erkennen kann,
    ob der gelesene Bytecode gültig/unterstützt ist.

  EIGENSCHAFTEN (stichpunktartig)
  - Validierender Decoder: akzeptiert nur bekannte Werte (MODE_ECB/MODE_CBC).
  - Fehler ohne Exceptions: ungültige Werte → Result := False (typisch fürs Parsing).
  - Saubere Symmetrie zu ModeToByte(...): stabile On-Disk-Codes ↔ typsicheres Enum im Code.
  - Achtung „out“-Semantik: Mode ist nur bei Result=True als gültig zu betrachten.

  VERWENDUNG IM PROJEKT
  - In ParseContainerBytes(...) beim Einlesen des Container-Headers:
    * Magic/Version prüfen
    * Mode-Byte lesen
    * ByteToMode(...) aufrufen → bei False Container ablehnen
  - Ergebnis steuert später, ob ECB- oder CBC-Entschlüsselung verwendet wird.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Das ist kein Kryptoschritt, aber ein sicherheitsrelevanter Parser-Baustein:
    Unbekannte/kaputte Moduswerte dürfen nicht „still“ akzeptiert werden, sonst
    könnte mit falschen Parametern entschlüsselt werden (Fehlinterpretation).
  - Boolean-Rückgabe ist defensives Parsing: korrupt/manipuliert/Version-Mismatch
    wird als ungültig erkannt, ohne Exception-Overhead.

  REFERENZEN / HINWEISE
  - AES-Kern: NIST FIPS 197 (Rijndael von Joan Daemen & Vincent Rijmen).
  - Modi: NIST SP 800-38A (ECB/CBC/CTR …).
  - Container-Design: „Stabile Codes“ statt Ord(Enum) im Dateiformat.
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: „out“-Parameter und warum der Boolean die Wahrheit ist
  ----------------------------------------------------------------------------
  - In Delphi/FPC ist „out“ nicht identisch zu „var“:
    Der Compiler darf den out-Parameter vor dem Funktionskörper auf einen
    Defaultwert setzen. Deshalb gilt:
      Mode ist nur dann zuverlässig/definiert, wenn Result=True ist.
  - Merksatz: „out + Boolean“ ⇒ erst Boolean prüfen, dann out-Wert benutzen.
  ----------------------------------------------------------------------------
}
begin
  Result := True;     // Optimistisch auf True setzen (wird im else-Fall auf False korrigiert)
  // DIDAKTIK: Dieses Muster ist praktisch, weil der „Happy Path“ kurz bleibt und der Fehlerfall
  // nur im else behandelt wird.

  case B of
    MODE_ECB: Mode := acmECB;  // Byte-Wert 1 → ECB-Modus (kein IV nötig, Blockweise unabhängig)
    MODE_CBC: Mode := acmCBC;    // Byte-Wert 2 → CBC-Modus (IV nötig, Verkettung der Blöcke)
  else
     // Ungültiger Byte-Wert (nicht 1 oder 2)
    // Parser-Logik: Unbekannter Modus → Container ablehnen (z.B. korrupt, falsches Format, neue Version).
    // WICHTIG: Mode ist bei Result=False als „nicht gültig“ zu betrachten (out-Semantik!).
    Result := False;
  end;

  // Nach dieser Funktion:
  // - Bei gültigem B: Mode enthält den entsprechenden Enum-Wert, Result=True
  // - Bei ungültigem B: Result=False; Mode darf NICHT verwendet werden
  //   (er kann unverändert sein oder einen Defaultwert erhalten haben).
end;



function BuildContainerBytes(const CipherBytes: TBytes;
  Mode: TAESContainerMode; const IV: TByteArray16): TBytes;
{
  ============================================================================
  FUNKTION: BuildContainerBytes
  ============================================================================
  TITEL/NAME
  - BuildContainerBytes – Erstellt das Container-Byteformat (Header + Ciphertext)

  ZWECK
  - Verpackt die verschlüsselten Daten (CipherBytes) in ein fest definiertes Containerformat.
  - Der Container enthält alle Metadaten, die für das spätere Entschlüsseln nötig sind:
      * Magic (Format-Erkennung)
      * Version (Kompatibilität)
      * Modus (ECB/CBC)
      * IV (bei CBC relevant; bei ECB als Null-Placeholder)
      * Cipher-Länge (für Validierung/Extraktion)
  - Ergebnis ist ein zusammenhängendes Byte-Array: [Header][CipherBytes].

  EIGENSCHAFTEN (stichpunktartig)
  - Feste Header-Länge: 32 Bytes → einfaches, robustes Parsing (konstante Offsets).
  - Selbstbeschreibend: Magic + Version + Mode verhindern „Rateversuche“ beim Laden.
  - IV-Feld immer vorhanden: bei ECB nur Platzhalter (Nullen), bei CBC echter IV.
  - Längenfeld als UInt32 Little-Endian: plattformunabhängig, symmetrisch zu ReadUInt32LE.
  - Kein Integritätsschutz: Container ist „nur“ Transport-/Speicherformat, nicht manipulationssicher.

  VERWENDUNG IM PROJEKT
  - Wird in der GUI beim Speichern aufgerufen:
      Container := BuildContainerBytes(FCipherBytes, FCipherMode, FCipherIV);
      SaveContainerToFile(..., Container);
  - Gegenstück beim Laden:
      ParseContainerBytes(Container, Cipher, Mode, IV);
  - Didaktischer Nutzen: Schüler können den Container im Hex-Editor inspizieren und Header-Felder finden.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - CBC benötigt einen IV; dieser ist nicht geheim, muss aber pro Nachricht eindeutig/idealerweise zufällig sein.
  - ECB nutzt keinen IV; das IV-Feld ist hier nur ein Platzhalter für ein einheitliches Dateiformat.
  - WICHTIG: Dieser Container bietet ohne MAC/AEAD keine Integrität/Authentizität:
    Header/IV/Ciphertext können manipuliert werden (z.B. CBC Bit-Flipping, Padding-Fehler).
    Für echte Anwendungen: Encrypt-then-MAC (HMAC) oder AEAD (z.B. GCM).

  REFERENZEN / HINWEISE
  - NIST FIPS 197: AES (Rijndael von Joan Daemen & Vincent Rijmen).
  - NIST SP 800-38A: Betriebsmodi (ECB/CBC) + IV-Konzept.
  - NIST SP 800-38D: GCM (AEAD) als Beispiel für „Verschlüsselung + Authentifizierung“.
  - Format-Design: Magic + Versionierung + feste Offsets („Vertrag“ Writer ↔ Reader).
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Typische Fehlerquellen im Containerbau
  ----------------------------------------------------------------------------
  - Off-by-one bei Offsets (z.B. IV beginnt bei 12, Länge bei 28): 1 Byte Fehler → Parser „sieht“ Müll.
  - Endianness der Länge: WriteUInt32LE muss symmetrisch zu ReadUInt32LE sein.
  - IV-Wiederverwendung bei CBC: Funktion speichert IV korrekt, aber der Aufrufer muss IV pro Nachricht neu wählen.
  - Große Datenmengen: Hier wird alles in einem TBytes zusammengebaut (RAM); Streaming wäre skalierbarer.
  ----------------------------------------------------------------------------
  }
const
  // Header-Länge:
  // Magic(8) + Version(1) + Mode(1) + Reserved(2) + IV(16) + CipherLen(4) = 32 Bytes
  HEADER_LEN = 32;
var
  HeaderBytes: TBytes;        // Arbeitsbuffer für den 32-Byte Header (wird später in Result kopiert)
  CipherLen: LongWord;        // Länge der verschlüsselten Nutzdaten (UInt32 im Header, Little-Endian)
  I: Integer;                 // Laufvariable für kleine Kopierschleifen (Magic/IV)
  ModeByte: Byte;             // Modus als stabiler On-Disk-Code (MODE_ECB=1, MODE_CBC=2)
  LocalIV: TByteArray16;      // Lokale IV-Kopie: bei ECB Null-Bytes, bei CBC der echte IV
begin
  HeaderBytes := nil;          // HINWEIS: nicht zwingend nötig, aber definierter Startzustand (Debug/Lesbarkeit)
  Result := nil;               // HINWEIS (Quality-Gate): Result wird unten per SetLength neu allokiert und gefüllt.
   LocalIV[0]:=0;               // Compiler-Hint beruhigen
   // HINWEIS: Kein Kryptoschritt. Nur, um mögliche „uninitialisiert“-Warnungen bei statischen Analyzern zu vermeiden.
   // Direkt danach wird LocalIV vollständig mit FillChar überschrieben.

  // -------------------------------------------------------------------------
  // SCHRITT 1: IV vorbereiten
  // -------------------------------------------------------------------------
  // LocalIV zunächst mit Nullen füllen (wichtig für ECB)
   FillChar(LocalIV, SizeOf(LocalIV), 0);
   // DIDAKTIK: Einheitlicher Header-Aufbau:
   // - Das IV-Feld ist immer 16 Bytes vorhanden.
   // - Bei ECB ist es nur ein Platzhalter (ECB verwendet keinen IV).
   // - Bei CBC wird es mit dem echten IV befüllt, der für die Entschlüsselung nötig ist.

  // Bei CBC: Verwende den übergebenen IV
  // Bei ECB: LocalIV bleibt Null-Bytes (wird trotzdem gespeichert)
   if Mode = acmCBC then  LocalIV := IV;
   // Typische Fehlerquelle: IV nicht mitspeichern → CBC-Entschlüsselung scheitert oder liefert falschen Klartext.
   // WICHTIG: Die Sicherheit hängt davon ab, dass der Aufrufer pro Nachricht einen frischen IV erzeugt.

  // -------------------------------------------------------------------------
  // SCHRITT 2: Metadaten berechnen
  // -------------------------------------------------------------------------
  // Cipher-Länge und Modus-Byte ermitteln
  CipherLen := LongWord(Length(CipherBytes));
  // DIDAKTIK: CipherLen wird im Header abgelegt, damit der Parser plausibilisieren kann:
  // - Ist der Container lang genug?
  // - Passt die angegebene Länge zur tatsächlichen Dateigröße?
  // Typische Fehlerquelle: Signed/Unsigned-Mix – LongWord ist korrekt für Längen (keine negativen Werte).

  ModeByte := ModeToByte(Mode);
  // ModeToByte liefert stabile Werte für das Dateiformat (nicht Ord(Mode)).
  // Typische Fehlerquelle: Enum-Reihenfolge ändern → alte Dateien würden falsch interpretiert, wenn man Ord() speichert.

   // -------------------------------------------------------------------------
  // SCHRITT 3: Header-Array allokieren und füllen
  // -------------------------------------------------------------------------
  SetLength(HeaderBytes, HEADER_LEN);
  // HeaderBytes ist nun 32 Bytes groß. Alle Felder werden explizit gesetzt, damit kein „Restmüll“ bleibt.

 // Magic-Bytes "LAES256\0" (8 Bytes)
  for I := 0 to 7 do
    HeaderBytes[I] := CONTAINER_MAGIC[I];
  // Magic ist die Dateisignatur: schnelle Format-Erkennung („ist das unser Container?“).
  // Typische Fehlerquelle: falsche Magic → Parser lehnt ab (gewollt).

  // Version, Modus, Reserved
  HeaderBytes[8] := Byte(CONTAINER_VERSION);   // Version 1
  // Versionierung: erlaubt spätere Erweiterungen/Änderungen, ohne alte Dateien „blind“ falsch zu parsen.

  HeaderBytes[9] := ModeByte;                  // ECB=1 oder CBC=2
  // Modus ist nicht Teil des AES-Kerns (AES ist nur Blockcipher), sondern Teil des „Mode of Operation“.

  HeaderBytes[10] := 0;                        // Reserved (zukünftige Verwendung)
  HeaderBytes[11] := 0;                        // Reserved (zukünftige Verwendung)
  // Reserved-Bytes sind bewusst 0, damit spätere Parser/Versionen Flags definieren können.
  // Typische Fehlerquelle: uninitialisierte Reserved-Bytes → nicht reproduzierbare Header.

   // IV (16 Bytes) - bei ECB sind das Null-Bytes
  for I := 0 to 15 do
    HeaderBytes[12 + I] := LocalIV[I];
  // IV beginnt bei Offset 12 und hat 16 Bytes (AES-Blockgröße).
  // Typische Fehlerquelle: falscher Offset (z.B. 11/13) → alles danach verschiebt sich.

  // Cipher-Länge als Little-Endian (4 Bytes)
  WriteUInt32LE(HeaderBytes, 28, CipherLen);
  // Länge steht bei Offset 28..31. Little-Endian ist hier der definierte „Vertrag“.
  // Typische Fehlerquelle: Endianness verwechselt → Parser liest falsche Länge (z.B. 1024 ↔ 262144).

  // -------------------------------------------------------------------------
  // SCHRITT 4: Gesamtcontainer zusammensetzen
  // -------------------------------------------------------------------------
  // Allokiere Speicher: Header (32 Bytes) + Cipher (CipherLen Bytes)
  SetLength(Result, HEADER_LEN + Length(CipherBytes));
  // HINWEIS: Es wird bewusst der komplette Container am Stück aufgebaut (einfach/didaktisch).
  // Für sehr große Daten wäre Streaming (Header schreiben, dann Cipher streamen) speichereffizienter.

  // Kopiere Header an den Anfang
  Move(HeaderBytes[0], Result[0], HEADER_LEN);
  // Move ist hier unkritisch, weil es Byte-Arrays kopiert (Endianness spielt bei Bytes keine Rolle).

 // Kopiere verschlüsselte Daten hinter den Header
  if Length(CipherBytes) > 0 then
    Move(CipherBytes[0], Result[HEADER_LEN], Length(CipherBytes));
  // Guard gegen Length=0: Move mit leerem Array kann je nach Compiler/RangeChecks Probleme machen.
  // Typische Fehlerquelle: Zugriff auf CipherBytes[0] bei Length=0 → Range Error/Access Violation.

  // Nach dieser Funktion:
  // Result enthält den vollständigen Container:
  // [32 Bytes Header][N Bytes Cipher]
  // Bereit zum Speichern oder Übertragen
  //
  // SICHERHEITSHINWEIS (nochmal als Merksatz):
  // - Dieser Container ist ohne MAC/AEAD nicht manipulationssicher.
  // - Header/IV/Ciphertext sollten in echten Anwendungen authentifiziert werden.
end;


function ParseContainerBytes(const Container: TBytes;
  out CipherBytes: TBytes; out Mode: TAESContainerMode; out IV: TByteArray16): Boolean;

{
  ============================================================================
  FUNKTION: ParseContainerBytes
  ============================================================================
  TITEL/NAME
  - ParseContainerBytes – Parst den AES-Container (Header + Cipher) und extrahiert CipherBytes/Mode/IV

  ZWECK
  - Analysiert das Containerformat, prüft die wichtigsten Plausibilitäten und
    extrahiert die für die Entschlüsselung benötigten Felder:
      * CipherBytes (Nutzdaten)
      * Mode (ECB/CBC)
      * IV (für CBC; bei ECB typischerweise Null-Bytes/Placeholder)
  - Gegenstück zu BuildContainerBytes(...): „Reader“ zum „Writer“.

  EIGENSCHAFTEN (stichpunktartig)
  - Defensive Parsing-Strategie: „bei erstem Fehler sofort Exit(False)“.
  - Validiert Magic (Format-Erkennung), Version (Kompatibilität), Mode (nur bekannte Werte).
  - Liest CipherLen als UInt32 Little-Endian und prüft, ob die Länge zum Container passt.
  - Schützt vor Integer-Überläufen bei TBytes-Allokation (CipherLen > High(Integer) → Exit).
  - Keine Exceptions für erwartbare Fehlerfälle → Boolean-Rückgabe ist parserfreundlich.

  VERWENDUNG IM PROJEKT
  - Wird nach LoadContainerFromFile(...) aufgerufen.
  - Bei Result=True können GUI/Decoder sicher mit Mode/IV/CipherBytes arbeiten.
  - Bei Result=False: Datei ablehnen und dem Nutzer „ungültig/korrupt/falsches Format“ melden.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Diese Funktion prüft *Formatkonsistenz*, nicht kryptographische Integrität:
    Ohne MAC/AEAD kann ein Angreifer Containerbytes manipulieren, ohne dass das hier sicher erkennbar ist.
  - Trotzdem ist defensive Validierung wichtig, um Parser-Crashes und Out-of-Bounds-Zugriffe zu verhindern.
  - Unbekannter Mode oder falsche Version → besser hart ablehnen, statt „irgendwie“ weiterzumachen.

  REFERENZEN / HINWEISE
  - Container-Konzept: Magic Header + Versionierung + feste Offsets („Vertrag“ Writer ↔ Reader).
  - Endianness: ReadUInt32LE(...) muss symmetrisch zu WriteUInt32LE(...) sein.
  - AES-Kontext: NIST FIPS 197 (Rijndael – Daemen & Rijmen); Modi: NIST SP 800-38A (ECB/CBC).
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Warum diese Checks so wichtig sind
  ----------------------------------------------------------------------------
  - Ein Parser ist immer „Angriffsfläche“: Er verarbeitet fremde/unklare Eingaben.
  - Häufigste Fehlerklassen:
    * Zu kurze Eingabe (Header fehlt)
    * Falsche Signatur (keine Containerdatei)
    * Version/Mode unbekannt (anderes Format/neuere Version/manipuliert)
    * Längenfelder lügen (führen sonst zu zu großen Allokationen oder OOB-Reads)
  - Merksatz: „Erst validieren, dann interpretieren.“
  ----------------------------------------------------------------------------
}
const
  HEADER_LEN = 32;                  // Container-Header ist immer 32 Bytes (feste Offsets → einfaches Parsing)
var
  I: Integer;                       // Laufvariable für Magic- und IV-Kopierschleifen
  Version: Byte;                    // Version aus Header (Position 8)
  ModeByte: Byte;                   // Modus aus Header (Position 9)
  CipherLen: LongWord;              // Cipher-Länge aus Header (Position 28-31, UInt32 Little-Endian)
  TotalLen: Integer;                 // Gesamtlänge des Container-Arrays (Length(Container) passt in Integer)
begin

  // -------------------------------------------------------------------------
  // INITIALISIERUNG: Out-Parameter mit Standardwerten füllen
  // -------------------------------------------------------------------------
  // DIDAKTIK:
  // - Bei Return=False sollen Aufrufer möglichst keine „Zufallsreste“ weiterverwenden.
  // - Trotzdem gilt (wegen out-Semantik): Aufrufer darf die out-Werte nur bei Result=True verwenden.

  CipherBytes := nil;         // definierter Start: keine Nutzdaten
  Mode := acmECB;             // Default (wird bei Erfolg überschrieben); dient auch als „sinnvoller“ Startwert
  IV[0]:=0;                   // Compiler-Hint beruhigen
  FillChar(IV, SizeOf(IV), 0); // IV auf Null (bei ECB entspricht das ohnehin dem Placeholder)

  // Pessimistisch auf False setzen (wird bei Erfolg auf True gesetzt)
  Result := False;

  // -------------------------------------------------------------------------
  // SCHRITT 1: Mindestlänge prüfen
  // -------------------------------------------------------------------------
  TotalLen := Length(Container);
  // TotalLen ist Integer: wichtig für spätere Vergleiche und Allokationen.
  // Typische Fehlerquelle: mit UInt32-Längen rechnen und dabei Integer-Überläufe übersehen.

  // Container muss mindestens 32 Bytes (Header) enthalten
   if TotalLen < HEADER_LEN then Exit;    // Zu kurz → kann kein gültiger Container sein

  // -------------------------------------------------------------------------
  // SCHRITT 2: Magic-Bytes validieren
  // -------------------------------------------------------------------------
  // Prüfe "LAES256\0" (8 Bytes)
  // DIDAKTIK: Magic ist „Format-Signatur“, kein Sicherheitsmerkmal.
  // Es schützt nicht vor Manipulation, aber verhindert Fehlinterpretation zufälliger Dateien.

  for I := 0 to 7 do
    if Container[I] <> CONTAINER_MAGIC[I] then Exit;
  // Sofortiges Exit bei erstem Unterschied → schnell und eindeutig.

  // -------------------------------------------------------------------------
  // SCHRITT 3: Version prüfen
  // -------------------------------------------------------------------------
  Version := Container[8];
  // Version ist ein Byte im Header: erlaubt spätere Formatänderungen.

  // Aktuell wird nur Version 1 unterstützt
  if Version <> Byte(CONTAINER_VERSION) then Exit;   // Falsche Version → nicht unterstützt
  // HINWEIS: In größeren Formaten würde man ggf. je nach Version unterschiedliche Parserpfade wählen.

  // -------------------------------------------------------------------------
  // SCHRITT 4: Modus validieren und konvertieren
  // -------------------------------------------------------------------------
  ModeByte := Container[9];        // Modus-Byte aus Header (On-Disk-Code)
  if not ByteToMode(ModeByte, Mode) then Exit;         // Ungültiger Modus → korrupter/inkompatibler Container
  // DIDAKTIK: Unbekannte Modi nicht „erraten“ → hart ablehnen, um falsches Entschlüsseln zu vermeiden.

  // -------------------------------------------------------------------------
  // SCHRITT 5: IV extrahieren
  // -------------------------------------------------------------------------
  // Kopiere 16 Bytes IV aus Position 12-27
  for I := 0 to 15 do
    IV[I] := Container[12 + I];
  // Bei ECB ist IV nur ein Placeholder (meist 0), bei CBC ist er zwingend nötig.
  // Typische Fehlerquelle: falscher Offset → IV „verschiebt“ und CipherLen wird später falsch gelesen.

  // -------------------------------------------------------------------------
  // SCHRITT 6: Cipher-Länge lesen
  // -------------------------------------------------------------------------
  // Lese 4 Bytes (Little-Endian) aus Position 28-31
  CipherLen := ReadUInt32LE(Container, 28);
  // Wichtig: Endianness muss exakt der Schreibseite entsprechen (WriteUInt32LE).
  // Typische Fehlerquelle: Big-/Little-Endianness vertauscht → riesige oder winzige Längen.

  // -------------------------------------------------------------------------
  // SCHRITT 7: Plausibilitätsprüfungen
  // -------------------------------------------------------------------------

  // Prüfung 7a: CipherLen darf nicht größer als High(Integer) sein
  // (Pascal Integer-Grenzen: -2.147.483.648 .. 2.147.483.647)
   if CipherLen > LongWord(High(Integer)) then Exit;            // CipherLen zu groß für Integer-Konvertierung
   // DIDAKTIK: SetLength(TBytes, Integer(CipherLen)) braucht Integer.
   // Ohne diese Prüfung könnte Integer(CipherLen) negativ werden → gefährliche Allokationen/Fehler.

   // Prüfung 7b: Passen Header + Cipher in den Container?
  // (Verhindert Lesen über Container-Ende hinaus)
   if (HEADER_LEN + Integer(CipherLen)) > TotalLen then Exit;   // Container behauptet mehr Daten als vorhanden
   // Typische Fehlerquelle: „HEADER_LEN + CipherLen“ ohne vorherige Größenprüfung → OOB-Reads.
   // Hier ist HEADER_LEN klein, aber Integer(CipherLen) ist nur sicher wegen Prüfung 7a.

   // -------------------------------------------------------------------------
   // SCHRITT 8: Cipher-Bytes extrahieren
   // -------------------------------------------------------------------------
   // Allokiere Array für verschlüsselte Daten
   SetLength(CipherBytes, Integer(CipherLen));
   // HINWEIS: Auch CipherLen=0 ist erlaubt → leeres Array (kann als „kein Payload“ interpretiert werden).

   // Kopiere Cipher-Bytes (ab Position 32)
   if CipherLen > 0 then
     Move(Container[HEADER_LEN], CipherBytes[0], Integer(CipherLen));
   // Guard ist wichtig: CipherBytes[0] ist bei Länge 0 nicht gültig.
   // Typische Fehlerquelle: Move(..., CipherBytes[0], 0) kann je nach Compiler/RangeChecks trotzdem Probleme machen.

   // -------------------------------------------------------------------------
   // SCHRITT 9: Erfolg!
   // -------------------------------------------------------------------------
    Result := True;
    // Ab hier gilt: CipherBytes/Mode/IV sind konsistent und dürfen vom Aufrufer verwendet werden.
end;

function SaveContainerToFile(const FileName: string; const Container: TBytes): Boolean;
{
  ============================================================================
  FUNKTION: SaveContainerToFile
  ============================================================================
  TITEL/NAME
  - SaveContainerToFile – Schreibt Container-Bytes (Header + Ciphertext) in eine Datei

  ZWECK
  - Persistiert den bereits fertig aufgebauten Container (BuildContainerBytes-Ergebnis)
    auf der Festplatte.
  - Kapselt Datei-I/O in einer eigenen Funktion, damit Kryptologie (AES/Containerformat)
    und Betriebssystem-/Dateifehler (Rechte, Platte voll, Locks) sauber getrennt bleiben.

  EIGENSCHAFTEN (stichpunktartig)
  - Wrapper um TFileStream im Modus fmCreate (neu erstellen / überschreiben).
  - Fehler werden als Boolean signalisiert (Result=True/False), nicht per Exception nach außen.
  - Defensive Guard: schreibt nur, wenn Length(Container) > 0 (verhindert Zugriff auf Container[0]).
  - Ressourcen-sicher: FS.Free im finally garantiert (kein Handle-Leak).

  VERWENDUNG IM PROJEKT
  - Typisch nach BuildContainerBytes(...):
      Container := BuildContainerBytes(CipherBytes, Mode, IV);
      if SaveContainerToFile(FileName, Container) then ...
  - Von UI-Code aufrufbar, ohne dass UI sich um Streams/Exceptions kümmern muss.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Diese Funktion macht keine Kryptografie – sie schreibt nur Bytes.
  - Trotzdem praxisrelevant:
    * Speicherort/Dateiname können sensible Informationen verraten.
    * Ohne „atomisches Speichern“ kann bei Abbruch eine teilweise Datei entstehen.
    * Container ist ohne MAC/AEAD nicht manipulationssicher; Dateispeicherung ändert daran nichts.
  - Lehr-Tradeoff: direkte Speicherung ist einfach/übersichtlich; für Produktivcode würde man oft
    „temp file + rename“ verwenden.

  REFERENZEN / HINWEISE
  - FreePascal/Lazarus: TFileStream, Dateimodi (fmCreate).
  - Konzept: „Separation of Concerns“ (Formatbau ≠ Datei-I/O).
  - Kontext AES/Container: NIST FIPS 197 (AES), NIST SP 800-38A (Modi) – nicht hier implementiert, aber Hintergrund.
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Typische Fehlerquellen bei Datei-I/O
  ----------------------------------------------------------------------------
  - Keine Schreibrechte / Pfad existiert nicht / Dateiname ungültig.
  - Datei ist gesperrt (Sharing/Locking).
  - Datenträger voll / Quota / Netzwerkunterbrechung.
  - Unerwarteter Abbruch während des Schreibens → „halb geschriebene“ Datei möglich.
  - Merksatz: „I/O kann immer scheitern – deshalb müssen wir sauber Fehler zurückgeben.“
  ----------------------------------------------------------------------------
}
var
  FS: TFileStream;          // FileStream zum Schreiben (besitzt ein OS-Handle; muss immer freigegeben werden)
begin
  Result := False;           // Pessimistisch auf False (wird nur bei komplettem Erfolg auf True gesetzt)
  try
     // Erstelle/Öffne Datei im Schreibmodus
    // fmCreate: Erstellt neue Datei oder überschreibt existierende
    // DIDAKTIK: Für verschlüsselte Ausgabedateien ist „überschreiben“ oft ok, weil man einen neuen Container erzeugt.
    // Praxis-Hinweis: Wenn man „nicht überschreiben“ will, müsste man vorher prüfen, ob die Datei existiert.
    FS := TFileStream.Create(FileName, fmCreate);
    try
      if Length(Container) > 0 then
        // Schreibe alle Container-Bytes in die Datei
        // WriteBuffer schreibt exakt die angegebene Byteanzahl oder löst eine Exception aus.
        // Vorteil gegenüber Write: Bei Teil-Schreibfehlern wird nicht „still“ weniger geschrieben.
        FS.WriteBuffer(Container[0], Length(Container));
        // Typische Fehlerquelle:
        // - Ohne die Length-Prüfung würde Container[0] bei leerem Array einen Range/Access-Fehler auslösen.
        // - Ein leerer Container ist inhaltlich meist sinnlos; hier wird dann einfach eine leere Datei erzeugt.
        //   HINWEIS: Man könnte (didaktisch) auch entscheiden, leere Container als Fehler zu behandeln – hier nicht.
    finally
      FS.Free;       // FileStream IMMER schließen (auch bei Exception) → verhindert Handle-Leaks und „hängende“ Locks
    end;
    Result := True;     // Erfolg: Stream konnte erstellt werden, und (falls >0) alle Bytes wurden geschrieben
  except
    // Alle I/O-Fehler abfangen
    // Result bleibt False
    // Exception wird nicht weitergegeben (saubere API)
    // HINWEIS (Quality-Gate): Das ist bewusst „still“ gehalten. Für Debug/Unterricht könnte man hier
    // die Exception-Nachricht loggen – aber das wäre eine funktionale Änderung im Verhalten/Output.
    Result := False;
  end;
   // Nach dieser Funktion:
  // - Bei Result=True: Datei wurde erfolgreich geschrieben
  // - Bei Result=False: Fehler beim Schreiben (Datei evtl. nicht erstellt oder unvollständig)
  // HINWEIS (Atomizität): Diese Implementierung ist nicht atomar. Bei Abbruch kann eine Teil-Datei entstehen.
end;

function LoadContainerFromFile(const FileName: string; out Container: TBytes): Boolean;
{
  ============================================================================
  FUNKTION: LoadContainerFromFile
  ============================================================================
  TITEL/NAME
  - LoadContainerFromFile – Lädt die Container-Datei vollständig als Bytes in den Speicher

  ZWECK
  - Liest eine Datei (typischerweise: AES-Container) vollständig in ein TBytes-Array ein.
  - Ist das Gegenstück zu SaveContainerToFile(...).
  - Wichtig: Diese Funktion validiert NICHT das Containerformat selbst – das macht später
    ParseContainerBytes(...). Hier geht es nur um „Bytes zuverlässig aus Datei holen“.

  EIGENSCHAFTEN (stichpunktartig)
  - Liefert Boolean statt Exceptions nach außen → erwartbare I/O-Fehler lassen sich sauber per if behandeln.
  - Initialisiert Container defensiv mit nil, damit bei Fehlern keine „Alt-Daten“ im Array stehen bleiben.
  - Prüft vor dem Öffnen: FileExists(FileName) → schneller Abbruch ohne Exception-Overhead.
  - Schützt vor zu großen Dateien: Size > High(Integer) → Exit (TBytes/SetLength erwartet Integer-Längen).
  - Ressourcensicher: FS.Free im finally verhindert Handle-Leaks (auch bei Exceptions).

  VERWENDUNG IM PROJEKT
  - Typische Reihenfolge beim Laden:
      if LoadContainerFromFile(...) then
        if ParseContainerBytes(...) then
          ... entschlüsseln ...
  - Trennung der Schichten:
      * LoadContainerFromFile: I/O
      * ParseContainerBytes: Format/Validierung
      * AES: Kryptographie

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Laden ist „untrusted input“: Datei kann manipuliert, abgeschnitten oder riesig sein.
  - Diese Funktion verhindert zumindest grobe Ressourcen-/Integer-Probleme (Size > High(Integer)).
  - Integrität/Authentizität werden hier nicht geprüft (ohne MAC/AEAD kann ein Container beliebig verändert sein).
  - Praxis-Hinweis: Für sehr große Dateien wäre Streaming besser; hier wird bewusst alles auf einmal gelesen (Lehrprojekt).

  REFERENZEN / HINWEISE
  - FreePascal/Lazarus: TFileStream, ReadBuffer, Dateimodi (fmOpenRead, fmShareDenyWrite).
  - Defensive Parsing: Größen-/Sanity-Checks vor Allokation.
  - AES-Kontext (nur Einordnung): NIST FIPS 197 (AES), NIST SP 800-38A (Modi).
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Typische Fehlerquellen beim „alles in RAM laden“
  ----------------------------------------------------------------------------
  - Datei ist leer → Container bleibt nil, Result wird trotzdem True (hier bewusst so).
  - Datei wird gerade geschrieben → man kann „Zwischenstände“ lesen (teilweise Inhalte).
  - Netzwerkpfade: Timeout/Disconnect → Exceptions möglich.
  - Große Dateien: RAM-Verbrauch; deswegen der Integer-Check (und in Praxis oft MaxSize-Limits).
  ----------------------------------------------------------------------------
}
var
  FS: TFileStream;      // FileStream zum Lesen (OS-Handle → muss im finally freigegeben werden)
  Size: Int64;          // Dateigröße in Bytes (TFileStream.Size ist Int64 → große Dateien möglich)
begin
  Container := nil;       // Definierter Ausgangszustand: „nichts geladen“
  Result := False;         // Pessimistisch starten: erst bei Erfolg auf True setzen

  if not FileExists(FileName) then Exit;
  // DIDAKTIK: FileExists ist ein schneller Vorcheck. Trotzdem können danach noch Fehler passieren
  // (z.B. Datei wird gelöscht/gesperrt zwischen Check und Create), daher bleibt try/except nötig.

  try
    // Öffne Datei im Lesemodus
    // fmOpenRead: Nur lesen, Datei muss existieren
    // fmShareDenyWrite: Andere dürfen lesen, aber nicht schreiben (reduziert Risiko, „halb geschrieben“ zu lesen)
    // HINWEIS: Der Kommentar oben im Text nennt fmShareDenyNone; der Code nutzt fmShareDenyWrite.
    // Das ist eine sinnvolle (strengere) Wahl beim Laden: verhindert gleichzeitiges Schreiben während des Lesens.
    FS := TFileStream.Create(FileName, fmOpenRead or fmShareDenyWrite);
    try
       if FS.Size > 0 then      // Prüfe, ob Datei nicht leer ist
      begin
      Size := FS.Size;
      // Typische Fehlerquelle: FS.Size ist Int64, SetLength erwartet Integer → bei sehr großen Dateien Overflow-Risiko.

      if Size > High(Integer) then Exit;
      // Defensive Check: verhindert, dass (Integer(Size)) negativ wird oder SetLength scheitert.
      // HINWEIS: Für Produktivcode wäre hier oft zusätzlich ein „MaxAllowedSize“-Limit sinnvoll.

      // Allokiere Container-Array in Dateigröße
      // FS.Size ist Int64, casten zu Integer ist sicher für normale Dateien (nach obigem Check)
      SetLength(Container, Size);

      // Lese komplette Datei in Container-Array
      // ReadBuffer liest exakt die gewünschte Byteanzahl oder wirft eine Exception (keine „Teilmengen“ ohne Hinweis).
      // Typische Fehlerquelle: Container[0] bei Länge 0 – wird durch „if FS.Size > 0“ verhindert.
      FS.ReadBuffer(Container[0], Size);
      end;
      // HINWEIS (Semantik): Bei FS.Size = 0 wird nichts gelesen und Container bleibt nil.
      // Result wird unten trotzdem True gesetzt → „Datei erfolgreich geöffnet/gelesen (leer)“.
      // Ob leere Dateien als Fehler gelten, entscheidet später der Parser (ParseContainerBytes prüft HEADER_LEN).
    finally
      FS.Free;
      // Garantiert: Datei-Handle wird geschlossen, auch wenn ReadBuffer eine Exception wirft.
    end;

    Result := True;
    // Erfolg heißt hier: Datei existierte, konnte geöffnet werden, und falls >0, wurden alle Bytes gelesen.

  except
    Container := nil;
    Result := False;
     // Alle I/O-Fehler abfangen (Datei nicht gefunden, keine Rechte, Sharing, Netzwerkfehler, etc.)
    // Container bleibt nil (kein undefinierter Inhalt)
    // Exception wird nicht weitergegeben (saubere API)
    //
    // HINWEIS: Für Unterricht/Debugging könnte man hier die Exception-Message loggen,
    // aber das wäre eine Verhaltensänderung (zusätzliche Ausgabe) und bleibt daher nur als Kommentar.
  end;

   // Nach dieser Funktion:
  // - Bei Result=True: Container enthält die Datei-Bytes (oder ist nil bei leerer Datei)
  // - Bei Result=False: Fehler beim Lesen, Container ist nil
  end;

end.

