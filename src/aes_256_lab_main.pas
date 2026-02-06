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
  Jeder Schritt wird im StatusMemo dokumentiert, damit der Ablauf
  nachvollziehbar ist.

  SICHERHEITSHINWEIS:
  Dies ist LEHRCODE! ECB-Modus ist für Produktivsysteme NICHT geeignet.
  Siehe Kommentare in uAES256_ECB.pas für Details.

  ----------------------------------------------------------------------------
  WARUM IST ECB HIER TROTZDEM OK?
  ----------------------------------------------------------------------------

  - ECB (Electronic Codebook) ist didaktisch praktisch, weil jeder 16-Byte-Block
    unabhängig verschlüsselt wird. Dadurch lassen sich einzelne Blöcke und
    Zwischenzustände sehr leicht testen, vergleichen und debuggen.
  - Genau diese Eigenschaft macht ECB in der Praxis unsicher: gleiche Klartext-
    Blöcke ergeben gleiche Ciphertext-Blöcke → Muster bleiben sichtbar.
  - Für Lernzwecke (Verständnis der AES-Runden und Testvektor-Vergleiche) ist
    ECB aber oft der einfachste Einstieg.

  ----------------------------------------------------------------------------
  WARUM UTF-8 → BYTES?
  ----------------------------------------------------------------------------

  - AES arbeitet nicht mit "Strings", sondern mit Bytes (0..255).
  - Ein Unicode-String muss daher in eine definierte Byte-Repräsentation
    überführt werden, damit die Verschlüsselung reproduzierbar ist.
  - UTF-8 ist dafür sinnvoll, weil es plattformübergreifend standardisiert ist.

  ----------------------------------------------------------------------------
  WARUM PKCS#7-PADDING?
  ----------------------------------------------------------------------------

  - AES ist ein Blockcipher mit fester Blockgröße (bei AES immer 128 Bit = 16 Byte).
  - Wenn der Klartext nicht genau ein Vielfaches von 16 Byte ist, muss aufgefüllt
    werden, damit die Blockverarbeitung eindeutig bleibt.
  - PKCS#7 ist ein verbreitetes Schema: Es hängt N Bytes an, und jedes dieser Bytes
    hat den Wert N. Wichtig: Auch bei exakt 16 Byte Länge wird ein kompletter
    16-Byte-Paddingblock angehängt, damit die Entschlüsselung eindeutig ist.

  ----------------------------------------------------------------------------
  WARUM "LEHR-TEST" AM ERSTEN BLOCK?
  ----------------------------------------------------------------------------

  - SubBytes, ShiftRows und MixColumns sind die Kern-Transformationen von AES
    (zusammen mit AddRoundKey). Einen einzelnen Block gezielt zu transformieren
    hilft, die Rundenlogik als "Substitution-Permutation Network" zu begreifen,
    bevor man komplette ECB/CBC-Durchläufe betrachtet.

  ----------------------------------------------------------------------------
  HISTORISCHER KONTEXT (AES / Rijndael)
  ----------------------------------------------------------------------------

  - AES basiert auf dem Algorithmus "Rijndael", entwickelt von
    Joan Daemen und Vincent Rijmen.
  - Rijndael wurde nach einem offenen NIST-Wettbewerb als AES-Standard ausgewählt.
  - In AES ist die Blockgröße fest 128 Bit; die Schlüssellängen sind 128/192/256 Bit.
    Für AES-256 gilt: 14 Runden (Rounds) + Key Schedule für die Rundenschlüssel.

  ----------------------------------------------------------------------------
  SICHERHEITSHINWEIS ZUR PASSWORT→KEY-ABLEITUNG
  ----------------------------------------------------------------------------

  - Hier wird (didaktisch) ein Passwort über SHA-256 zu 32 Key-Bytes geformt.
  - In echten Anwendungen nutzt man dafür eine KDF mit Salt und Arbeit (z.B. PBKDF2,
    scrypt, Argon2), um Wörterbuch-/GPU-Angriffe stark zu erschweren.
  - Dieses Projekt ist Lehrcode: Ziel ist Nachvollziehbarkeit, nicht Hardening.

  ----------------------------------------------------------------------------
  TIPP FÜR EXPERIMENTE
  ----------------------------------------------------------------------------

  Verwende bekannte Testvektoren (FIPS 197 / SP 800-38A) und vergleiche:
  (a) Key, (b) Plaintext-Block, (c) Ciphertext-Block.

  So lässt sich sehr schnell prüfen, ob S-Box, ShiftRows, MixColumns und
  AddRoundKey korrekt implementiert sind.

  ----------------------------------------------------------------------------
  WEITERFÜHRENDE INFORMATIONEN
  ----------------------------------------------------------------------------

  - NIST FIPS 197: "Advanced Encryption Standard (AES)"
    → Offizielle AES-Spezifikation mit Rundendefinitionen, S-Box, MixColumns, Key Schedule

  - NIST SP 800-38A: "Recommendation for Block Cipher Modes of Operation"
    → Referenz für ECB/CBC/CTR usw. inkl. Testvektoren

  - NIST CAVP (Cryptographic Algorithm Validation Program)
    → Umfangreiche Testvektor-Sammlungen (AES Known Answer Tests / KAT)

  - Original-Paper zu Rijndael (Daemen & Rijmen)
    → Suchbegriff: "The Rijndael Block Cipher" / "AES Proposal Rijndael"

  - Praxis-Lektüre (Krypto-Grundlagen)
    → "Crypto 101" (frei verfügbar, gute Einstiegslektüre)

  ============================================================================
}
var
  PlainText: string;            // Text, den der Benutzer in MemoPlain eingibt
  PlainBytes: TBytes;           // Klartext als UTF-8-Byte-Array
  PaddedBytes: TBytes;          // Klartext nach PKCS#7-Padding
  HexText: string;              // Hex-Darstellung der gepaddeten Daten

  Block: TByteArray16;          // Erster 16-Byte-Block für Lehr-Test
  State: TAESState;             // AES-State-Matrix (4×4)
  RoundBytes: TBytes;           // Block nach SubBytes+ShiftRows+MixColumns
  HexRound: string;             // Hex-Darstellung des transformierten Blocks

  KeyBytes: TBytes;             // AES-256 Key (32 Bytes)
  Ctx: TAES256Context;          // Roundkeys (15 Rundenschlüssel)
  CipherBytes: TBytes;          // Verschlüsselte Daten (ECB)
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

  // Produktiv-Code (NICHT in diesem Lehrprojekt):
  Randomize;
  for I := 0 to 15 do
    IV[I] := Random(256);  // Oder besser: Kryptographisch sicherer RNG

  ----------------------------------------------------------------------------
  WARUM CBC "SICHERER" IST – UND WO DIE GRENZEN SIND
  ----------------------------------------------------------------------------

  - CBC löst das "Musterproblem" von ECB, weil gleiche Klartextblöcke durch die
    Verkettung (XOR mit vorherigem Ciphertext) *nicht* mehr zu gleichen
    Ciphertextblöcken führen.

  - WICHTIG: CBC liefert dadurch Vertraulichkeit (Confidentiality), aber *keine*
    Integrität/Authentizität. Ein Angreifer kann Ciphertext-Bits gezielt ändern,
    was beim Entschlüsseln vorhersehbare Änderungen im Klartext erzeugt.
    → Fazit: CBC sollte in echten Systemen immer mit MAC (Encrypt-then-MAC) oder
      besser gleich mit AEAD-Modi (z.B. GCM) kombiniert werden.

  ----------------------------------------------------------------------------
  WARUM DER IV SO KRITISCH IST
  ----------------------------------------------------------------------------

  - Der IV ist sozusagen der "Startblock" der Kette: Er beeinflusst direkt den
    ersten verschlüsselten Block.

  - Wenn man IVs wiederverwendet (mit gleichem Key), kann das Informationen über
    gleiche Präfixe offenbaren und führt zu vermeidbaren Angriffsmöglichkeiten.

  - Der IV muss NICHT geheim sein, aber er muss UNVORHERSEHBAR (zufällig) und
    pro Nachricht eindeutig sein. Typisch wird er zusammen mit dem Ciphertext
    gespeichert/übertragen.

  ----------------------------------------------------------------------------
  DIDAKTIK-TIPP ZUM XOR-CHAINING
  ----------------------------------------------------------------------------

  Eine gute Übung ist, zwei Nachrichten mit identischem ersten 16-Byte-Block
  zu verschlüsseln:

  (a) einmal mit gleichem IV (unsicher) → erster Ciphertextblock identisch
  (b) einmal mit unterschiedlichem IV → erster Ciphertextblock unterschiedlich

  So sieht man direkt den praktischen Effekt des IVs.

  ----------------------------------------------------------------------------
  PADDING: WARUM DAS MEHR ALS "NUR AUFFÜLLEN" IST
  ----------------------------------------------------------------------------

  - PKCS#7 ist eindeutig decodierbar, aber Implementierungen müssen beim
    Entpadden sorgfältig sein:
    * Ungültiges Padding darf nicht "leaken", sonst drohen Padding-Oracle-Angriffe
      (klassisches CBC-Problem in Web-/Protokollkontexten).

  - Für ein Lehrprojekt ist PKCS#7 perfekt, weil es einfach und standardnah ist.

  ----------------------------------------------------------------------------
  HISTORISCHER KONTEXT (AES / Rijndael)
  ----------------------------------------------------------------------------

  - AES basiert auf "Rijndael", entwickelt von Joan Daemen und Vincent Rijmen.
  - Rijndael gewann den offenen NIST-Wettbewerb und wurde als FIPS 197 standardisiert.
  - CBC ist ein "Mode of Operation" um einen Blockcipher wie AES für beliebig lange
    Daten zu verwenden; das steht getrennt vom AES-Kernalgorithmus.

  ----------------------------------------------------------------------------
  PRAKTISCHER LEHR-ABSCHLUSS
  ----------------------------------------------------------------------------

  Wenn die Implementierung steht, lohnt sich ein Vergleich mit Testvektoren:
  Key + IV + Plaintext → Ciphertext (aus SP 800-38A).

  Damit kann man sehr schnell erkennen, ob:
  (a) IV/XOR-Kette korrekt ist
  (b) Padding korrekt ist
  (c) der AES-Kern korrekt arbeitet

  ----------------------------------------------------------------------------
  WEITERFÜHRENDE INFORMATIONEN
  ----------------------------------------------------------------------------

  - NIST FIPS 197:
    Offizielle AES-Spezifikation (Runden, S-Box, MixColumns, Key Schedule)

  - NIST SP 800-38A:
    Offizielle Empfehlung zu Blockcipher-Modi inkl. ECB/CBC/CTR und Testvektoren
    → Für CBC gibt es dort Known-Answer-Tests (KAT), ideal zum Gegenprüfen

  - "The Rijndael Block Cipher" / "AES Proposal Rijndael" (Daemen & Rijmen):
    Technischer Hintergrund zur Designentscheidung (SPN-Struktur, Effizienz, Sicherheit)

  - Stichworte zum Nachschlagen/Vertiefen:
    * "CBC bit flipping"
    * "Padding oracle attack"
    * "Encrypt-then-MAC"
    * "AEAD" / "GCM"

  ============================================================================
}
var
  PlainText: string;                     // Klartext aus MemoPlain
  PlainBytes: TBytes;                    // Klartext als UTF-8-Bytes
  PaddedBytes: TBytes;                   // Gepaddeter Klartext (Vielfaches von 16 Bytes)
  HexText: string;                       // Hex-Darstellung der gepaddeten Daten

  KeyBytes: TBytes;                      // Passwort → SHA-256 → 32-Byte AES-Key
  Ctx: TAES256Context;                   // AES-256 Kontext (15 Rundenschlüssel)
  CipherBytes: TBytes;                   // Verschlüsselte Daten (CBC-Modus)
  HexCipher: string;                     // Hex-Darstellung des Ciphertexts

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
{
 ============================================================================
 entschluesseln_ECBClick - ECB-Entschlüsselung (Button-Event-Handler)
 ============================================================================

 ZWECK:
 Event-Handler für den "Entschlüsseln (ECB)"-Button. Entschlüsselt die
 zuvor mit ECB verschlüsselten Daten aus FCipherBytes.

 BESONDERHEIT - KEINE EXCEPTIONS IM DEBUGGER:
 Diese Funktion verwendet TryGetPKCS7PadLen statt PKCS7Unpad, um
 Exceptions zu vermeiden. Warum?

 PROBLEM mit PKCS7Unpad:
 - Wirft Exception bei ungültigem Padding
 - Im Lazarus-Debugger: Unterbrechung bei jeder Exception
 - Für Schüler verwirrend, auch wenn Exception abgefangen wird

 LÖSUNG mit TryGetPKCS7PadLen:
 - Gibt True/False zurück (keine Exception)
 - Debugger bleibt ruhig
 - Für Lehrzwecke besser geeignet

 ABLAUF:
 1. FCipherBytes aus Speicher holen (wurde bei Verschlüsselung gespeichert)
 2. Validierung (Länge, Vielfaches von 16)
 3. Passwort → SHA-256 → Key (GLEICHER wie bei Verschlüsselung!)
 4. ECB-Entschlüsselung
 5. Padding validieren (OHNE Exception)
 6. Padding manuell entfernen
 7. Bytes → UTF-8 String
 8. Anzeigen

 WICHTIG - FALSCHES PASSWORT:
 Wenn das falsche Passwort eingegeben wird:
 - Entschlüsselung "funktioniert" technisch
 - Ergebnis sind zufällige Bytes ("Müll")
 - Padding ist ungültig → TryGetPKCS7PadLen gibt False zurück
 - Benutzer sieht Fehlermeldung "Ungültiges Padding"

 ============================================================================



 HINWEIS ZU ECB UND „UNGÜLTIGES PADDING“
 - Dass falsche Passwörter häufig erst beim Padding auffallen, ist typisch für
   *nicht-authentifizierte* Verschlüsselung (ECB/CBC ohne MAC).
 - In der Praxis würde man statt „Padding-Fehler“ lieber Authentizität prüfen
   (AEAD, z.B. GCM), damit Manipulationen/Fehlpasswörter sauber erkannt werden.

 WEITERFÜHRENDE INFO (für Lernende)
 - AES (Rijndael, Daemen & Rijmen) ist der Blockcipher.
   ECB/CBC sind „Modes of Operation“ – sie sind nicht Teil des AES-Kerns.
 - FIPS 197: AES-Spezifikation (Runden, S-Box, MixColumns, Key Schedule)
 - NIST SP 800-38A: ECB/CBC und Testvektoren (sehr gut zum Gegenprüfen)
 ----------------------------------------------------------------------------


 }
var
  KeyBytes: TBytes;                 // Passwort → SHA-256 → 32-Byte AES-Key
  Ctx: TAES256Context;              // AES-256 Kontext (15 Rundenschlüssel)
  DecryptedPadded: TBytes;          // Entschlüsselte Daten (MIT Padding!)
  PlainBytes: TBytes;               // Entschlüsselte Daten (OHNE Padding)
  PlainText: string;                // Entschlüsselter Text als String
  PadLen: Integer;                  // Länge des Paddings (1..16 Bytes)
  OutLen: Integer;                  // Länge der Daten ohne Padding
begin

 // -------------------------------------------------------------------------
  // VORBEREITUNG: Alle Variablen initialisieren
  // -------------------------------------------------------------------------

  KeyBytes        := nil;
  DecryptedPadded := nil;
  PlainBytes      := nil;
  PlainText       := '';

  // -------------------------------------------------------------------------
  // AUSGABE VORBEREITEN: StatusMemo leeren
  // -------------------------------------------------------------------------
  StatusMemo.Clear;
  StatusMemo.Lines.Add('--- Entschlüsselung (ECB) gestartet ---');

  // -------------------------------------------------------------------------
  // SCHRITT 1: Validierung - Sind verschlüsselte Daten vorhanden?
  // -------------------------------------------------------------------------
  // FCipherBytes ist eine Instanzvariable (private-Sektion)
  // Sie wurde bei der Verschlüsselung gefüllt (siehe Verschluesseln_ButtonClick)
  //
  // Wenn leer: Benutzer hat vergessen zu verschlüsseln oder zu laden

  if Length(FCipherBytes) = 0 then
  begin
    StatusMemo.Lines.Add('Fehler: Kein Cipher im Speicher (FCipherBytes ist leer).');
    StatusMemo.Lines.Add('Hinweis: Bitte zuerst verschlüsseln oder laden.');
    Exit;       // Abbruch, nichts zu entschlüsseln
  end;

  // -------------------------------------------------------------------------
  // SCHRITT 2: Validierung - Ist die Länge ein Vielfaches von 16?
  // -------------------------------------------------------------------------
  // AES arbeitet nur mit 16-Byte-Blöcken
  // Wenn die Länge kein Vielfaches von 16 ist:
  // - Daten sind korrupt
  // - Oder: Falsches Format geladen

  if (Length(FCipherBytes) mod 16) <> 0 then
  begin
    StatusMemo.Lines.Add('Fehler: Cipher-Datenlänge ist kein Vielfaches von 16.');
    Exit;    // Abbruch, Daten sind ungültig
  end;

    // Info für Benutzer: Zeige Länge der zu entschlüsselnden Daten
  StatusMemo.Lines.Add('CipherBytes aus Speicher übernommen (Länge: ' +
     IntToStr(Length(FCipherBytes)) + ' Bytes).');

  // -------------------------------------------------------------------------
  // SCHRITT 3: Passwort → SHA-256 → Key
  // -------------------------------------------------------------------------
  // WICHTIG: Das Passwort muss EXAKT das gleiche sein wie bei der Verschlüsselung!
  //
  // Ablauf:
  // 1. Passwort aus Edit2 (Eingabefeld) lesen

  // Passwort -> SHA-256 -> Key
  KeyBytes := StringToBytesUTF8(Edit2.Text);

  // 2. SHA-256 Hash berechnen
  // Dies muss den GLEICHEN Key wie bei der Verschlüsselung ergeben
  // Wenn Passwort unterschiedlich → Key unterschiedlich → Müll beim Entschlüsseln
  KeyBytes := SHA256(KeyBytes);

  // -------------------------------------------------------------------------
  // SCHRITT 4: AES-256 Kontext initialisieren
  // -------------------------------------------------------------------------
  // Key Schedule: Generiert die gleichen 15 Rundenschlüssel wie bei Verschlüsselung
  // (falls Passwort korrekt ist!)

  AES256InitKey(KeyBytes, Ctx);

  // ECB entschlüsseln
  // -------------------------------------------------------------------------
  // SCHRITT 5: ECB-Entschlüsselung
  // -------------------------------------------------------------------------
  // AES256DecryptECB macht:
  // - Schleife über alle 16-Byte-Blöcke
  // - Jeden Block mit AES256DecryptBlock entschlüsseln
  // - Ergebnisse zusammenfügen
  //
  // WICHTIG:
  // - Wenn Key korrekt: Ergebnis = Original-Plaintext (mit Padding)
  // - Wenn Key falsch: Ergebnis = zufällige Bytes

  DecryptedPadded := AES256DecryptECB(FCipherBytes, Ctx);
  StatusMemo.Lines.Add('ECB-Entschlüsselung durchgeführt.');

  // -------------------------------------------------------------------------
  // SCHRITT 6: Padding validieren (OHNE Exception!)
  // -------------------------------------------------------------------------
  // TryGetPKCS7PadLen prüft, ob das Padding gültig ist:
  //
  // Was wird geprüft?
  // 1. Letztes Byte auslesen → PadLen (sollte 1..16 sein)
  // 2. Prüfen: Liegt PadLen im gültigen Bereich?
  // 3. Prüfen: Sind die letzten PadLen Bytes alle = PadLen?
  //
  // Rückgabe:
  // - True: Padding ist gültig, PadLen enthält die Padding-Länge
  // - False: Padding ist ungültig (sehr wahrscheinlich falsches Passwort!)
  // Padding vorab prüfen (ohne Exception)

  if not TryGetPKCS7PadLen(DecryptedPadded, PadLen, 16) then
  begin
    // -----------------------------------------------------------------------
    // FEHLER: Padding ungültig
    // -----------------------------------------------------------------------
    // Dies passiert, wenn:
    // - Falsches Passwort verwendet wurde
    // - Falscher Modus (CBC statt ECB oder umgekehrt)
    // - Daten sind korrupt
    //
    // Der häufigste Fall: Falsches Passwort!

    StatusMemo.Lines.Add('FEHLER: Padding ungültig.');
    StatusMemo.Lines.Add('→ Sehr wahrscheinlich falsches Passwort oder falscher Modus.');

    // Benutzerfreundliche MessageBox
    ShowMessage('ECB-Entschlüsselung fehlgeschlagen.');
    Exit;     // Abbruch, wir können nicht weitermachen
  end;

  // Padding ist gültig - zeige Länge zur Information
  StatusMemo.Lines.Add('Padding OK. PadLen=' + IntToStr(PadLen));

   // -------------------------------------------------------------------------
  // SCHRITT 7: Padding manuell entfernen (OHNE PKCS7Unpad!)
  // -------------------------------------------------------------------------
  // Warum manuell?
  // - PKCS7Unpad würde Exception werfen bei Fehler
  // - Debugger würde unterbrechen (störend für Schüler)
  // - TryGetPKCS7PadLen hat bereits validiert, Padding ist OK
  //
  // Wie funktioniert es?
  // - Original-Länge = Gesamt-Länge - Padding-Länge
  // - PlainBytes auf Original-Länge setzen
  // - Bytes (ohne Padding) kopieren
  OutLen := Length(DecryptedPadded) - PadLen;


   // Kopieren nur, wenn tatsächlich Daten vorhanden sind
  // (könnte theoretisch 0 sein, wenn Original leer war und nur Padding)

  if OutLen < 0 then
  begin
    StatusMemo.Lines.Add('FEHLER: Interner Padding-Fehler (OutLen < 0).');
    ShowMessage('ECB-Entschlüsselung fehlgeschlagen.');
    Exit;
  end;

  SetLength(PlainBytes, OutLen);
  // Kopieren nur, wenn tatsächlich Daten vorhanden sind
  // (könnte theoretisch 0 sein, wenn Original leer war und nur Padding)
  if OutLen > 0 then
    Move(DecryptedPadded[0], PlainBytes[0], OutLen);

  StatusMemo.Lines.Add('PKCS#7-Padding wurde entfernt (ohne Exception).');

   // -------------------------------------------------------------------------
  // SCHRITT 8: Bytes → UTF-8 String
  // -------------------------------------------------------------------------
  // Umkehrung der StringToBytesUTF8 aus der Verschlüsselung
  //
  // PlainBytes enthält UTF-8 kodierte Bytes
  // BytesToStringUTF8 interpretiert sie und erzeugt einen Lazarus-String
  //
  // Umlaute, Sonderzeichen, Emojis werden korrekt wiederhergestellt
  PlainText := BytesToStringUTF8(PlainBytes);

   StatusMemo.Lines.Add('Klartext wurde aus den Bytes rekonstruiert.');

  // -------------------------------------------------------------------------
  // SCHRITT 9: Anzeigen im Entschlüsselungs-Memo
  // -------------------------------------------------------------------------
  // decrypted_Memo ist das Ausgabe-Memo für entschlüsselte Texte

  decrypted_Memo.Clear;
  decrypted_Memo.Lines.Add(PlainText);
  // -------------------------------------------------------------------------
  // SCHRITT 10: Erfolgreiche Entschlüsselung bestätigen
  // -------------------------------------------------------------------------
  StatusMemo.Lines.Add('');
  StatusMemo.Lines.Add('Entschlüsselung erfolgreich abgeschlossen.');

  // Visuell hervorgehobene Ausgabe für bessere Übersichtlichkeit
  StatusMemo.Lines.Add('--------------------------------------------');
  StatusMemo.Lines.Add('###########   ENT-SCHLÜSSELT   ###########');
  StatusMemo.Lines.Add('--------------------------------------------');
  StatusMemo.Lines.Add(PlainText);  // Klartext nochmal im Status anzeigen
  StatusMemo.Lines.Add('--------------------------------------------');
  StatusMemo.Lines.Add('###########   ENT-SCHLÜSSELT   ###########');
  StatusMemo.Lines.Add('--------------------------------------------');

  // =========================================================================
// ENDE DER ECB-ENTSCHLÜSSELUNG
// =========================================================================
//
//
// 1. SYMMETRISCHE VERSCHLÜSSELUNG:
//    - Gleicher Key für Ver- und Entschlüsselung
//    - Passwort muss exakt gleich sein
//    - Ein Zeichen Unterschied → Komplett anderer Key → Müll
//
// 2. PADDING-VALIDIERUNG:
//    - Erste Erkennung eines falschen Passworts
//    - Ungültiges Padding = fast sicher falsches Passwort
//    - TryGetPKCS7PadLen ist "Debugger-freundlich"
//
// 3. ECB-EIGENSCHAFTEN:
//    - Fehler in einem Block betrifft nur diesen Block
//    - Andere Blöcke bleiben lesbar
//    - Im Gegensatz zu CBC (dort: 2 Blöcke betroffen)
//
// 4. FEHLERQUELLEN:
//    - Falsches Passwort (häufigster Fall)
//    - Falscher Modus (CBC statt ECB)
//    - Korrupte Daten
//    - Nicht verschlüsselt vor Entschlüsselung

{
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Key-Ableitung, ECB-Kontext, typische Stolperfallen
  ----------------------------------------------------------------------------

  1) PASSWORT → KEY: Warum SHA-256 hier nur ein Lehr-Kompromiss ist

  - In diesem Projekt wird das Passwort (UTF-8 Bytes) mit SHA-256 gehasht und
    das Ergebnis direkt als 32-Byte-Key für AES-256 genutzt.

  - Das ist für Lernzwecke nachvollziehbar (einfach, deterministisch, ohne
    Zusatzparameter), hat aber in der Praxis einen großen Nachteil:
    SHA-256 ist schnell → Angreifer können sehr viele Passwörter pro Sekunde
    testen (Wörterbuch-/GPU-Angriffe).

  - In realen Systemen nutzt man deshalb eine KDF (Key Derivation Function),
    die absichtlich rechenintensiv ist und ein Salt verwendet, z.B.:
    PBKDF2 (NIST), scrypt, Argon2.

  - Merksatz: "Hash ist nicht automatisch eine Passwort-KDF."

  2) AES-KERN vs. MODUS (ECB): Was gehört wohin?

  - AES (eigentlich: Rijndael als AES-Standard) ist der Blockcipher:
    Er verschlüsselt genau 16 Byte (128 Bit) pro Block.

  - ECB ist nur ein Betriebsmodus ("Mode of Operation"), der festlegt, wie
    man viele Blöcke verarbeitet. Bei ECB sind Blöcke unabhängig voneinander.

  - Vorteil für Unterricht: Jeder Block lässt sich isoliert testen und mit
    Testvektoren vergleichen.

  - Nachteil in der Praxis: Muster werden sichtbar (gleiche Klartextblöcke →
    gleiche Ciphertextblöcke). Deshalb ECB praktisch nur für Spezialfälle.

  3) WARUM PADDING OFT "DEN FEHLER ERKENNT"

  - Bei falschem Passwort ist der entschlüsselte Byte-Strom praktisch Zufall.

  - Zufall erfüllt die PKCS#7-Regeln am Ende nur selten → Padding-Check schlägt
    meist fehl und liefert damit einen frühen "Hinweis" auf falschen Key/Modus.

  - Achtung Praxis: Gerade dieses Verhalten kann gefährlich werden, wenn ein
    System unterschiedliche Fehlermeldungen/Timings preisgibt:
    → Padding-Oracle-Angriffe (klassisch bei CBC, theoretisch auch als Konzept
      wichtig zu verstehen). In Lehrcode darf man das klar sichtbar machen,
      in echter Software muss man hier sehr sauber sein.

  4) UTF-8 ALS LEHR-THEMA

  - AES arbeitet auf Bytes; Text ist eine Kodierung darüber.

  - Mit UTF-8 ist klar definiert, wie "äöü€" etc. in Bytes umgesetzt werden.

  - Bei falschem Key können entstehende Bytes kein gültiges UTF-8 darstellen;
    je nach Implementierung können dann Ersatzzeichen auftauchen. Das ist normal:
    "Krypto liefert Bytes – Text ist nur eine Interpretation."

  5) HISTORISCHER KONTEXT (Daemen & Rijmen)

  - AES basiert auf "Rijndael" von Joan Daemen und Vincent Rijmen.

  - Rijndael gewann den offenen AES-Wettbewerb von NIST und wurde als FIPS 197
    standardisiert.

  - Design-Idee (vereinfacht): Substitution + Permutation + Rundenschlüssel
    (SPN-Struktur) → sehr effizient in Software/Hardware und gut analysierbar.

  ----------------------------------------------------------------------------
  WEITERFÜHRENDE INFORMATIONEN
  ----------------------------------------------------------------------------

  AES / Rijndael Grundlagen:
  - NIST FIPS 197: Offizielle AES-Spezifikation (S-Box, Runden, Key Schedule)
  - Buch: "The Design of Rijndael" (Daemen & Rijmen) – tiefere Hintergründe
  - Suchbegriff: "Rijndael submission AES" (Original-Einreichung & Hintergründe)

  Betriebsmodi & Testvektoren:
  - NIST SP 800-38A: ECB/CBC/CTR usw. + offizielle Testvektoren
  - NIST CAVP / KAT: "Known Answer Tests" (sehr gut zum Validieren der Implementierung)

  Padding / Sicherheit:
  - PKCS#7 Padding ist u.a. in RFC 5652 (CMS) dokumentiert (Praxisreferenz)
  - Vaudenay (2002): Padding-Oracle-Angriff (historisch sehr wichtig)
  - Empfehlenswerte Praxislektüre: "Cryptography Engineering"

  ----------------------------------------------------------------------------
}

end;



{ ---------------------------------------------------------------------------
  ENTschlüsseln (CBC) – nutzt FCipherBytes + FCipherIV
  Ziel: keine Exceptions bei ungültigem Padding -> Debugger bleibt still
  --------------------------------------------------------------------------- }



procedure TAES_256_Lab.entschluesseln_CBCClick(Sender: TObject);
{
  ----------------------------------------------------------------------------
  PROZEDUR: entschluesseln_CBCClick
  ----------------------------------------------------------------------------

  ZIEL (WAS PASSIERT HIER?)
  - Diese Routine entschlüsselt die aktuell im Speicher liegenden Daten
    (FCipherBytes) im CBC-Modus mit AES-256.
  - Danach wird das PKCS#7-Padding geprüft und entfernt.
  - Abschließend werden die reinen Klartext-Bytes wieder als UTF-8-String in
    decrypted_Memo ausgegeben.

  ----------------------------------------------------------------------------
  DIDAKTIK (WARUM IST DAS SO AUFGEBAUT?)
  ----------------------------------------------------------------------------

  1) Vorbedingungen prüfen (Defensive Programming)
     - Wenn FCipherBytes leer ist, kann man nicht entschlüsseln → früh Exit.
     - Wenn die Länge kein Vielfaches von 16 ist, ist das für AES-Blöcke ungültig.
       (AES hat immer 16-Byte-Blockgröße, unabhängig von 128/192/256 Bit Key.)
     - Der Hinweis auf FCipherMode zeigt, dass "AES" (Blockcipher) und "CBC"
       (Betriebsmodus) zwei verschiedene Ebenen sind.

  2) Passwort → Key (über SHA-256)
     - Hier wird das Passwort (UTF-8 Bytes) per SHA-256 auf 32 Bytes gebracht
       und als AES-256-Key verwendet.
     - Das ist für ein Lehrprojekt nachvollziehbar und reproduzierbar.
     - ABER: In realen Anwendungen ist das nicht ideal, weil SHA-256 sehr schnell
       ist → erleichtert Wörterbuch-/GPU-Angriffe.
       Praxis-Korrektur wäre eine KDF mit Salt + Arbeit (PBKDF2 / scrypt / Argon2).

  3) CBC-Entschlüsselung mit IV
     - CBC benötigt zusätzlich zum Key einen IV (Initialisierungsvektor).
     - Der IV sorgt dafür, dass der erste Block nicht deterministisch startet.
       (Gleiche Nachricht + gleicher Key → bei neuem IV anderer Ciphertext.)
     - Der IV ist nicht geheim, aber muss pro Nachricht eindeutig und
       unvorhersehbar sein.

  4) Padding prüfen und entfernen (PKCS#7)
     - Blockcipher liefern immer Blocklängen → deshalb wurde beim Verschlüsseln
       Padding angehängt.
     - Beim Entschlüsseln muss man prüfen, ob das Padding gültig ist.
     - Wichtiger Lehrpunkt: Bei falschem Passwort sind die entschlüsselten Bytes
       praktisch Zufall → gültiges PKCS#7-Padding tritt dann selten auf.
       Deshalb ist "Padding ungültig" ein sehr typisches Symptom für falschen Key,
       falschen Modus oder manipulierte Daten.

  5) Sicherheits-Hinweis: "CBC liefert keine Integrität"
     - CBC schützt Vertraulichkeit, aber nicht automatisch gegen Manipulation.
     - Ohne zusätzliche Authentifizierung (MAC / AEAD) kann Ciphertext verändert
       werden, und die Entschlüsselung produziert entsprechend veränderten Klartext.
     - Für Lehrzwecke ist das ok, in echten Systemen nutzt man z.B. AEAD (GCM).

  ----------------------------------------------------------------------------
  IMPLEMENTATIONSDETAILS
  ----------------------------------------------------------------------------

  - TryGetPKCS7PadLen(...) kapselt eine sichere/saubere Padding-Längen-Erkennung,
    ohne Exceptions zu werfen. Das macht Fehlerpfade gut sichtbar.

  - OutLen := Length(DecryptedPadded) - PadLen ist der zentrale Schritt, um den
    Klartext ohne Padding zu erhalten.

  - Move(...) kopiert die relevanten Bytes in ein neues Array, damit PlainBytes
    exakt die Klartextlänge hat (und keine Padding-Reste enthält).

  - BytesToStringUTF8(...) zeigt erneut den wichtigen Punkt: Krypto arbeitet
    mit Bytes; die Interpretation als Text ist ein separater Schritt.

  ----------------------------------------------------------------------------
  HISTORISCHER KONTEXT (AES / Rijndael)
  ----------------------------------------------------------------------------

  - AES basiert auf dem Blockcipher "Rijndael", entworfen von
    Joan Daemen und Vincent Rijmen.

  - Der AES-Standard (FIPS 197) fixiert die Blockgröße auf 128 Bit (16 Byte)
    und erlaubt 128/192/256 Bit Schlüssel. AES-256 nutzt 14 Runden.

  ----------------------------------------------------------------------------
  WEITERFÜHRENDE INFORMATIONEN
  ----------------------------------------------------------------------------

  - NIST FIPS 197:
    Offizielle AES-Spezifikation (Runden, S-Box, MixColumns, Key Schedule)

  - NIST SP 800-38A:
    Blockcipher-Modi (ECB/CBC/CTR etc.) inkl. offizieller Testvektoren

  - NIST CAVP / KAT:
    Known-Answer-Tests zum Validieren der eigenen Implementierung

  - Stichworte zum Vertiefen:
    * "CBC bit flipping" (Manipulation ohne Authentifizierung)
    * "Padding oracle attack" (warum Padding-Fehler in Protokollen gefährlich sein können)
    * "PBKDF2 / scrypt / Argon2" (Passwort-basierte Schlüsselableitung)
    * "AEAD / GCM" (Verschlüsselung + Authentifizierung in einem Verfahren)

  ----------------------------------------------------------------------------
}
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
 {
  ----------------------------------------------------------------------------
  PROZEDUR: SpeichernClick
  ----------------------------------------------------------------------------
  ZWECK
  - Speichert die bereits erzeugten CipherBytes (FCipherBytes) in eine Datei –
    jedoch nicht als „rohe“ Ciphertext-Bytes, sondern als *Containerformat*.
  - Der Container verpackt Ciphertext *plus* notwendige Metadaten (z.B. Modus,
    ggf. IV), damit eine spätere Entschlüsselung eindeutig möglich ist.

  EIGENSCHAFTEN (Stichpunkte)
  - Speichert nur, wenn tatsächlich Daten vorhanden sind (Length(FCipherBytes) > 0).
  - Verwendet ein einheitliches Containerlayout:
    * ECB: kein IV nötig → IV-Feld wird mit ZERO_IV belegt (Platzhalter).
    * CBC: IV zwingend nötig → tatsächlicher FCipherIV wird gespeichert.
  - Trennt Verantwortlichkeiten:
    * BuildContainerBytes(...) baut den Byte-Container (Daten + Metadaten).
    * SaveContainerToFile(...) kümmert sich um Dateizugriff/Fehlerbehandlung.
  - Protokolliert Benutzerabbrüche und Ergebnis im StatusMemo.

  VERWENDUNG IM PROJEKT
  - Typischer UI-Flow: Erst Verschlüsseln → FCipherBytes/FCipherIV/FCipherMode setzen
    → anschließend über „Speichern“ den verschlüsselten Inhalt als Datei-Container ablegen.
  - Gegenstück ist (je nach Projektstruktur) ein „Laden/Entschlüsseln“-Pfad, der den
    Container wieder parst und Modus/IV/Ciphertext rekonstruiert.

  SICHERHEIT / EINORDNUNG
  - Das Speichern von IVs ist bei CBC *normal und korrekt*: IV muss nicht geheim sein,
    aber sollte pro Nachricht einzigartig und idealerweise zufällig/unvorhersehbar sein.
  - WICHTIG: Ein Container mit ECB/CBC liefert (typischerweise) nur *Vertraulichkeit*.
    Ohne Integritätsschutz (z.B. HMAC / Encrypt-then-MAC / AEAD wie GCM) kann ein
    Angreifer Ciphertext oder IV manipulieren → Entschlüsselung ergibt verfälschten
    Klartext oder Padding-Fehler. Merksatz: „Verschlüsselung ≠ Integrität“.

  REFERENZEN / HINWEISE
  - AES-Standard: NIST FIPS 197 (Rijndael von Joan Daemen & Vincent Rijmen).
  - Blockcipher-Modi: NIST SP 800-38A (u.a. ECB, CBC; enthält auch Testvektoren).
  - Container-Design (allgemein): Magic-Header, Versionierung, Längenfelder, Checks.
  ----------------------------------------------------------------------------
}
var
  Container: TBytes;                // Byte-Puffer für den fertig aufgebauten Container (Metadaten + Ciphertext)
begin

  // Defensive Programmierung: Ohne CipherBytes gibt es nichts Sinnvolles zu speichern.
  // Typische Fehlerquelle in Projekten: „Speichern“ wird gedrückt, bevor überhaupt
  // eine Verschlüsselung durchgeführt wurde.

  if Length(FCipherBytes) = 0 then
  begin
    StatusMemo.Lines.Add('Hinweis: Es gibt keine CipherBytes zum Speichern.');
    Exit;         // Früher Exit hält den Ablauf übersichtlich und vermeidet unnötige Sonderfälle.
  end;


  // UI-Interaktion: Benutzer wählt Zielpfad/Dateiname.
  // Wenn abgebrochen wird, darf NICHT gespeichert werden – und wir protokollieren das sauber.

  if not SaveDialog1.Execute then
  begin
    StatusMemo.Lines.Add('Speichern abgebrochen.');
    Exit;     // Früher Exit statt „if-verschachteln“ → klarer Kontrollfluss.
  end;

  // ECB: IV egal -> ZERO_IV, CBC: FCipherIV wird gespeichert
  // DIDAKTIK:
  // - CBC benötigt den IV, sonst kann der erste Block nicht korrekt entschlüsselt werden.
  // - ECB hat keinen IV. Damit das Dateiformat trotzdem immer gleich aufgebaut ist,
  //   wird ein definierter Platzhalter gespeichert (ZERO_IV). So lernen Schüler:
  //   „IV gehört zu CBC, nicht zu ECB“, ohne dass der Parser Sonderfälle braucht.

  if FCipherMode = acmCBC then
    Container := BuildContainerBytes(FCipherBytes, FCipherMode, FCipherIV)
  // FCipherMode wird direkt übernommen (CBC) und FCipherIV als Metadatum mitgespeichert.
  // Typische Fehlerquelle: IV vergessen zu speichern/übertragen → Entschlüsselung scheitert.

  else
    Container := BuildContainerBytes(FCipherBytes, acmECB, ZERO_IV);
  // HINWEIS: Hier wird acmECB explizit gesetzt (statt FCipherMode).
  // Das ist didaktisch eindeutig und verhindert, dass bei „sonstigen“ Modi ungewollt
  // ein Container mit inkonsistenten Metadaten entsteht.
  // ZERO_IV ist *kein* Sicherheitsfeature, sondern nur ein Format-Platzhalter.

  // Schreiben auf die Platte ist kapselt: Diese Prozedur entscheidet „was“, die Hilfsfunktion „wie“.
  // Vorteil: Kryptologie/Containerlogik bleibt testbar, I/O-Details sind isoliert.

  if SaveContainerToFile(SaveDialog1.FileName, Container) then
  begin
     // Erfolgsmeldung: Pfad und Cipher-Länge sind für Nutzer hilfreich,
    // um zu sehen, dass tatsächlich Bytes gespeichert wurden.

    StatusMemo.Lines.Add('Container gespeichert: ' + SaveDialog1.FileName);
    StatusMemo.Lines.Add('Cipher-Länge: ' + IntToStr(Length(FCipherBytes)) + ' Bytes');

    // HINWEIS: Diese Länge ist die Ciphertext-Länge, nicht zwingend die Containerlänge.
    // (Container ist in der Regel größer wegen Header/Modus/IV/Längenfeldern.)
  end
  else
    StatusMemo.Lines.Add('Fehler: Konnte Container nicht speichern.');
    // HINWEIS: Im Fehlerfall wäre (optional) eine genauere Ursache interessant
    // (z.B. Rechte/Datenträger voll/Path ungültig) – das gehört aber in SaveContainerToFile(...).

end;

procedure TAES_256_Lab.LadenClick(Sender: TObject);
  {
  ----------------------------------------------------------------------------
  PROZEDUR: LadenClick
  ----------------------------------------------------------------------------
  ZWECK
  - Lädt eine zuvor gespeicherte Datei (AES-Container) von der Platte, prüft/zerlegt
    den Container und übernimmt die Ergebnisse in die Arbeitsvariablen:
      * FCipherBytes  → eigentlicher Ciphertext (verschlüsselte Nutzdaten)
      * FCipherMode   → welcher Modus wurde beim Speichern verwendet (ECB oder CBC)
      * FCipherIV     → IV (nur bei CBC relevant; bei ECB typischerweise ZERO_IV)
  - Danach wird der Ciphertext zur Kontrolle als Hex im Memo angezeigt.

  EIGENSCHAFTEN (stichpunktartig)
  - Benutzerfreundlich: Abbruch im OpenDialog ist ein normaler Pfad, kein Fehler.
  - Robust: Dateiinhalt wird erst geladen, dann *geparst/validiert*, bevor interne
    Zustände gesetzt werden (fail-fast, klare Fehlerpfade).
  - Didaktisch: Hex-Ausgabe visualisiert Binärdaten (Blockgrenzen, Vergleiche, Debug).
  - Saubere Schichten:
    * LoadContainerFromFile(...) = reines Datei-I/O (Bytes lesen)
    * ParseContainerBytes(...)   = Formatprüfung/Extraktion (Container → Felder)
    * GUI hier                  = Ablaufsteuerung + Statusanzeigen

  VERWENDUNG IM PROJEKT
  - Typischer Ablauf: Container laden → FCipherBytes/FCipherMode/FCipherIV setzen →
    anschließend Entschlüsselung mit exakt diesen Parametern.
  - Diese Routine ist das Gegenstück zum „Speichern“-Pfad (BuildContainerBytes + Save...).

  SICHERHEIT / EINORDNUNG (Stand allgemein)
  - Der Container speichert Ciphertext + Metadaten (Modus/IV). Das ist notwendig für
    korrekte Entschlüsselung, aber es ist *kein* Integritätsschutz.
  - Ohne Authentifizierung (z.B. HMAC / Encrypt-then-MAC / AEAD wie GCM) kann ein
    Angreifer Containerdaten manipulieren:
      * CBC erlaubt „Bit-Flipping“ (gezielte Klartextänderungen in Folgeböcken).
      * Unterschiedliches Fehlerverhalten (z.B. bei Padding) kann zu Oracles führen.
  - Merksatz: „Verschlüsselung ≠ Integrität.“

  REFERENZEN / HINWEISE
  - NIST FIPS 197: Advanced Encryption Standard (AES) – Rijndael (Daemen/Rijmen).
  - NIST SP 800-38A: Modes of Operation (ECB/CBC/CTR …) + Testvektoren.
  - Container-Design allgemein: Magic Header, Versionierung, Längenfelder, Plausibilitätschecks.
  ----------------------------------------------------------------------------
}
var
  Container: TBytes;          // Rohdaten der Datei: kompletter Container als Bytefolge
  Mode: TAESContainerMode;    // Ergebnis aus dem Parser: im Container gespeicherter Modus (ECB/CBC)
  IV: TByteArray16;           // Ergebnis aus dem Parser: 16-Byte IV (bei CBC relevant, sonst meist ZERO_IV)
  Cipher: TBytes;             // Ergebnis aus dem Parser: extrahierter Ciphertext (ohne Header/Metadaten)
begin
  // Schritt 1: Benutzer wählt die Datei.
  // Abbruch ist kein „Fehler“, sondern eine normale Benutzerentscheidung.
  if not OpenDialog1.Execute then
  begin
    StatusMemo.Lines.Add('Laden abgebrochen.');
    Exit; // Früher Exit verhindert unnötige Folgeaktionen und hält die Logik flach.
  end;

  // Schritt 2: Datei-I/O – hier wird ausschließlich gelesen, noch nicht interpretiert.
  // Typische Fehlerquellen: fehlende Rechte, ungültiger Pfad, Datei in Benutzung, Datenträgerfehler.
  if not LoadContainerFromFile(OpenDialog1.FileName, Container) then
  begin
    StatusMemo.Lines.Add('Fehler: Konnte Datei nicht laden.');
    Exit; // Fail-fast: Ohne Bytes kann nicht geparst werden.
  end;

  // Schritt 3: Parser/Validator – hier wird das Containerformat geprüft und zerlegt.
  // Typische Prüfungen (abhängig von deiner Implementierung):
  // - Magic/Header korrekt?
  // - Version bekannt?
  // - Modus-Feld plausibel (nur bekannte Werte)?
  // - Längenfelder konsistent (keine Überläufe / keine negativen / keine Off-by-one)?
  // - IV-Länge exakt 16 Byte, Cipher-Länge plausibel (bei Blockcipher oft Vielfaches von 16, je nach Padding).
  if not ParseContainerBytes(Container, Cipher, Mode, IV) then
  begin
    StatusMemo.Lines.Add('Fehler: Datei ist kein gültiger Container oder beschädigt.');
    Exit; // WICHTIG: Erst nach erfolgreichem Parse interne Zustände ändern (sonst „halbgeladener“ Zustand).
  end;

  // Schritt 4: Übernahme in Projektzustand.
  // Copy(Cipher) stellt sicher, dass FCipherBytes eine eigene dynamische Bytefolge bekommt.
  // (In Delphi/Lazarus sind dynamische Arrays referenzgezählt; Copy kann helfen, Seiteneffekte zu vermeiden,
  // falls Cipher später noch verändert wird. Je nach Compiler/Optimierung kann Copy auch redundant sein.)
  FCipherBytes := Copy(Cipher);
  FCipherMode  := Mode; // Der Modus steuert später die Entschlüsselung (ECB/CBC).
  FCipherIV    := IV;   // Bei CBC zwingend nötig; bei ECB meist ZERO_IV als Platzhalter.

  // Statusausgabe: macht transparent, was geladen wurde (wichtig für Debugging/Lehre).
  StatusMemo.Lines.Add('Container geladen: ' + OpenDialog1.FileName);
  if FCipherMode = acmCBC then
    StatusMemo.Lines.Add('Mode: CBC (IV im Container gespeichert)')
    // DIDAKTIK: CBC braucht den IV zur Rekonstruktion des ersten Blocks.
    // Der IV ist nicht geheim, aber sollte pro Nachricht einzigartig sein.
  else
    StatusMemo.Lines.Add('Mode: ECB');
    // DIDAKTIK: ECB verwendet keinen IV; gleiche Klartextblöcke → gleiche Cipherblöcke (Muster sichtbar).
    // In realen Systemen wird ECB daher i.d.R. vermieden, außer in sehr speziellen Fällen.

  // Anzeigezweck: Ciphertext ist Binärdaten → Hex ist eine robuste Debug-/Lehrdarstellung.
  // Typische Fehlerquelle: Binärdaten als Text interpretieren (Encoding-Probleme, Steuerzeichen, Datenverlust).
  MemoCipher.Clear;
  MemoCipher.Lines.Add('Geladener Cipher (Hex, nur Anzeige):');
  MemoCipher.Lines.Add(BytesToHex(FCipherBytes));
  // HINWEIS: Bei sehr großen Dateien kann Hex-Ausgabe das UI ausbremsen (viel Text).
  // Für Lehrzwecke ok; produktiv würde man ggf. kürzen (z.B. nur erste/letzte N Bytes).
end;


procedure TAES_256_Lab.NIST_CBCClick(Sender: TObject);
{------------------------------------------------------------------------------
  PROZEDUR: NIST_CBCClick
  ----------------------------------------------------------------------------
  TITEL/NAME
  - NIST-Test (AES-256 CBC, Single Block) – Known Answer Test (KAT)

  ZWECK
  - Prüft, ob die eigene AES-256-Implementierung im CBC-Modus für einen exakt
    definierten NIST-Referenzfall (Key/IV/Plaintext → erwarteter Ciphertext)
    das korrekte Ergebnis liefert.
  - Optional wird zusätzlich die Entschlüsselung getestet („Roundtrip“), um
    Encrypt- und Decrypt-Pfad gemeinsam zu validieren.

  EIGENSCHAFTEN (stichpunktartig)
  - Deterministischer Test: feste Eingabedaten (Key/IV/PT) und festes Soll-Ergebnis (CT).
  - Single-Block-Test (16 Byte): keine Padding-Fragen, daher ideal als Einstieg.
  - Prüft zwei Dinge gleichzeitig:
    * AES-Kern (KeySchedule + Rundenfunktionen) muss korrekt sein
    * CBC-Modus (XOR mit IV / Verkettungslogik) muss korrekt sein
  - Vergleich erfolgt als Hex-String (robust für Debugging, leicht mit Spezifikation abzugleichen).

  VERWENDUNG IM PROJEKT
  - Als „Vertrauensanker“ im Lehrprojekt: Bevor man eigene Dateien/Container verschlüsselt,
    prüft man mit einem offiziellen KAT, ob die Implementierung grundsätzlich korrekt arbeitet.
  - Ergänzend zu weiteren Tests (z.B. ECB-KAT, Multi-Block-CBC, Randomized Tests).

  SICHERHEIT/ EINORDNUNG
  - Ein KAT beweist keine „Sicherheit“, sondern primär Korrektheit gegenüber bekannten
    Referenzdaten. Er reduziert die Wahrscheinlichkeit klassischer Implementierungsfehler
    (Endianness, falsches Round-Key-Handling, falsche XOR-Verkettung etc.).
  - CBC benötigt einen IV; der IV ist nicht geheim, muss aber (pro Nachricht) eindeutig und
    idealerweise zufällig sein. In diesem Test ist der IV absichtlich fest, weil es um
    Reproduzierbarkeit geht.
  - Hinweis: CBC allein bietet keine Integrität. In realen Systemen ergänzt man Authentizität/
    Integrität (HMAC/AEAD), das ist hier aber nicht Ziel des KAT.

  REFERENZEN / HINWEISE
  - NIST FIPS 197: Advanced Encryption Standard (AES) – Rijndael (Joan Daemen & Vincent Rijmen).
  - NIST SP 800-38A: Block Cipher Modes of Operation (u.a. CBC) inkl. Testvektoren.
  - NIST CAVP (Cryptographic Algorithm Validation Program): KATs/Validierungsdaten für AES.
------------------------------------------------------------------------------}
const
  // Testvektoren als Hex-Strings (bewusst „hart kodiert“ für Reproduzierbarkeit)
  // KEY_HEX: 32 Bytes = 256 Bit Schlüsselmaterial
  // IV_HEX : 16 Bytes = 128 Bit Initialisierungsvektor (CBC-Startwert)
  // PT_HEX : 16 Bytes = 1 Block Klartext
  // CT_HEX : 16 Bytes = erwarteter Ciphertext laut NIST-Vektor
  KEY_HEX = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
  IV_HEX  = '000102030405060708090a0b0c0d0e0f';
  PT_HEX  = '6bc1bee22e409f96e93d7e117393172a';
  CT_HEX  = 'f58c4c04d6e5f1ba779eabfb5f7bfbd6';
var
  KeyBytes, PtBytes, CtExpected, CtActual, PtDecrypted: TBytes;
  // KeyBytes   : dynamisches Array für den 32-Byte AES-256 Schlüssel
  // PtBytes    : dynamisches Array für den 16-Byte Klartextblock
  // CtExpected : dynamisches Array für den 16-Byte Referenz-Ciphertext (Soll)
  // CtActual   : dynamisches Array für das tatsächlich berechnete Ergebnis (Ist)
  // PtDecrypted: Ergebnis der Rück-Entschlüsselung (Soll: wieder PT_HEX)
  Ctx: TAES256Context;
  // Ctx: Kontext/State für AES-256 (typischerweise: RoundKeys/KeySchedule, ggf. Parameter)
  IV: TByteArray16;
  // IV: 16-Byte Block für CBC (wichtig: CBC arbeitet blockweise mit exakt 16 Byte)

  procedure BytesToBlock16(const Src: TBytes; out Dst: TByteArray16);
  begin
    // Diese Hilfsroutine zwingt den IV (oder allgemein einen Block) auf exakt 16 Bytes.
    // DIDAKTIK: CBC (wie AES selbst) arbeitet in 128-Bit-Blöcken. Alles andere ist ein Fehler.
    // Typische Fehlerquelle: Arrays falscher Länge oder Off-by-one beim Move().
    if Length(Src) <> 16 then
      raise Exception.Create('NIST-CBC-Test: Blocklänge ist nicht 16 Byte.');

    Dst[0] := 0; // Compiler-Hinweis beruhigen
    // HINWEIS: Dieser Schreibzugriff stellt sicher, dass Dst als „benutzt“ gilt.
    // In manchen Lazarus/Delphi-Konstellationen reduziert das Warnungen über „uninitialisierte Variable“.
    // Kryptografisch hat diese Zeile keinen Effekt, da sie direkt danach überschrieben wird.

    Move(Src[0], Dst[0], 16);
    // Kritischer Schritt:
    // - Move kopiert 16 Bytes 1:1. Voraussetzung: Src hat Länge 16 (oben geprüft).
    // - Typische Fehlerquelle: falscher Count (15/17) oder Src[1] statt Src[0] (Off-by-one).
  end;

begin
  StatusMemo.Clear;
  MemoCipher.Clear;
  // UI/Didaktik: Vor jedem Test alte Ausgaben entfernen, damit das Ergebnis eindeutig ist.

  StatusMemo.Lines.Add('--- NIST AES-256 CBC (Single Block) Test ---');
  // Statuszeile: hilft, Logs zu unterscheiden, wenn mehrere Tests nacheinander laufen.

  // Hex -> Bytes
  KeyBytes   := HexToBytes(KEY_HEX);
  // Erwartung: 32 Bytes. Typische Fehlerquelle: HexToBytes muss 2 Hex-Zeichen → 1 Byte korrekt umsetzen.
  // HINWEIS: Bei ungültigen Hex-Zeichen sollte HexToBytes sauber fehlschlagen (Exception/False), sonst
  // können stille Fehler entstehen, die der KAT entlarvt.

  PtBytes    := HexToBytes(PT_HEX);
  // Erwartung: 16 Bytes (genau ein AES-Block). Kein Padding beteiligt → ideal für Einsteiger-KAT.

  CtExpected := HexToBytes(CT_HEX);
  // Erwartung: 16 Bytes. Didaktisch: CtExpected könnte auch direkt byteweise verglichen werden.
  // (Im aktuellen Code wird stattdessen der Hex-String-Vergleich genutzt, siehe weiter unten.)

  // IV vorbereiten
  BytesToBlock16(HexToBytes(IV_HEX), IV);
  // Wichtig: IV ist bei CBC Teil der Berechnung:
  //   C1 = AES_K( P1 XOR IV )
  // Typische Fehlerquelle: IV in falscher Byte-Reihenfolge (Endianness) – bei Bytes ist das „roh“,
  // aber Fehler passieren beim Umwandeln/Interpretieren.

  // AES KeySchedule
  AES256InitKey(KeyBytes, Ctx);
  // Design-Idee: Schlüsselaufbereitung (KeySchedule) einmalig vorbereiten, dann mehrfach nutzen.
  // Typische Fehlerquelle: falsche Schlüsselgröße (AES-256: 32 Bytes). Ein KAT deckt das auf.

  // CBC Encrypt (1 Block)
  CtActual := AES256EncryptCBC(PtBytes, IV, Ctx);
  // Didaktik: Bei Single-Block-CBC ist die Formel besonders anschaulich:
  //   CtActual = AES_K( PtBytes XOR IV )
  // Fehlerquellen, die hier auffallen:
  // - XOR vor der AES-Runde vergessen
  // - XOR mit falschem IV (oder IV nicht 16 Byte)
  // - falscher RoundKey-Index / KeySchedule-Fehler

  // Ausgabe
  MemoCipher.Lines.Add('Key:       ' + KEY_HEX);
  MemoCipher.Lines.Add('IV:        ' + IV_HEX);
  MemoCipher.Lines.Add('Plaintext: ' + PT_HEX);
  MemoCipher.Lines.Add('Expected:  ' + CT_HEX);
  MemoCipher.Lines.Add('Actual:    ' + BytesToHex(CtActual));
  // Hex-Ausgabe ist „Debug-freundlich“: Binärdaten werden stabil vergleichbar gemacht.
  // Typische Fehlerquelle: Binärdaten als Text anzeigen → Encoding-Probleme, Steuerzeichen, unlesbar.

  if SameText(BytesToHex(CtActual), CT_HEX) then
    StatusMemo.Lines.Add('OK: CBC-Verschlüsselung stimmt mit NIST-Testvektor.')
  else
    StatusMemo.Lines.Add('FEHLER: CBC-Ausgabe weicht vom NIST-Testvektor ab!');
  // Vergleich als String:
  // - SameText erlaubt A–F vs a–f, ohne dass Bytes sich unterscheiden.
  // - Alternativ könnte man byteweise vergleichen (CtActual gegen CtExpected).
  // HINWEIS: Byteweiser Vergleich wäre „strenger“ und würde zusätzliche Umwandlung sparen,
  // aber für Lehrzwecke ist Hex-Vergleich sehr anschaulich.

  // Optional: CBC Decrypt (zur Kontrolle zurück)
  PtDecrypted := AES256DecryptCBC(CtActual, IV, Ctx);
  // Roundtrip-Prinzip: Wenn Decrypt korrekt ist, muss wieder exakt der ursprüngliche Plaintext entstehen.
  // Typische Fehlerquelle: IV-Handling beim Decrypt (bei CBC: P1 = AES^-1(C1) XOR IV).

  MemoCipher.Lines.Add('Decrypted: ' + BytesToHex(PtDecrypted));
  // Didaktisch: zeigt sofort, ob Entschlüsselung exakt zurückführt (ohne Text-Encoding-Probleme).

  if SameText(BytesToHex(PtDecrypted), PT_HEX) then
    StatusMemo.Lines.Add('OK: CBC-Entschlüsselung liefert wieder den Klartext.')
  else
    StatusMemo.Lines.Add('FEHLER: CBC-Entschlüsselung liefert NICHT den Klartext.');

  CtExpected:=CtExpected;    // Kompilermeldung "never used" abschalten
  // HINWEIS (Quality-Gate / Stil):
  // - CtExpected wird oben zwar geladen, aber im aktuellen Vergleich nicht verwendet.
  // - Diese Selbstzuweisung ist ein gängiger Trick, um Warnungen zu unterdrücken.
  // - Didaktisch könntest du später (ohne Krypto-Code zu ändern) alternativ CtExpected wirklich nutzen,
  //   z.B. durch einen byteweisen Vergleich oder BytesToHex(CtExpected) im Output.
end;

procedure TAES_256_Lab.NIST_TestClick(Sender: TObject);
    {
 ------------------------------------------------------------------------------
  PROZEDUR: NIST_TestClick
  ----------------------------------------------------------------------------
  TITEL/NAME
  - NIST-Test (AES-256 Single-Block / Known Answer Test, KAT)

  ZWECK
  - Führt einen „Known Answer Test“ (KAT) für AES-256 auf genau EINEM 16-Byte-Block aus.
  - Verifiziert damit den AES-Kern (KeySchedule + Blockverschlüsselung) gegen einen
    offiziellen Referenzwert (Ciphertext), wie er in NIST-Testvektoren veröffentlicht ist.

  EIGENSCHAFTEN (stichpunktartig)
  - Deterministischer Test: feste Eingaben (Key + Plaintext) → fest erwartetes Ergebnis (Ciphertext).
  - Single-Block: Keine Verkettung (IV), kein Padding, kein Block-Loop → ideal zur Fehlereingrenzung.
  - Vergleich als Hex-String mit SameText(...): robust gegenüber Groß-/Kleinschreibung der Hex-Ausgabe.
  - Enthält didaktische Hilfsroutinen zur sicheren 16-Byte-Block-Konvertierung.

  VERWENDUNG IM PROJEKT
  - „Basis-Selbsttest“ der Implementierung: Erst wenn dieser KAT besteht, lohnt es sich,
    CBC/Container/Dateitests zu interpretieren.
  - Gut geeignet für Unterricht: Studierende können einzelne AES-Teilschritte absichtlich
    verändern (z.B. ShiftRows) und sehen sofort, dass der KAT fehlschlägt.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Ein KAT ist ein Korrektheitstest, kein Sicherheitsbeweis.
  - Besteht der Test, ist das ein starker Hinweis, dass AES-256 für diesen Vektor korrekt
    implementiert ist (S-Box, Runden, MixColumns, AddRoundKey, KeySchedule).
  - Er sagt nichts darüber aus, ob das Gesamtsystem sicher eingesetzt wird
    (z.B. Moduswahl, IV-Handling, Integritätsschutz, Side-Channel-Risiken).

  REFERENZEN / HINWEISE
  - NIST FIPS 197: Advanced Encryption Standard (AES) – Rijndael (Joan Daemen & Vincent Rijmen).
  - NIST CAVP AES KAT: Known Answer Tests/Validierungsdaten für systematische Prüfungen.
  - NIST SP 800-38A: Modes of Operation (für die nächsten Tests wie CBC/CTR etc.).
 ----------------------------------------------------------------------------}
   const
  // Testvektor als Hex-Strings:
  // KEY_HEX: 32 Bytes (256 Bit) Schlüssel
  // PT_HEX : 16 Bytes (128 Bit) Klartextblock
  // CT_HEX : 16 Bytes (128 Bit) erwarteter Ciphertext
  KEY_HEX = '603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4';
  PT_HEX  = '6bc1bee22e409f96e93d7e117393172a';
  CT_HEX  = 'f3eed1bdb5d2a03c064b5a7e3db181f8';
var
  KeyBytes, PtBytes, CtExpected, CtActual: TBytes;
  // KeyBytes   : 32-Byte AES-256 Schlüsselmaterial (aus KEY_HEX)
  // PtBytes    : 16-Byte Klartext (aus PT_HEX)
  // CtExpected : erwarteter 16-Byte Ciphertext (aus CT_HEX) – hier nur zum „Vollständigkeit laden“
  // CtActual   : tatsächlich berechneter 16-Byte Ciphertext als TBytes (für Hex-Ausgabe/Vergleich)
  Ctx: TAES256Context;
  // Ctx: AES-256 Kontext mit KeySchedule (RoundKeys). Wird einmal initialisiert, dann genutzt.
  InBlock, OutBlock: TByteArray16;
  // InBlock : Klartext als fester 16-Byte Blocktyp (AES arbeitet auf 128 Bit Blöcken)
  // OutBlock: Ergebnisblock der AES-Verschlüsselung (ebenfalls 16 Byte)

  procedure BytesToBlock16(const Src: TBytes; out Dst: TByteArray16);
  begin
    // DIDAKTIK: Diese Hilfsroutine erzwingt „Blockdenken“:
    // AES256EncryptBlock erwartet exakt 16 Bytes. Ein falsches Array darf nicht still
    // „irgendwie“ verarbeitet werden, sonst entstehen schwer auffindbare Fehler.
    if Length(Src) <> 16 then
      raise Exception.Create('NIST-Test: Blocklänge ist nicht 16 Byte.');
      // Typische Fehlerquelle: falsche Eingabelänge durch falsche Hex-Konvertierung
      // oder versehentliches Padding/Truncation. Der KAT soll genau solche Fehler finden.

    Dst[0] := 0; // Compiler-Hinweis beruhigen
    // HINWEIS: Kein Kryptoschritt. Dient nur dazu, bestimmte Compiler-/Analysewarnungen
    // zu vermeiden („Dst könnte uninitialisiert sein“). Direkt danach wird komplett überschrieben.

    Move(Src[0], Dst[0], 16);
    // Kritischer Schritt: 16 Bytes 1:1 kopieren.
    // Fehlerquellen: Off-by-one (15/17), falscher Startindex, Src zu kurz (oben geprüft).
  end;

  function Block16ToBytes(const B: TByteArray16): TBytes;
  begin
    result:=nil;
    // HINWEIS (Quality-Gate): Diese Initialisierung ist in Pascal oft nicht nötig,
    // weil SetLength(Result, 16) das dynamische Array neu anlegt.
    // Sie ist hier aber harmlos und kann Warnungen/Lesbarkeit beeinflussen – nicht entfernen.

    SetLength(Result, 16);
    // Ergebnis wird auf exakt 16 Bytes dimensioniert (ein AES-Block).

    Move(B[0], Result[0], 16);
    // 16-Byte Block → dynamisches Byte-Array, z.B. für BytesToHex(...) oder weitere Verarbeitung.
    // Typische Fehlerquelle: falsche Länge oder falscher Move-Count.
  end;

begin
  StatusMemo.Clear;
  MemoCipher.Clear;
  // UI/Didaktik: Alte Testausgaben entfernen, damit der aktuelle Test eindeutig nachvollziehbar ist.

  StatusMemo.Lines.Add('--- NIST AES-256 ECB (Single Block) Test ---');
  // DIDAKTIK: In vielen Quellen steht „ECB“, weil ein einzelner Block ohne Verkettung
  // dem ECB-Fall entspricht. In Wahrheit wird hier nur der AES-Kern auf einem Block getestet.

  // Hex -> Bytes
  KeyBytes   := HexToBytes(KEY_HEX);
  // Erwartung: 32 Bytes. Fehlerquellen: Hex-Parsing, falsche Schlüssel-Länge (z.B. 16/24 statt 32).

  PtBytes    := HexToBytes(PT_HEX);
  // Erwartung: 16 Bytes. Single-Block ohne Padding – ideal zur Kernprüfung.

  CtExpected := HexToBytes(CT_HEX);
  // Erwartung: 16 Bytes. Wird hier nicht direkt byteweise verglichen, aber als Referenz geladen.
  // HINWEIS: Das spätere „CtExpected:=CtExpected“ ist ein Warnungs-Suppressor.

  // Bytes -> 16-Byte Block
  BytesToBlock16(PtBytes, InBlock);
  // Wichtig: AES256EncryptBlock arbeitet mit einem festen Blocktyp (TByteArray16).
  // Das verhindert „zufällige“ Längen und macht den Blockbegriff im Lehrprojekt sichtbar.

  // AES Core
  AES256InitKey(KeyBytes, Ctx);
  // KeySchedule für AES-256 (14 Runden) erzeugen.
  // Typische Fehlerquelle: falsche RoundKey-Berechnung, falsche Rcon-Anwendung, Endianness-Missverständnisse
  // (bei AES intern byteorientiert, aber beim Implementieren/Debuggen passieren trotzdem Verwechslungen).

  AES256EncryptBlock(InBlock, OutBlock, Ctx);
  // Reiner AES-Block-Encrypt:
  //   OutBlock = AES_K(InBlock)
  // Keine IVs, keine Verkettung, kein Padding, kein Multi-Block-Loop.
  // Genau das macht den Test so „sauber“ zur Fehlersuche.

  CtActual := Block16ToBytes(OutBlock);
  // Für Ausgabe/Vergleich wird der Block wieder als dynamisches Array bereitgestellt.

  // Ausgabe
  MemoCipher.Lines.Add('Key:       ' + KEY_HEX);
  MemoCipher.Lines.Add('Plaintext: ' + PT_HEX);
  MemoCipher.Lines.Add('Expected:  ' + CT_HEX);

  MemoCipher.Lines.Add('Actual:    ' + BytesToHex(CtActual));
  // Hex ist die Standarddarstellung für Binärdaten beim Debugging und beim Abgleich mit Standards.

 if SameText(BytesToHex(CtActual), CT_HEX) then
    StatusMemo.Lines.Add('OK: AES-256 Blocktest bestanden.')
  else
    StatusMemo.Lines.Add('FEHLER: Ausgabe weicht vom NIST-Testvektor ab!');
  // Vergleich als String:
  // - SameText macht den Vergleich unempfindlich gegenüber A–F vs a–f.
  // - Typische Fehlerquelle: BytesToHex liefert Großbuchstaben, CT_HEX ist klein (oder umgekehrt).
  // Alternative (Übung): CtActual byteweise gegen CtExpected vergleichen (schneller/ohne Hex).

    CtExpected:=CtExpected;    // Kompilermeldung never used abschalten
    // HINWEIS (Quality-Gate):
    // - CtExpected wird geladen, aber nicht benutzt → daher Warnung.
    // - Diese Selbstzuweisung unterdrückt sie, ohne den Testablauf zu verändern.
    // - Didaktischer Ausbau: CtExpected im Vergleich wirklich nutzen (byteweise) oder zusätzlich ausgeben.
end;


procedure TAES_256_Lab.Selftest_ButtonClick(Sender: TObject);
  {
  ----------------------------------------------------------------------------
  PROZEDUR: Selftest_ButtonClick
  ----------------------------------------------------------------------------
  TITEL/NAME
  - Selftest_ButtonClick – UI-Auslöser für den AES-256 Selbsttest (KAT/Validierung)

  ZWECK
  - Startet einen Selbsttest der AES-256-Implementierung und zeigt die Ergebnisse
    verständlich in zwei Memos an:
      * StatusMemo: kurze, menschliche Statusmeldungen („gestartet“, „ok“, „fehler“)
      * MemoCipher: ausführlicher Report-Text („Report“) zum Nachlesen/Debuggen

  EIGENSCHAFTEN (stichpunktartig)
  - GUI-Eventhandler: enthält bewusst nur „Ablaufsteuerung“ und Ausgabe.
  - Testlogik ist gekapselt: AES256SelfTest(Report) liefert
      * Ok (Boolean): maschinenfreundliches Gesamt-Ergebnis
      * Report (string): menschenfreundliche Detailinformationen
  - Räumt die Ausgaben vor dem Testlauf auf (Clear), um Verwechslungen zu vermeiden.
  - Keine Kryptorechnung in dieser Prozedur selbst → bessere Wartbarkeit/Testbarkeit.

  VERWENDUNG IM PROJEKT
  - Wird vom Selftest-Button in der Oberfläche aufgerufen.
  - Dient als schneller „Gesundheitscheck“ der Implementierung, z.B.:
    * nach Codeänderungen
    * beim Unterricht/Debuggen
    * vor dem Verschlüsseln echter Daten/Container

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Ein bestandener Selbsttest ist ein starker Hinweis auf *Korrektheit* (gegen Referenzdaten),
    aber kein mathematischer Sicherheitsbeweis.
  - Selbsttests sind essenziell, weil Kryptofehler oft „still“ sind: Das Programm läuft,
    aber ein Byte ist falsch → Entschlüsselung/Interoperabilität scheitert.
  - Gute Praxis: KATs (Known Answer Tests) sind Minimum; weiterführend gibt es MCTs
    (Monte Carlo Tests) und große Fehlersammlungen (z.B. Google Wycheproof).

  REFERENZEN / HINWEISE
  - NIST FIPS 197: AES (Rijndael von Joan Daemen & Vincent Rijmen).
  - NIST SP 800-38A: Betriebsmodi + Testvektoren (für CBC/CTR usw.).
  - NIST CAVP: AES KAT/MCT Validierungsdaten.
  ----------------------------------------------------------------------------
}
var
  Report: string;   // Sammeltext mit Detailergebnissen aus dem Selbsttest (für Schüler/Debugging)
  Ok: Boolean;      // Gesamtstatus: True = alle Teiltests bestanden, False = mindestens ein Test fehlgeschlagen
begin
  // UI-Reset: Alte Ausgaben entfernen, damit der aktuelle Lauf eindeutig nachvollziehbar ist.
  // Didaktik: Lernende sehen klar, welche Zeilen „zu diesem Klick“ gehören.
  StatusMemo.Clear;
  MemoCipher.Clear;

  // Kurzer Status „Ampel“: Der Nutzer sieht sofort, dass der Test gestartet wurde.
  StatusMemo.Lines.Add('--- AES-256 Selftest gestartet ---');

  // Initialisierung des Reports:
  // - Ein leerer String ist ein definierter Startzustand.
  // - Typische Fehlerquelle in Tests: Report enthält noch Text vom letzten Lauf → Verwirrung.
  Report := '';

  // Aufruf der eigentlichen Testlogik:
  // - Hier passiert (je nach Implementierung) z.B. KATs gegen NIST-Vektoren,
  //   ggf. ECB-Blocktests, CBC-Tests, Randfälle, etc.
  // - Trennung der Schichten: Diese Prozedur bleibt „UI“, AES256SelfTest ist „Fachlogik“.
  Ok := AES256SelfTest(Report);

  // Report ins Memo (für Lernzwecke):
  // - Enthält im Idealfall nachvollziehbare Details: welche Tests, welche Soll/Ist-Werte,
  //   und ggf. an welcher Stelle es scheiterte.
  MemoCipher.Lines.Add(Report);          // Report ins Memo (für Lernzwecke)

  // Abschlussmeldung: Kurz und eindeutig für den Benutzer.
  if Ok then
    StatusMemo.Lines.Add('--- AES-256 Selftest ERFOLGREICH abgeschlossen ---')
  else
    StatusMemo.Lines.Add('--- AES-256 Selftest FEHLGESCHLAGEN: Implementierung prüfen! ---');
    // HINWEIS: Im Fehlerfall ist der Report entscheidend: dort sollte stehen, welcher Teiltest
    // fehlschlug (z.B. KeySchedule, Blockverschlüsselung, CBC-Verkettung, Hex-Konvertierung).
end;








procedure TAES_256_Lab.FormCreate(Sender: TObject);
{
  ============================================================================
  PROZEDUR: FormCreate
  ============================================================================
  TITEL/NAME
  - FormCreate – Formular-Initialisierung beim Programmstart (Lazarus/LCL)

  ZWECK
  - Wird automatisch genau EINMAL beim Erzeugen des Hauptformulars aufgerufen.
  - Setzt Standardwerte für GUI-Komponenten (Captions, Start-Tab) und initialisiert
    die internen Klassenfelder für den Krypto-Status (CipherBytes/Mode/IV).
  - Stellt damit sicher, dass das Programm reproduzierbar in einem definierten
    Ausgangszustand startet (wichtig für Tests und Lehrzwecke).

  EIGENSCHAFTEN (stichpunktartig)
  - Lifecycle-Hook: Teil des Lazarus-Form-Lebenszyklus (CreateForm → FormCreate).
  - UI-Konfiguration: Beschriftungen werden zentral gesetzt (statt verteilt in .lfm).
  - Defensiv: Assigned(Memo_Control) verhindert Zugriffe auf nicht vorhandene Komponenten.
  - Kryptozustand definiert:
    * FCipherBytes = nil  (noch keine Daten)
    * FCipherMode  = acmECB (Startmodus)
    * FCipherIV    = ZERO_IV (Platzhalter; CBC setzt später echten IV)
  - Minimalinvasiv: Keine Kryptorechnung, nur Vorbereitung/Startzustand.

  VERWENDUNG IM PROJEKT
  - Startpunkt für konsistente GUI und für die späteren „Speichern/Laden“-Workflows:
    Diese nutzen FCipherBytes/FCipherMode/FCipherIV als „letzten Verschlüsselungszustand“.
  - Unterstützt die didaktischen Tests: Selbsttest/NIST-Tests starten aus sauberem Zustand,
    damit keine Altlasten aus vorherigen Läufen die Interpretation verfälschen.

  SICHERHEIT/ EINORDNUNG
  - ZERO_IV als Startwert ist ein *Platzhalter* (insbesondere für ECB, das keinen IV nutzt).
  - Für CBC muss später ein pro Nachricht einzigartiger, idealerweise zufälliger IV verwendet
    werden. Diese Prozedur erzeugt bewusst keinen IV, sie initialisiert nur den Zustand.
  - UI-Texte sind sicherheitsneutral, aber konsistente Initialisierung verhindert typische
    Programmfehler (Null-Pointer/undefinierte Werte), die bei Krypto-Workflows schnell zu
    falschen Ergebnissen oder schwer nachvollziehbaren Bugs führen.

  REFERENZEN / HINWEISE
  - Lazarus/LCL Form Lifecycle: Application.CreateForm(...) → FormCreate → FormShow → Run-Loop.
  - AES-Kontext: NIST FIPS 197 (AES / Rijndael von Joan Daemen & Vincent Rijmen).
  - Modus-Kontext (für spätere CBC-Teile): NIST SP 800-38A (Modes of Operation).
  ============================================================================
}
begin

  // -------------------------------------------------------------------------
  // SCHRITT 1: Label-Beschriftungen setzen
  // -------------------------------------------------------------------------
  // Diese Labels beschreiben die Eingabefelder für den Benutzer.
  // Didaktik: Klare UI-Texte reduzieren Bedienfehler (z.B. Klartext/Key vertauscht).
  Label_Text.Caption := 'Eingabe Klartext';
  Label_Key.Caption  := 'Eingabe Key';

  // -------------------------------------------------------------------------
  // SCHRITT 2: Button-Beschriftungen setzen
  // -------------------------------------------------------------------------
  // Zentral gesetzte Captions sind leichter zu warten und ggf. später zu lokalisieren (i18n).
  // Typische Fehlerquelle: Inkonsistente Beschriftungen zwischen .lfm und Code.
  Verschluesseln_Button.Caption := 'Verschlüsseln (ECB)';
  CBCModus_Button.Caption       := 'Verschlüsseln (CBC)';

  entschluesseln_ECB.Caption    := 'Entschlüsseln (ECB)';
  entschluesseln_CBC.Caption    := 'Entschlüsseln (CBC)';

  Selftest_Button.Caption       := 'Selbsttest'   ;
  NIST_Test.Caption             := 'NIST_Test'    ;
  NIST_CBC.Caption              := 'NIST_CBC'     ;
  speichern.Caption             := 'Chiffre Speichern'   ;
  laden.Caption                 := 'Chiffre Laden'       ;
  // HINWEIS (Didaktik/UX): Uneinheitliche Schreibweise („NIST_Test“/„NIST_CBC“ vs. „Selbsttest“)
  // ist funktional egal, kann aber für Lernende verwirrend sein. (Kein Code ändern – nur Hinweis.)

  // -------------------------------------------------------------------------
  // SCHRITT 3: PageControl initialisieren
  // -------------------------------------------------------------------------
  // Setze die erste Registerkarte als aktiv (sichtbar).
  // Assigned-Prüfung verhindert Access Violation, falls Memo_Control nicht existiert
  // (z.B. Komponente in .lfm gelöscht/umbenannt, oder Form-Definition inkonsistent).
  if Assigned(Memo_Control) then
    Memo_Control.ActivePageIndex := 0;
    // Typische Fehlerquelle: Ohne Assigned(...) würde ein nil-Zugriff sofort crashen.

   // -------------------------------------------------------------------------
  // SCHRITT 4: Interne Cipher-Variablen initialisieren
  // -------------------------------------------------------------------------
  // Diese Klassenfelder speichern den Zustand der letzten Verschlüsselung für Speichern/Laden.
  // Wichtig: Ein definierter Startzustand vermeidet „Geisterdaten“ aus nicht initialisierten Feldern.
  FCipherBytes := nil;
  // FCipherBytes = nil bedeutet: Es gibt aktuell keinen gültigen Ciphertext im Speicher.
  // Typische Fehlerquelle: Speichern wird gedrückt, obwohl noch nichts verschlüsselt wurde.

  FCipherMode  := acmECB;
  // Startmodus = ECB:
  // Didaktik: Einfachster Modus ohne IV/Verkettung. Für Lehrzwecke okay, für reale Daten i.d.R. vermeiden.
  // (ECB zeigt Muster: gleiche Klartextblöcke → gleiche Cipherblöcke.)

  FCipherIV    := ZERO_IV;
  // ZERO_IV ist ein definierter Platzhalter:
  // - Für ECB irrelevant (ECB nutzt keinen IV).
  // - Für CBC nur als „Initialwert“ im Programmzustand, bis später ein echter IV gesetzt wird.
  // Typische Fehlerquelle: CBC mit konstantem IV verwenden → unsichere Wiederverwendung.
  // Hier wird *nicht* CBC verschlüsselt, daher ist ZERO_IV als Startzustand okay.

  // -------------------------------------------------------------------------
  // SCHRITT 5: StatusMemo initialisieren
  // -------------------------------------------------------------------------
  // Zeige eine kurze Erfolgsmeldung, dass die Initialisierung durchgelaufen ist.
  // Didaktik/Debugging: Falls später beim Start etwas crasht, sieht man ggf., ob FormCreate
  // bis hierhin kam.
  StatusMemo.Clear;
  StatusMemo.Lines.Add('Init- OK');

  // Nach FormCreate:
  // - Alle GUI-Komponenten sind beschriftet
  // - Alle internen Variablen sind initialisiert
  // - Programm ist bereit für Benutzerinteraktion
end;

end.

