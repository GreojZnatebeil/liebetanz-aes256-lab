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
  FUNKTION: ROTR
  ============================================================================
  TITEL/NAME
  - ROTR – Rotate Right (32-Bit-Rechtsrotation, zyklisch)

  ZWECK
  - Rotiert die Bits eines 32-Bit-Wertes (LongWord) zyklisch um n Positionen nach rechts.
  - Diese Operation ist ein Grundbaustein in SHA-256 (und vielen anderen Hash-/Krypto-Algorithmen),
    weil sie Bits „mischt“, ohne Information zu verlieren.

  EIGENSCHAFTEN (stichpunktartig)
  - Zyklisch (Rotation), nicht „Shift mit Nullauffüllen“:
    * Bits, die rechts „herausfallen“, kommen links wieder hinein.
  - 32-Bit-Operation: nutzt die feste Wortbreite von SHA-256 (Worte = 32 Bit).
  - Deterministisch und schnell: nur Bit-Shifts + OR.
  - In Kombination mit XOR bildet ROTR die σ/Σ-Funktionen von SHA-256.

  VERWENDUNG IM PROJEKT
  - Wird in SHA-256 typischerweise innerhalb der Funktionen Σ0/Σ1 und σ0/σ1 verwendet, z.B.:
      Σ0(x) = ROTR(x, 2) XOR ROTR(x, 13) XOR ROTR(x, 22)
      Σ1(x) = ROTR(x, 6) XOR ROTR(x, 11) XOR ROTR(x, 25)
    (Konkrete Kombinationen sind in FIPS 180-4 definiert.)

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - ROTR ist keine „Sicherheitsmaßnahme“ an sich, sondern eine primitive Bit-Operation.
  - In SHA-256 dient sie der Diffusion: kleine Änderungen am Input sollen sich schnell auf viele Bits auswirken.
  - Wichtig: Korrekte Wortbreite und korrektes Verhalten bei Randfällen (n=0 / n=32) sind entscheidend,
    sonst stimmen Testvektoren nicht.

  REFERENZEN / HINWEISE
  - NIST FIPS 180-4: Secure Hash Standard (SHA-256) – Definition der ROTR- und Σ/σ-Funktionen.
  - Typische Fehlerquellen: Shift-Breite, n außerhalb 0..31, Integer-Typen (signed vs unsigned).
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Rotation vs. Shift – der entscheidende Unterschied
  ----------------------------------------------------------------------------
  - Shift (shr) ist „Bits nach rechts schieben und links mit 0 füllen“ → Information geht verloren.
  - Rotation (ROTR) ist „Bits schieben und herumwickeln“ → Information bleibt erhalten.
  - Merksatz: „Rotation mischt, Shift verwirft.“
  ----------------------------------------------------------------------------
  HINWEIS (Quality-Gate / Randfälle):
  - Diese Implementierung setzt assume: n ist sinnvoll (typisch 0..31).
  - Wenn n = 0, ist (32 - n) = 32 → x shl 32 ist in Pascal je nach Compiler/CPU-Konvention potenziell kritisch
    (oft 0 oder undefiniert). In SHA-256 werden die Rotationskonstanten aber fix und nie 0.
  - Wenn n >= 32, wäre ebenfalls Vorsicht nötig (Rotation sollte dann modulo 32 erfolgen).
  - Im Lehrprojekt ist das ok, solange alle Aufrufer nur gültige SHA-256-Rotationswerte verwenden.
  ----------------------------------------------------------------------------
}
begin
  // Rechtsrotation: dreht die Bits nach rechts (zyklisch)
  //
  // Idee:
  // 1) (x shr n)              → schiebt x nach rechts; die unteren n Bits „fallen heraus“
  // 2) (x shl (32 - n))       → schiebt x nach links; genau die „herausgefallenen“ Bits kommen links wieder rein
  // 3) OR verbindet beide Teile → ergibt die zyklische Rotation
  //
  // Beispiel (vereinfachte Bitdarstellung):
  //   x = ABCDEFGH (Bits), n=2
  //   x shr 2          → 00ABCDEF
  //   x shl (32-2)     → GH000000  (die letzten 2 Bits wandern nach vorn)
  //   OR               → GHABCDEF  (Rotation)
  Result := (x shr n) or (x shl (32 - n));
end;


function SHR32(x: LongWord; n: LongWord): LongWord;
{
  ============================================================================
  FUNKTION: SHR32
  ============================================================================
  TITEL/NAME
  - SHR32 – Logisches Rechts-Schieben (32-Bit Shift Right)

  ZWECK
  - Schiebt die Bits eines 32-Bit-Wertes (LongWord) um n Positionen nach rechts.
  - Links werden Nullen „nachgefüllt“ (logischer Shift), rechts fallen Bits weg.
  - In SHA-256 wird SHR (zusammen mit ROTR und XOR) in den kleinen σ-Funktionen verwendet,
    weil es gezielt Information verwirft und damit die Bitmischung ergänzt.

  EIGENSCHAFTEN (stichpunktartig)
  - Nicht zyklisch: Bits, die rechts herausfallen, sind verloren (anders als bei ROTR).
  - Logisch (unsigned): LongWord sorgt dafür, dass links mit 0 aufgefüllt wird (kein Vorzeichenbit).
  - 32-Bit-Kontext: SHA-256 arbeitet mit 32-Bit-Worten (Message Schedule / Arbeitsvariablen).
  - Schnell und deterministisch: eine primitive CPU-Operation.

  VERWENDUNG IM PROJEKT
  - Typisch in SHA-256 innerhalb der σ-Funktionen (FIPS 180-4), z.B.:
      σ0(x) = ROTR(x, 7) XOR ROTR(x, 18) XOR SHR32(x, 3)
      σ1(x) = ROTR(x, 17) XOR ROTR(x, 19) XOR SHR32(x, 10)
  - Dadurch wird erreicht, dass manche Bits rotieren (Information bleibt erhalten),
    während andere per Shift „abgeschnitten“ werden (Information geht verloren) – das ist gewollt.

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - SHR32 ist keine „Sicherheitsfunktion“ an sich, sondern eine Bit-Primitive.
  - In Hashfunktionen unterstützt sie die Diffusion/Verteilung von Bitänderungen,
    indem sie Bits an neue Positionen bringt und Teile verwirft.
  - Korrektes Verhalten bei Wortbreite und Randfällen ist wichtig, sonst stimmen
    Testvektoren nicht.

  REFERENZEN / HINWEISE
  - NIST FIPS 180-4: Secure Hash Standard – Definition von SHR und den σ/Σ-Funktionen.
  - Typische Fehlerquellen:
    * signed vs. unsigned (arithmetischer Shift vs. logischer Shift),
    * n außerhalb 0..31 (Shift-Breite),
    * Verwechslung mit ROTR (Rotation ≠ Shift).
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Warum SHA-256 sowohl ROTR als auch SHR nutzt
  ----------------------------------------------------------------------------
  - ROTR (Rotation) bewahrt Information: Bits werden nur umgeordnet.
  - SHR (Shift) verwirft Information: Bits werden abgeschnitten und links mit 0 aufgefüllt.
  - Merksatz: „ROTR mischt ohne Verlust, SHR mischt mit Verlust“ – die Kombination
    erschwert das Zurückrechnen und verteilt Input-Bits über das Wort.
  ----------------------------------------------------------------------------
  HINWEIS (Quality-Gate / Randfälle):
  - Diese Funktion setzt voraus, dass n sinnvoll ist (typisch 0..31).
  - Bei n >= 32 ist das Verhalten je nach Compiler/CPU-Konvention potenziell problematisch
    (oft 0, manchmal undefiniert). SHA-256 nutzt feste, gültige Shift-Konstanten (z.B. 3, 10),
    daher ist das im Lehrprojekt ok.
  ----------------------------------------------------------------------------
}
begin
  // Logisches Rechts-Schieben
  //
  // (x shr n) bedeutet:
  // - Bits wandern nach rechts
  // - links werden 0-Bits eingefügt (weil x ein LongWord = unsigned ist)
  // - die unteren n Bits gehen verloren
  //
  // Beispiel (vereinfacht):
  //   x = 10110011, n=2
  //   x shr 2 = 00101100
  Result := x shr n;
end;

// --- SHA-256 Konstanten (aus FIPS-180-4) ---
const
  K: array[0..63] of LongWord = (
    {=========================================================================
      KONSTANTE: K (SHA-256 Round Constants)
      =========================================================================
      TITEL/NAME
      - K – 64 Rundkonstanten (je 32 Bit) für SHA-256

      ZWECK
      - Diese Konstanten werden in jeder der 64 Runden der SHA-256-Kompressionsfunktion
        als additive „Rundenwürze“ (Round Constant) verwendet.
      - Sie sorgen dafür, dass jede Runde eine eindeutig andere, feste Konstante einmischt,
        damit sich keine „zu symmetrischen“ Rechenmuster ergeben.

      EIGENSCHAFTEN (stichpunktartig)
      - 64 Werte, passend zu 64 Runden von SHA-256.
      - Jeder Wert ist ein 32-Bit-Wort (LongWord).
      - Fest definiert im Standard (kein Geheimnis, kein Schlüssel).
      - Werte stammen aus den ersten 32 Bits der Nachkommastellen der Kubikwurzeln
        der ersten 64 Primzahlen (standardisierte Ableitung → vermeidet „willkürlich gewählt“).

      VERWENDUNG IM PROJEKT
      - In der SHA-256-Rundschleife typischerweise so (schematisch):
          T1 := h + Σ1(e) + Ch(e,f,g) + K[t] + W[t];
          T2 := Σ0(a) + Maj(a,b,c);
        → K[t] ist dabei genau diese Konstante der Runde t (0..63).
      - Wichtig: K ist unabhängig vom Input und unabhängig vom Schlüssel (SHA ist unkeyed).

      SICHERHEIT/ EINORDNUNG (Stand allgemein)
      - K-Konstanten sind öffentlich und müssen exakt stimmen.
      - Schon ein einziges falsches K-Wort führt zu komplett falschen Hashes
        (Testvektoren schlagen sofort fehl).
      - Diese Konstanten machen SHA-256 nicht „geheim“, sondern standard-konform
        und reproduzierbar.

      REFERENZEN / HINWEISE
      - NIST FIPS 180-4: Secure Hash Standard (SHA-256), Abschnitt zu Konstanten K[0..63].
      - Testen: Offizielle SHA-256 Testvektoren (z.B. NIST CAVP) – ideal zur Verifikation.
      - Typische Fehlerquelle: falscher Datentyp (signed statt unsigned) oder falsche Wortbreite.
      =========================================================================
      DIDAKTISCHE ERGÄNZUNG: Warum sind diese Konstanten „komisch“ (Hex-Zahlen)?
      -------------------------------------------------------------------------
      - Hex ist hier die natürliche Darstellung, weil SHA-256 wortweise (32 Bit) arbeitet.
      - Die Ableitung aus Primzahlen (Kubikwurzeln) ist ein klassischer Trick in Standards:
        Es vermeidet die Diskussion „hat jemand Hintertüren eingebaut?“ durch frei gewählte Zahlen.
      -------------------------------------------------------------------------
      HINWEIS (Quality-Gate)
      - Reihenfolge ist kritisch: K[0] gehört zur Runde 0, K[63] zur Runde 63.
      - Nicht umsortieren, nicht kürzen, nicht als Dezimal neu formatieren – sonst stimmen
        die Hashwerte nicht mehr.
      -------------------------------------------------------------------------}
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
    {=========================================================================
      KONSTANTE: H0 (SHA-256 Initial Hash Value / Initialisierungsvektor)
      =========================================================================
      TITEL/NAME
      - H0 – 8 Initialwerte (je 32 Bit) für den Startzustand von SHA-256

      ZWECK
      - Definiert den initialen Hash-Zustand (a..h bzw. H[0..7]) vor der Verarbeitung
        des ersten 512-Bit-Blocks.
      - Diese 8 Wörter sind der „Startpunkt“ der Kompressionsfunktion; danach werden
        sie blockweise weitergemischt (Merksatz: „State rein, State raus“).

      EIGENSCHAFTEN (stichpunktartig)
      - 8 Werte, passend zu den 8 Arbeitsregistern/State-Worten von SHA-256.
      - Jeder Wert ist ein 32-Bit-Wort (LongWord).
      - Fest definiert im Standard (öffentlich, kein Geheimnis, kein Schlüssel).
      - Werte stammen aus den ersten 32 Bits der Nachkommastellen der Quadratwurzeln
        der ersten 8 Primzahlen (standardisierte Ableitung → vermeidet „willkürlich gewählt“).

      VERWENDUNG IM PROJEKT
      - Bei Start einer SHA-256-Berechnung typischerweise:
          H[0] := H0[0]; ... H[7] := H0[7];
        Danach für jeden 512-Bit-Block:
          Kompressionsrunde → State aktualisieren → zu H addieren (feed-forward).
      - Wichtig: Für jeden neuen Hash (neue Nachricht) wird wieder mit genau diesen
        H0-Werten gestartet.

      SICHERHEIT/ EINORDNUNG (Stand allgemein)
      - Diese Werte sind Teil der SHA-256-Spezifikation und müssen exakt stimmen.
      - Schon ein falsches Bit in H0 führt zu komplett falschen Hashes
        (Testvektoren schlagen sofort fehl).
      - H0 ist kein „Salt“ und kein Schlüssel: SHA-256 ist unkeyed; Geheimhaltung
        dieser Werte bringt keine Sicherheit.

      REFERENZEN / HINWEISE
      - NIST FIPS 180-4: Secure Hash Standard (SHA-256), Abschnitt zu den Initialwerten H0..H7.
      - Testen: NIST CAVP SHA-256 Testvektoren (Known Answer Tests) zur Verifikation.
      - Typische Fehlerquelle: falscher Datentyp (signed) oder Verwechslung mit SHA-224
        (SHA-224 nutzt andere Initialwerte).
      =========================================================================
      DIDAKTISCHE ERGÄNZUNG: Warum heißt das manchmal „IV“?
      -------------------------------------------------------------------------
      - In Hashfunktionen bezeichnet man den Startzustand oft als „Initial Value (IV)“.
      - Anders als bei CBC-IVs ist dieser IV bei SHA-256 konstant und standardisiert.
      - Merksatz: „SHA-IV = fester Startzustand; CBC-IV = pro Nachricht neu und zufällig.“
      -------------------------------------------------------------------------
      HINWEIS (Quality-Gate)
      - Reihenfolge ist kritisch: H0[0] gehört zu H[0] (a), ..., H0[7] zu H[7] (h).
      - Nicht umsortieren oder als Dezimal neu formatieren – sonst stimmen Hashwerte nicht.
      -------------------------------------------------------------------------}
    $6A09E667, $BB67AE85, $3C6EF372, $A54FF53A,
    $510E527F, $9B05688C, $1F83D9AB, $5BE0CD19
  );


// --- Verarbeitet einen 512-Bit Block ---
procedure SHA256Transform(var State: TSHA256State; const Block: TSHA256Buffer);
{
  ============================================================================
  PROZEDUR: SHA256Transform
  ============================================================================
  TITEL/NAME
  - SHA256Transform – Kompressionsfunktion für SHA-256 (ein 512-Bit-Block)

  ZWECK
  - Verarbeitet GENAU einen 512-Bit-Block (64 Byte) gemäß SHA-256 und aktualisiert
    den internen Hash-Zustand (State: 8×32 Bit).
  - Dies ist der „Kernmotor“ von SHA-256: Alle höheren Funktionen (Init/Update/Final)
    reduzieren am Ende auf wiederholte Aufrufe dieser Transform-Routine.

  EIGENSCHAFTEN (stichpunktartig)
  - Eingabe:
    * Block = 64 Bytes (512 Bit) – bereits passend gepuffert (Padding passiert außerhalb).
  - Ausgabe:
    * State wird IN PLACE aktualisiert (var-Parameter), d.h. derselbe State wird weitergeführt.
  - Arbeitet wortweise (32 Bit) mit:
    * ROTR (Rotation), SHR (Shift), XOR, AND/NOT, und Addition modulo 2^32.
  - Enthält die drei Standard-Phasen:
    1) Message Schedule W[0..63] (Erweiterung der 16 Eingabewörter)
    2) 64 Runden Kompression (Arbeitsregister a..h)
    3) Feed-Forward: Ergebnis wird zum ursprünglichen State addiert

  VERWENDUNG IM PROJEKT
  - Wird typischerweise in SHA256Update aufgerufen, sobald 64 Bytes im Buffer voll sind.
  - Wird in SHA256Final ggf. noch einmal für den letzten (gepaddingten) Block aufgerufen.
  - Für Testzwecke: Wenn SHA-256 Testvektoren nicht stimmen, ist SHA256Transform eine
    der ersten Stellen zum Prüfen (Endianness, Schedule, Rundenschleife).

  SICHERHEIT/ EINORDNUNG (Stand allgemein)
  - Diese Prozedur implementiert die standardisierte SHA-256-Kompressionsfunktion (FIPS 180-4).
  - Sicherheit entsteht durch die korrekte Kombination aus:
    * nichtlinearen Funktionen (Ch/Maj),
    * Rotationen/Shifts,
    * Rundkonstanten K[i],
    * und Feed-Forward (State-Addition).
  - Wichtig: Schon kleinste Abweichungen (z.B. Endianness oder falsche Rotation) machen den Hash falsch.
  - Hinweis für Praxis: SHA-256 ist ein Hash (Integrität), keine Verschlüsselung (Vertraulichkeit).

  REFERENZEN / HINWEISE
  - NIST FIPS 180-4: Secure Hash Standard (SHA-256) – offizielle Definition der Funktionen.
  - NIST CAVP: SHA-256 Known Answer Tests (Testvektoren zur Verifikation).
  - Merkhilfe (AES-Kontext): AES (Rijndael, Daemen & Rijmen, FIPS 197) ist ein Blockcipher,
    SHA-256 ist ein Hash – beide arbeiten blockweise, aber mit völlig anderem Ziel.
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Typische Fehlerquellen in SHA256Transform
  ----------------------------------------------------------------------------
  1) ENDIANNESS (sehr häufig!)
     - SHA-256 liest die 32-Bit-Wörter aus dem Byte-Block in BIG-ENDIAN.
       Wer Little-Endian liest, bekommt falsche Hashes.
  2) MODULO 2^32 ADDITION
     - LongWord-Überläufe sind hier nicht „Bug“, sondern Teil der Spezifikation.
  3) OFF-BY-ONE IN W[ ] ODER RUNDEN
     - W muss 0..63 haben, Runden müssen genau 64 sein.
  4) SHIFT-BREITEN / n=0 / n>=32
     - In SHA-256 sind die verwendeten Rotations-/Shiftkonstanten fix und gültig.
       Trotzdem gilt: Wenn ROTR/SHR32 „komisch“ implementiert sind, fällt alles auseinander.
  ----------------------------------------------------------------------------
}
var
  W: array[0..63] of LongWord;      // Message Schedule W[t]: 64×32-Bit-Worte (aus 16 Wörtern erweitert)
  a,b,c,d,e,f,g,h: LongWord;        // Arbeitsvariablen (entsprechen den 8 State-Worten während der Runde)
  t1, t2: LongWord;                  // Temporäre Summen (T1/T2 aus dem Standard), jeweils modulo 2^32
  i: Integer;                         // Schleifenindex (0..63)
begin
  // 1. Erste 16 Wörter direkt aus Block einlesen (Big-Endian)
  //
  // WHY: SHA-256 definiert, dass die Nachricht als Folge von 32-Bit-Worten in BIG-ENDIAN
  // interpretiert wird („Network Byte Order“). Daher wird jedes 4-Byte-Paket so zusammengesetzt:
  //   W[i] = (B0<<24) | (B1<<16) | (B2<<8) | B3
  //
  // Typische Fehlerquelle:
  // - Wenn man hier Little-Endian liest (B3<<24...), stimmen alle Testvektoren nicht.
  for i := 0 to 15 do
    W[i] :=
      (LongWord(Block[4*i]) shl 24) or         // höchstwertiges Byte (MSB) an Position 24..31
      (LongWord(Block[4*i+1]) shl 16) or       // nächstes Byte an Position 16..23
      (LongWord(Block[4*i+2]) shl 8) or        // nächstes Byte an Position 8..15
      (LongWord(Block[4*i+3]));                // niedrigstwertiges Byte (LSB) an Position 0..7

   // 2. Restliche Wörter berechnen (Message Schedule)
  //
  // WHY: SHA-256 arbeitet 64 Runden lang, braucht also 64 W[t]-Worte.
  // Die ersten 16 kommen direkt aus dem Block, die restlichen 48 werden aus früheren Werten
  // abgeleitet (Diffusion über den Block hinweg).
  //
  // Formeln (FIPS 180-4):
  //   σ0(x) = ROTR(x,7) XOR ROTR(x,18) XOR SHR(x,3)
  //   σ1(x) = ROTR(x,17) XOR ROTR(x,19) XOR SHR(x,10)
  //   W[t]  = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]
  //
  // Hinweis: Die Addition ist modulo 2^32 (LongWord-Überlauf ist gewollt).
  for i := 16 to 63 do
  begin
    W[i] :=
      (ROTR(W[i-15], 7) xor ROTR(W[i-15], 18) xor SHR32(W[i-15], 3)) +  // σ0(W[i-15]): mischt Bits + verwirft gezielt Bits
      W[i-7] +                                                          // direkter Beitrag aus einem früheren Wort (Verknüpfung über Distanz)
      (ROTR(W[i-2],17) xor ROTR(W[i-2],19) xor SHR32(W[i-2],10)) +       // σ1(W[i-2]): zweite Mischfunktion
      W[i-16];                                                          // „Anker“: hält Bezug zu den Originaldaten
  end;

  // 3. Arbeitsvariablen initialisieren
  //
  // WHY: a..h sind lokale Kopien des aktuellen State. Wir arbeiten 64 Runden lang
  // mit diesen Registern und addieren am Ende zurück in State (Feed-Forward).
  a := State[0];
  b := State[1];
  c := State[2];
  d := State[3];
  e := State[4];
  f := State[5];
  g := State[6];
  h := State[7];

  // 4. 64 Runden
  //
  // Jede Runde nutzt:
  // - Σ0(a), Σ1(e): große Rotationsfunktionen (nur ROTR, kein SHR)
  // - Ch(e,f,g): Choice-Funktion (nichtlinear)
  // - Maj(a,b,c): Majority-Funktion (nichtlinear)
  // - K[i]: Rundkonstante (öffentlich, fest aus FIPS 180-4)
  // - W[i]: Message Schedule Wort
  //
  // Formeln (FIPS 180-4):
  //   T1 = h + Σ1(e) + Ch(e,f,g) + K[i] + W[i]
  //   T2 = Σ0(a) + Maj(a,b,c)
  //   (a..h) werden dann „weitergeschoben“ und a := T1 + T2
  for i := 0 to 63 do
  begin
    t1 := h + (ROTR(e,6) xor ROTR(e,11) xor ROTR(e,25))                 // Σ1(e): starke Bitmischung durch Rotationen
            + ((e and f) xor ((not e) and g))                           // Ch(e,f,g): wählt bitweise f oder g abhängig von e
            + K[i] + W[i];                                              // Rundkonstante + Nachrichtenwort: rundenabhängige „Einspeisung“

    t2 := (ROTR(a,2) xor ROTR(a,13) xor ROTR(a,22))                     // Σ0(a): starke Bitmischung der oberen Register
            + ((a and b) xor (a and c) xor (b and c));                  // Maj(a,b,c): bitweise Mehrheit (mind. 2 von 3)

    // Register-Update (Pipeline):
    //
    // WHY: Diese Verschiebung sorgt dafür, dass T1/T2 die Register „durchwandern“,
    // und jede Runde unterschiedliche Registerrollen hat. Das ist Teil der Diffusion.
    h := g;
    g := f;
    f := e;
    e := d + t1;                                                        // e bekommt Mischung aus d und T1
    d := c;
    c := b;
    b := a;
    a := t1 + t2;                                                       // a ist die neue Hauptmischung
  end;

  // 5. Ergebnis zum State addieren (Diffusion)
  //
  // WHY (Feed-Forward): Der neue Registerzustand wird zum alten State addiert.
  // Das verhindert u.a. triviale Invertierbarkeit innerhalb eines Blocks und
  // koppelt die Ausgabe fest an den Eingangsstate (Merkregel: „State rein → State raus → addieren“).
  //
  // Hinweis: Auch hier gilt Addition modulo 2^32 (LongWord-Überlauf ist korrekt).
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
  FUNKTION: SHA256
  ============================================================================
  TITEL/NAME
  - SHA256 – Berechnet den SHA-256 Hash über beliebige Eingabedaten (Bytes)

  ZWECK
  - Liefert den SHA-256 Digest (256 Bit = 32 Byte) für beliebige Eingabedaten.
  - Implementiert die SHA-256 Spezifikation blockweise (512 Bit / 64 Byte pro Block)
    inkl. Padding und Längenfeld.

  EIGENSCHAFTEN (stichpunktartig)
  - Deterministisch: Gleiche Eingabe → gleicher Hash.
  - Feste Ausgabelänge: immer 32 Byte.
  - Blockbasiert: verarbeitet volle 64-Byte-Blöcke direkt, den Rest via Padding.
  - Standardkonform: nutzt
    * Initialwerte H0[0..7],
    * 64-Runden-Kompression via SHA256Transform,
    * Padding-Regel mit 0x80 + Nullen,
    * 64-Bit-Längenfeld in BIG-ENDIAN.

  VERWENDUNG IM PROJEKT
  - Typischer Einsatz: Passwort/Passphrase → SHA-256 → 32 Byte Schlüsselmaterial
    (z.B. als AES-256 KeyBytes).
  - Hinweis für Lernende: Das ist eine einfache Ableitung, aber kein Passwort-Hashing
    mit Work-Factor (siehe Sicherheit/Einordnung).

  SICHERHEIT/ EINORDNUNG (Stand allgemein, keine Marketing-Aussagen)
  - SHA-256 ist eine kryptographische Hashfunktion (Integrität/Fingerabdruck),
    keine Verschlüsselung.
  - Für allgemeine Integritätsprüfungen ist SHA-256 breit etabliert.
  - Für Passwort-basierte Schlüsselableitung ist „einmal SHA-256“ in der Praxis
    oft zu schwach gegen Offline-Bruteforce (keine Iterationen, kein Memory-Hard).
    Dafür nimmt man KDFs wie PBKDF2, scrypt oder Argon2 (mit Salt + vielen Runden).
  - Diese Funktion liefert korrekt nur den Digest – Schutz gegen Ratenangriffe
    hängt vom darüberliegenden Design ab.

  REFERENZEN / HINWEISE
  - NIST FIPS 180-4: Secure Hash Standard (SHA-256) – Padding, Längenfeld, Big-Endian.
  - NIST CAVP: SHA-256 Known Answer Tests (KAT) – zum Verifizieren der Implementierung.
  - Design-Kontext: SHA-2 Familie (NSA, standardisiert durch NIST); heute Standardbaustein.
  ============================================================================
  ----------------------------------------------------------------------------
  DIDAKTISCHE ERGÄNZUNG: Typische Fehlerquellen (Padding/56/64/Big-Endian)
  ----------------------------------------------------------------------------
  - 56/64-Grenze:
    * In einem 64-Byte-Block müssen die letzten 8 Bytes für die Bitlänge frei bleiben.
    * Wenn nach dem 0x80-Padding weniger als 8 Bytes übrig sind (Rest >= 56),
      braucht man einen Zusatzblock.
  - Längenfeld in BIT (nicht Byte!):
    * Len := Length(Data) * 8;  // sonst stimmen Testvektoren nicht.
  - Big-Endian:
    * Sowohl das Einlesen der Blockwörter (in SHA256Transform) als auch
      das Schreiben von Len und der finalen Ausgabe sind Big-Endian.
  - Integer-/Überlauf:
    * Len ist Int64, damit die Bitlänge auch für größere Eingaben passt.
    * Die internen Additionen in SHA256Transform laufen modulo 2^32 (LongWord) – gewollt.
  ----------------------------------------------------------------------------
}
var
  State: TSHA256State;                  // Interner Hash-Zustand (8×32 Bit) – wird pro Block weiterentwickelt
  Len: Int64;                           // Gesamtlänge der Originaldaten in BIT (64-Bit-Feld laut FIPS 180-4)
  Buffer: TSHA256Buffer;                // 512-Bit-Arbeitspuffer (64 Byte) für SHA256Transform
  i: Integer;                           // Laufvariable / Index in Data
begin
  Result := nil;                        // Initialisiert das Ergebnis explizit (beruhigt den Compiler)
  Result := nil;                        // Initialisiert das Ergebnis explizit (beruhigt den Compiler)
  // HINWEIS: Doppelt ist funktional redundant. Im Lehrkontext ok, aber normalerweise reicht einmal.

  // Explizite Initialisierung des Puffers, damit der Compiler sicher ist,
  // dass alle Elemente von Buffer einen definierten Wert haben.
  // WHY: In Lehr-/Debug-Szenarien vermeiden solche Initialisierungen „uninitialisierte Variable“-Hints
  // und machen den Ablauf deterministischer, auch wenn später sowieso überschrieben wird.
  for i := 0 to High(Buffer) do         // Schleife über alle Bytes im Buffer (0..63)
    Buffer[i] := 0;                     // Setzt jedes Byte des Puffers auf 0

  // 1. Startwerte setzen (Initial Hash Values H0..H7)
  // WHY: SHA-256 startet nicht bei 0, sondern mit fest definierten Initialwerten (IV),
  // die in FIPS 180-4 vorgegeben sind. Ohne diese Werte wäre es „nicht SHA-256“.
  for i := 0 to 7 do                    // Schleife über die 8 State-Werte
    State[i] := H0[i];                  // Übernimmt die vordefinierten Initialwerte in den State

{
  // 1. Startwerte setzen (Initial Hash Values H0..H7)
  for i := 0 to 7 do                    // Schleife über die 8 State-Werte
    State[i] := H0[i];                  // Übernimmt die vordefinierten Initialwerte in den State
}
  // HINWEIS: Dieser auskommentierte Block dupliziert die Initialisierung oben.
  // Das ist didaktisch manchmal nützlich (als „Notiz“), aber in Produktcode würde man das entfernen,
  // um Verwirrung zu vermeiden (hier: NICHT entfernen, nur einordnen).

  // 2. Daten blockweise verarbeiten (512-Bit Blöcke)
  //
  // WHY: SHA-256 arbeitet intern immer auf 64-Byte-Blöcken. Vollständige Blöcke
  // kann man direkt verarbeiten, ohne Padding-Logik.
  i := 0;                               // Startindex im Eingabearray
  while (i + 64) <= Length(Data) do     // Solange noch mindestens 64 Bytes (ein voller Block) übrig sind
  begin
    Move(Data[i], Buffer[0], 64);       // Kopiert 64 Bytes aus den Eingabedaten in den Blockpuffer
    // HINWEIS: Move arbeitet bytegenau. Buffer ist exakt 64 Bytes groß.
    SHA256Transform(State, Buffer);     // Verarbeitet diesen Block und aktualisiert den State
    Inc(i, 64);                         // Erhöht den Index um 64, um den nächsten Block zu verarbeiten
  end;

  // 3. Padding vorbereiten (FIPS 180-4)
  //
  // Padding-Regel:
  // - Hänge ein einzelnes '1'-Bit an (als Byte 0x80, also 1000 0000),
  // - dann Nullen,
  // - sodass am Ende des letzten Blocks die letzten 8 Bytes für die Bitlänge frei sind.
  //
  // WHY: Dadurch wird die Nachricht eindeutig „gerahmt“ und SHA-256 wird
  // für beliebige Längen definiert.
  Len := Length(Data) * 8;              // Gesamtlänge der Originaldaten in Bit
  // TYPISCHE FEHLERQUELLE: Länge in Bytes statt Bits → falsche Hashes / Testvektoren schlagen fehl.

  FillChar(Buffer, SizeOf(Buffer), 0);  // Setzt den Puffer auf 0, bevor der letzte Block vorbereitet wird
  // WHY: Wir bauen jetzt den „Restblock“ kontrolliert zusammen (Restdaten + 0x80 + Nullen + Länge).
  Move(Data[i], Buffer[0], Length(Data)-i);
  // Kopiert die restlichen (weniger als 64) Bytes in den Anfang des Puffers
  // HINWEIS: Length(Data)-i ist der Rest (0..63). Das ist sicher, weil die while-Schleife oben
  // alle vollen Blöcke bereits verarbeitet hat.

  Buffer[Length(Data)-i] := $80;        // Fügt das Padding-Startbyte 0x80 an (Bit '1' gefolgt von Nullen)
  // WHY: 0x80 entspricht genau einem '1'-Bit an der nächsten freien Position, gefolgt von 7 Nullen.
  // Danach bleiben die restlichen Bytes im Buffer (durch FillChar) automatisch 0.

  // Falls im aktuellen Block kein Platz mehr für die Längenangabe ist:
  if (Length(Data)-i >= 56) then        // 56 = 64 - 8, Platz für die 64-Bit-Länge
  begin
    // WHY: Ab Byte 56..63 müssen die 8 Längenbytes rein. Wenn der Rest (inkl. 0x80)
    // bereits Byte 56 oder höher belegt, muss dieser Block zuerst „ohne Länge“ verarbeitet werden,
    // und die Länge kommt in einen komplett neuen Null-Block.
    SHA256Transform(State, Buffer);     // Verarbeitet den (fast) vollen Block
    FillChar(Buffer, SizeOf(Buffer),0); // Setzt den Puffer erneut auf 0 für den letzten Block
  end;

   // 4. Länge in letzte 8 Bytes schreiben (Big-Endian)
  //
  // WHY Big-Endian: SHA-256 definiert, dass das 64-Bit-Längenfeld in Big-Endian
  // ans Ende geschrieben wird (FIPS 180-4).
  //
  // Typische Fehlerquelle:
  // - Endianness vertauscht (Little-Endian geschrieben) → Hash falsch.
  // - Len als 32 Bit statt 64 Bit → Hash falsch für längere Eingaben.
  Buffer[63] := Len and $FF;            // Niedrigstwertiges Byte der Länge
  Buffer[62] := (Len shr 8) and $FF;    // Nächstes Byte
  Buffer[61] := (Len shr 16) and $FF;   // ...
  Buffer[60] := (Len shr 24) and $FF;
  Buffer[59] := (Len shr 32) and $FF;
  Buffer[58] := (Len shr 40) and $FF;
  Buffer[57] := (Len shr 48) and $FF;
  Buffer[56] := (Len shr 56) and $FF;   // Höchstwertiges Byte der Länge
  // HINWEIS: Die Reihenfolge 56..63 ist Big-Endian: höchstes Byte zuerst (bei Index 56).

  SHA256Transform(State, Buffer);       // Verarbeitet den letzten Block mit der Längenangabe

   // 5. Ausgabe erzeugen (32 Bytes)
  //
  // State enthält 8×32 Bit (a.k.a. H0..H7 nach der Verarbeitung). Der Digest wird in Bytes ausgegeben.
  // SHA-256 schreibt die Ausgabe ebenfalls in Big-Endian pro 32-Bit-Wort.
  SetLength(Result, 32);                // Reserviert 32 Bytes für den Hash-Wert (256 Bit)
  for i := 0 to 7 do                    // Schleife über die 8 32-Bit-Wörter im State
  begin
    Result[i*4]   := (State[i] shr 24) and $FF; // Oberes Byte nach Result kopieren (MSB)
    Result[i*4+1] := (State[i] shr 16) and $FF; // Nächstes Byte
    Result[i*4+2] := (State[i] shr 8) and $FF;  // Nächstes Byte
    Result[i*4+3] := State[i] and $FF;          // Niedrigstwertiges Byte (LSB)
    // TYPISCHE FEHLERQUELLE: Reihenfolge vertauscht → Hash-Bytes falsch (auch wenn State intern stimmt).
  end;
end;

end.

