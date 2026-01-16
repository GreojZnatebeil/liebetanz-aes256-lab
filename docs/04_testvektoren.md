# 04 Testvektoren (AES-256)


## Nutzung im Projekt (GUI)
Im Programm gibt es zwei Buttons, mit denen die Referenzwerte direkt geprüft werden können:

- **NIST Test (AES-256 Block)**  
  Prüft einen Single-Block Known Answer Test (KAT). Damit wird verifiziert, dass der AES-Kern für bekannte Referenzdaten exakt das erwartete Ergebnis liefert.

- **NIST Test (AES-256 CBC)**  
  Prüft CBC mit festem IV anhand eines NIST-Testvektors (Verschlüsselung und optional Rück-Entschlüsselung).

## Warum das hilfreich ist
Diese Tests zeigen nachvollziehbar, dass die Implementierung für definierte Eingaben exakt die offiziellen Referenz-Ausgaben erzeugt – also **kein “Fake”** ist.
Gleichzeitig dienen sie als Sicherheitsnetz für Weiterentwicklung: Wer am Code etwas ändert, kann sofort prüfen, ob die Änderung die Korrektheit beeinflusst.

Empfehlung: Nach Änderungen am AES-Kern oder an ECB/CBC immer zuerst die NIST-Tests laufen lassen.


