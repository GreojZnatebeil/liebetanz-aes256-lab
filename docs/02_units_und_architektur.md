# 02 Units und Architektur

## Einstieg / GUI
- `AES_256_Lab_Main`: Oberfläche und Ablaufsteuerung

## Kryptobausteine
- `uAES256`: AES-Kernlogik (Rundenfunktionen, Key Schedule, Grundoperationen)
- `uAES256_ECB`: ECB-Modus (nur zum Verstehen)
- `uAES256_CBC`: CBC-Modus (nur zum Verstehen)
- `uSHA256`: SHA-256 (z.B. für Lernzwecke / Ableitungen im Projekt)
- `uAES256_Container`: Hilfsstrukturen und Container

## Namenskonvention
Funktionen mit Suffix `_TEST` sind nur für interne Selftests gedacht.
Die “normalen” ECB/CBC-Funktionen ohne Suffix sind die API, die die GUI verwendet.

## Hinweis
Die Aufteilung ist didaktisch gewählt: Lieber nachvollziehbar als „maximal elegant“ oder „maximal performant“.

