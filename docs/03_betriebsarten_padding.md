# 03 Betriebsarten und Padding

## ECB (Electronic Codebook)
ECB ist leicht zu verstehen, aber unsicher, weil gleiche Klartextblöcke zu gleichen Ciphertextblöcken werden.

## CBC (Cipher Block Chaining)
CBC verknüpft Blöcke miteinander (XOR mit vorherigem Ciphertextblock) und benötigt ein IV.

## Padding
Wenn Klartext nicht exakt ein Vielfaches der Blockgröße ist, braucht man Padding (z.B. PKCS#7).
Dieses Projekt hält den Fokus auf Verständlichkeit: Details werden schrittweise ergänzt.

