# 05 Containerformat (Datei/Bytes)

Dieses Projekt nutzt ein eigenes, bewusst einfaches Containerformat, damit man Mode/IV/Ciphertext nachvollziehen kann.

## Header (32 Bytes)
Offset | Länge | Inhalt
---|---:|---
0 | 8 | Magic: "LAES256" + #0
8 | 1 | Version (aktuell: 1)
9 | 1 | Mode (1=ECB, 2=CBC)
10 | 2 | Reserved (aktuell 0)
12 | 16 | IV (bei ECB 0)
28 | 4 | CipherLen (UInt32 Little Endian)

Ab Byte 32 folgt der Ciphertext (CipherLen Bytes).

## Wichtiger Hinweis
Der Container enthält **keinen Schutz gegen Manipulation** (keine Authentifizierung/Integrität).
Für echte Sicherheit braucht man z.B. AEAD (AES-GCM) oder mindestens MAC/Tag.

