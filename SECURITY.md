# Security policy

## Supported branch

Die aktuelle main-Version ist der unterstützte Entwicklungsstand.

## Reporting

Bitte veröffentliche Sicherheitslücken nicht zuerst als öffentliches Issue. Melde sie dem Maintainer beziehungsweise dem künftigen Security-Kontakt des Projekts mit:

- betroffener Version oder Commit;
- reproduzierbarer, möglichst minimaler Beschreibung;
- Auswirkung;
- gegebenenfalls sicher bereinigten Logs.

Bis ein offizieller Kontakt hinterlegt ist, darf das Repository nicht als produktionsreif beworben werden.

## Security boundaries

- Mavi speichert keine Secrets im Umgebungsprofil.
- SSH-Private-Keys bleiben im Laufzeitprojekt auf dem Controller.
- Bootstrap-Downloads müssen HTTPS und SHA-256-Prüfungen bestehen.
- Der OpenSSH-Bootstrap beschränkt Port 22 auf die konfigurierte Controller-IP.
- Der optionale PSRP-Weg verlangt HTTPS und Kerberos.
- Doctor und Windows-Collector sind read-only; sie sollen keine Konfiguration reparieren.

Vor einer externen Veröffentlichung muss der Security-Review aus RELEASE_CHECKLIST.md abgeschlossen sein.
