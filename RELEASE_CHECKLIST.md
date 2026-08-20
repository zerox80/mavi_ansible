# Open-source release checklist

Vor jedem versionierten Release beziehungsweise Git-Tag:

- [ ] Rechteinhaber hat bestätigt, dass Quellcode, Historie und Assets veröffentlicht werden dürfen.
- [ ] Alle Firmen-/Kundendaten wurden gesucht und entfernt: Domains, IPs, UNC-Pfade, Hostnamen, Benutzernamen, Zertifikate, Schlüssel, Inventories, Softwarekataloge und Logs.
- [ ] Git-Historie und eventuell hochgeladene Release-Artefakte wurden separat geprüft.
- [ ] Lizenzentscheidung wurde von den Rechteinhabern freigegeben.
- [ ] SECURITY.md enthält einen erreichbaren privaten Meldekanal.
- [ ] Kein Vault, privater Schlüssel, Zertifikat oder Installer ist im Repository enthalten.
- [ ] Die Beispielprofile sind leer/generisch und funktionieren nur nach dem TUI-Setup.
- [ ] Der Doctor erklärt fehlende Abhängigkeiten, ohne Daten zu verändern.
- [ ] Sicherheitskritische Wege (SSH-Bootstrap, PKI, Firewall, WinRM/Kerberos) wurden in einem isolierten, synthetischen Lab geprüft.
- [ ] Version, Changelog und Unterstützungsmodell sind festgelegt.

Diese Checkliste ersetzt keine rechtliche oder Sicherheitsfreigabe.
