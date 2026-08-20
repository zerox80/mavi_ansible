# Changelog

## 0.9.4-oss

- Wiederholbaren WinRM/Kerberos-Stand-0-Rückbau über den bestehenden OpenSSH-Kanal ergänzt.
- Optionales vollständiges Abschalten des Mavi-Fernzugangs mit Entfernung des umgebungseigenen SSH-Keys und der OpenSSH-Firewallregel sowie verzögertem Stoppen von `sshd` ergänzt.
- Hostbezogenen WinRM-Inventory-Status und ausgestellte Hostzertifikate nach erfolgreichem Rückbau bereinigt; die gemeinsame WinRM-CA bleibt für andere PCs erhalten.
- Neue TUI-Aktionen und `ssh winrm-reset [--disable-openssh]` ergänzt.

## 0.9.3-oss

- Erstes Mavi-Provisioner-OSS-Releasekandidatenlayout.
- Firmengebundene Standardwerte aus dem Quellcode entfernt.
- TUI-first Startansicht mit Umgebungseinrichtung, Doctor und PC-Flow ergänzt.
- Nicht geheimes Umgebungsprofil unter software/mavi_config.yml eingeführt.
- Read-only Doctor mit Controller-, Inventory-, Remote- und Offline-Collector-Workflow ergänzt.
- Open-Source-Dokumentation, Beispielprofil, Ignore-Regeln und Release-Checkliste ergänzt.

## Vorherige interne Entwicklung

Die vorherige Versionshistorie wurde nicht als öffentliche Projektgeschichte übernommen. Bevor eine echte Git-Historie veröffentlicht wird, muss sie separat auf Firmen- und Kundendaten geprüft werden.
