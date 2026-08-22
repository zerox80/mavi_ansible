# Changelog

## 0.9.9-oss

- `ping` verwendet nun dieselbe private, vorab geprüfte Kerberos-Sitzung und denselben kurzlebigen Ticket-Cache wie die übrigen Client-Aktionen; ein temporäres Ein-Host-Inventar verhindert dabei Ansible-Pattern-Erweiterungen.
- Mehrdeutige Remote-Ergebnismarker und unvollständige v2-Bootstrap-Instanznachweise brechen vor jeder Zustandsübernahme oder instanzbezogenen Bereinigung sicher ab.

## 0.9.8-oss

- Inventar- und livebasierten, strikt lesenden Remote-Verwaltungs-Audit für einzelne Windows-Hosts oder das gesamte Inventory ergänzt.
- WinRM-, OpenSSH-, Firewall- und Zertifikatszustände werden gegen exakt controllerseitig belegte Mavi-Identitäten klassifiziert.
- Den vollständigen Remote-Rückbau auf exakt identifizierte Listener, Zertifikate, Schlüssel und Controller-Artefakte begrenzt und mit prüfbaren Rückbau-Nachweisen sowie Rollback abgesichert.
- Historische Bootstrap-CAs, ältere Host-Aliase sowie getrennte PSRP- und SSH-Ports werden sicher und rückwärtskompatibel behandelt.
- Neue CLI-Varianten `ssh status --all` und `ssh status [HOST|--all] --live` ergänzt.

## 0.9.7-oss

- Windows-Client-Menü zum Deaktivieren des Schnellstarts bei erhaltenem Ruhezustand und zum getrennten Einstellen der Bildschirmtimeouts für Netz- und Akkubetrieb ergänzt.
- Klassische Windows-Programme werden dynamisch aus Maschinen- und aktuellem Benutzerkontext gelesen, durchsuchbar mehrfach ausgewählt und strikt nacheinander unbeaufsichtigt deinstalliert.
- Microsoft-365-Einträge können vorab markiert werden; Office 2024, Project und Visio bleiben dabei ausgeschlossen.
- Alle Optimierungs-, Inventar-, Deinstallations- und Erreichbarkeitsläufe verwenden dieselbe gebundene Ansible-Sitzung samt privatem Kerberos-Ticket-Cache.
- Fehlgeschlagene Client-Playbooks zeigen die tatsächliche relevante Ansible-Fehlerzeile statt nur der PLAY-RECAP-Zusammenfassung.
- Neue CLI-Befehle `client optimize` und `client uninstall` ergänzt.

## 0.9.6-oss

- Vollständigen Software-Installationslauf an eine einzige gebundene Ansible-Sitzung gekoppelt.
- Haupt-Playbook, Installed-Precheck, Live-Proben, Nachlaufkontrolle und Erreichbarkeitsprüfung verwenden denselben vorab geprüften Kerberos-Ticket-Cache und denselben Ansible-Python.
- Ansible-Startpunkt und Inventory-Pfad werden für den gesamten Lauf festgehalten; benannte Inventory-Credentials werden bei Kerberos-Sitzungen leer überlagert.
- Die interaktive OpenSSH-Vollautomatik fragt wieder nach der optionalen OpenSSH-MSI; Enter verwendet weiterhin Windows Capability/FoD.

## 0.9.5-oss

- WinRM-Listenerfreiheit wird beim Stand-0-Rückbau geprüft, solange WinRM noch läuft.
- Die Abschlussprüfung verwendet nach dem Stoppen ausschließlich den lokalen Dienststatus und den Registry-Startwert; dadurch wartet der Rückbau nicht mehr auf einen bereits deaktivierten WSMan-/CIM-Kanal.
- Fortschrittshinweis für den bis zu 180 Sekunden laufenden OpenSSH-Rückbau ergänzt.

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
