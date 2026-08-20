# Doctor

Der Mavi Doctor ist kein KI-Modell und muss nicht trainiert werden. Er nutzt feste, nachvollziehbare Checks und zeigt zu jedem fehlenden Fakt den nächsten konkreten TUI-Schritt.

## Drei Modi

1. Controller-Doctor prüft Profil, Ansible, Softwarequelle und die Voraussetzungen für SSH beziehungsweise WinRM/Kerberos.
2. Remote-Doctor verwendet die bestehende SSH- oder PSRP-Verbindung für ein temporäres, read-only Ansible-Playbook.
3. Offline-Collector ist für neue Windows-PCs ohne erreichbaren Management-Transport.

Der eigentliche `doctor` ist strikt diagnostisch: Er ruft keine Initialisierung
oder Migration auf und schreibt keine Projektdatei. Fehlt eine Konfiguration,
meldet er dies als offenen Punkt. Die explizite Collector-Erzeugung ist davon
getrennt:

~~~bash
python3 mavi_provisioner.py doctor-collector --out ./Mavi-Doctor-Collector.ps1
~~~

Beim Gesamtcheck sind noch nicht eingerichtete optionale Wege – etwa Vault,
OpenSSH oder WinRM – Hinweise. Ein gezielter Aufruf wie
`doctor --feature ssh` oder `doctor --feature winrm` bewertet genau diesen Weg
als Pflicht und meldet fehlende Voraussetzungen entsprechend als offene Punkte.

## Offline-Collector

In der TUI:

Doctor & Bereitschaft → Offline-Collector für einen Windows-PC erzeugen

Den erzeugten Mavi-Doctor-Collector-Datei auf dem Ziel-PC mit administrativen Rechten ausführen:

~~~powershell
.\Mavi-Doctor-Collector-PC-001.ps1
~~~

Er schreibt standardmäßig Mavi-Doctor-Facts.json nach %TEMP% und zeigt den Pfad an. Diese JSON-Datei auf den Controller zurückkopieren und in der TUI importieren.

Der Collector liest unter anderem:

- Windows-Version und Rechnername
- Domänenmitgliedschaft
- Domain Controller sowie LDAP- und Kerberos-SRV-Antworten
- IPv4-Präfixe, DNS, Default-Gateways und DHCP-Server je Adapter
- gemappte Netzlaufwerke und SMB-Mappings im Collector-Kontext
- Windows-Zeitquelle und Proxy-Metadaten
- veröffentlichte Enterprise-CAs und Enrollment-Templates aus AD CS
- Status von sshd und WinRM
- vorhandene WinRM-Listener

Er installiert keinen Dienst, öffnet keine Firewall, ändert keine Registry und enthält keine Passwörter.

## Domänen-Admin

Ein Domänen-Admin ist Berechtigung, aber kein Transport. Der Doctor kann einen Ziel-PC erst remote abfragen, wenn eine Verbindung besteht:

- neu / noch kein Transport: Collector lokal auf dem PC ausführen;
- nach OpenSSH-Bootstrap: Remote-Doctor über SSH;
- nach PSRP-Setup: Remote-Doctor über HTTPS + Kerberos.

Damit ist keine permanente Management-Agent-Installation erforderlich.

## Automatisierung

`doctor --format json` gibt Schema, Zusammenfassung und Findings
maschinenlesbar aus. Mindestens ein `fail` ergibt Exitcode 1; Warnungen und
Informationen allein ergeben Exitcode 0. Der Remote-Modus legt nur temporäre
Controller-Dateien an und entfernt sie anschließend wieder; Zielsystem und
Projektkonfiguration bleiben unverändert.
