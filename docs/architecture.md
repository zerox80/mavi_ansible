# Architektur

~~~text
Mavi Provisioner (TUI auf dem Controller)
        |
        +-- Schnellstart: nicht geheimes Umgebungsprofil
        |      |
        |      +-- Zugangsdaten & Vault: verschlüsseltes Kennwort
        |
        +-- Doctor: feste Checks + Handlungsempfehlungen
        |      |
        |      +-- vorhandene Verbindung -> temporäres Ansible Playbook
        |      |
        |      +-- keine Verbindung -> einmaliger PowerShell-Collector
        |
        +-- Provisioning: Kataloge, Drucker, WinGet, Store, OpenSSH, WinRM
~~~

## Verantwortlichkeiten

- Quellrepository: nur generischer Code und Beispiele.
- Laufzeitprojekt: jede Organisation hat ein eigenes Profil, Inventory und eigene Kataloge; produktiv läuft genau ein Projekt pro Controller-VM.
- Ansible Vault oder Secret Store: Passwörter und andere Geheimnisse. Der
  geführte Standard speichert `ansible_password` verschlüsselt unter
  `inventory/group_vars/windows/vault.yml` im Laufzeitprojekt.
- Windows-Ziel: kein persistenter Mavi-Agent.

## Transportmodell

OpenSSH ist der pragmatische Erstkontakt. Der mitgelieferte Bootstrap erzeugt einen separaten Automationsschlüssel, prüft HTTPS und Hashes und begrenzt TCP/22 auf die Controller-IP.

PSRP/WinRM ist optionaler Endzustand für Domänenumgebungen und wird nur über HTTPS mit Kerberos verwaltet. Mavi führt keinen HTTP-, NTLM- oder Zertifikat-ignorieren-Fallback ein.

## Profile statt Forks

Firmenwerte gehören in ein Laufzeitprofil, nicht in Python-Code. Das bedeutet:

- ein Projekt pro Umgebung und produktiver Controller-VM;
- keine kundenspezifischen Forks für IPs, Shares oder Domains;
- wiederholbarer Setup-Assistent;
- Doctor meldet fehlende oder widersprüchliche Fakten vor einer Provisionierung.

## Ersteinrichtung ohne Überforderung

Der Grundassistent benötigt nur Profilname, Controller-IPv4 und einen lokalen
Softwareordner. Benutzername und Vault folgen als eigener Schritt vor dem
ersten PC. AD-Domäne, SMB-/Laufwerkszuordnung, Enterprise-CA und WinRM sind
optionale Ausbauschritte. Der Doctor-Collector kann diese Umgebungsfakten auf
einem bestehenden Windows-PC erfassen, statt sie beim ersten Start zu erraten.

## Python-Module

Die ausführbare Datei `mavi_provisioner.py` ist nur noch der kompatible
Programmeinstieg. Die Implementierung liegt im neutral benannten Paket
`windows_provisioner`, damit portable Änderungen aus dem Firmenprojekt an
denselben Pfaden übernommen werden können.

| Modul | Verantwortung |
| --- | --- |
| `_dependencies.py` | Standardbibliothek und optionale Python-Abhängigkeiten |
| `settings.py` | Produktversion, Standardpfade und Datenvorlagen |
| `templates.py` | Ansible- und PowerShell-Vorlagen |
| `environment.py` | Projekt-, Datei-, Pfad- und Umgebungsverwaltung |
| `installer_analysis.py` | Installer- und Silent-Switch-Analyse |
| `catalogs.py` | Kataloge, Parameterprofile und interaktive Auswahl |
| `software.py` | Office-, WinGet-, Store- und Softwareaufnahme-Workflows |
| `reports.py` | Terminal-/HTML-Berichte und redigierte Ausgaben |
| `printers.py` | INF-Analyse, Druckerkatalog und Installation |
| `remote.py` | Transport-, Kerberos- und WinRM-Grundlagen |
| `openssh.py` | OpenSSH-Bootstrap und Remotezugriffs-Workflows |
| `execution.py` | Inventory-, Ansible- und Installationsausführung |
| `clients.py` | Windows-Clientoptimierung und Programmbereinigung |
| `cli.py` | Menüs, Argumentparser und Programmeinstieg |

Abhängigkeiten zwischen Fachmodulen werden explizit im jeweiligen Workflow
importiert. Es gibt keine nachträglich verdrahtete globale Registry und keine
gegenseitigen Importzyklen.

## Synchronisation mit Ansible-Windows-Script

`Ansible-Windows-Script` bleibt die intern bewährte Firmenintegration;
Mavi-Provisioner bleibt die allgemein nutzbare Open-Source-Variante. Beide
verwenden dieselben Modulnamen und fachlichen Grenzen.

1. Eine allgemeine Änderung wird im Firmen-Repository als eigener portabler
   Commit im passenden `windows_provisioner/`-Modul umgesetzt.
2. Firmenwerte und interne Sonderwege folgen in einem getrennten Commit.
3. Der portable Commit wird mit `git cherry-pick -x <commit>` nach Mavi
   übernommen.
4. Notwendige Mavi-Ausgaben oder Defaults folgen als kleiner separater Commit.
5. Der Pull Request nennt den korrespondierenden Commit des anderen
   Repositories.

Empfohlene Commit-Präfixe sind `core:` für portable Logik, `company:` für
interne Integration, `mavi:` für die Open-Source-Schicht und `sync:` für eine
unveränderte Übernahme. Ein Commit soll nur eine dieser Kategorien enthalten.
