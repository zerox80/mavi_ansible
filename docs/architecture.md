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

Die bekannten Fachmodule bleiben als stabile Importfassaden erhalten. Die
Implementierung ist darunter nach jeweils einer Verantwortung aufgeteilt:

| Fassade | Implementierungsmodule |
| --- | --- |
| `cli.py` | `cli_menu.py`, `cli_parser.py` |
| `catalogs.py` | `catalog_selection.py`, `catalog_storage.py`, `catalog_parameters.py`, `catalog_contexts.py`, `catalog_editing.py`, `catalog_menu.py`, `catalog_products.py` |
| `software.py` | `software_office.py`, `software_catalog.py`, `software_winget.py`, `software_manual.py` |
| `execution.py` | `execution_inventory.py`, `execution_hosts.py`, `execution_process.py`, `execution_ping.py`, `execution_install.py`, `execution_credentials.py` |
| `installer_analysis.py` | `installer_rules.py`, `installer_switches.py`, `installer_rule_commands.py`, `installer_metadata.py`, `installer_workflow.py` |
| `printers.py` | `printer_inf.py`, `printer_catalog.py`, `printer_install.py` |
| `clients.py` | `client_runtime.py`, `client_optimization.py`, `client_uninstall.py`, `client_menu.py` |
| `environment.py` | `environment_files.py`, `environment_paths.py`, `environment_installers.py`, `environment_mavi.py` |
| `reports.py` | `report_catalog.py`, `report_redaction.py`, `report_html.py`, `report_commands.py`, `report_security.py` |
| `remote.py` | `remote_transport.py`, `remote_kerberos.py`, `remote_pki.py`, `remote_cleanup.py`, `remote_session.py`, `remote_play_runner.py`, `remote_winrm_install.py`, `remote_winrm_reset.py` |
| `openssh.py` | `openssh_keys.py`, `openssh_scripts.py`, `openssh_bootstrap.py`, `openssh_commands.py`, `openssh_winrm.py`, `openssh_cleanup.py`, `openssh_audit.py`, `openssh_menu.py`, `openssh_lifecycle.py` |
| `templates.py` | `template_printers.py`, `template_installation.py`, `template_clients.py` |

`_dependencies.py` bündelt weiterhin Standardbibliothek und optionale
Python-Abhängigkeiten. `settings.py` enthält Produktversion, Standardpfade und
persistierte Datenvorlagen. Bestehende Imports aus den Fassaden funktionieren
weiter; neue Logik gehört direkt in das fachlich zuständige
Implementierungsmodul.

Abhängigkeiten zwischen Fachmodulen werden explizit im jeweiligen Workflow
importiert. Interne Implementierungen greifen bei fachinternen Abhängigkeiten
über einen lokalen Import auf die stabile Fassade zu. Es gibt keine
nachträglich verdrahtete globale Registry und keine Importzyklen beim
Paketstart.

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
