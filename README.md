# Mavi Provisioner

Mavi Provisioner ist eine TUI-first-Umgebung für die Provisionierung von
Windows-Endpunkten mit Ansible. Sie bündelt Softwarekataloge, WinGet,
Microsoft Store, Drucker, OpenSSH sowie optional PSRP/WinRM mit Kerberos.

Das Repository enthält absichtlich keine Firmenwerte: keine Domains, IPs,
Shares, Benutzer, Zertifikate, Inventories, Installer oder Kennwörter. Jede
Organisation legt ihre eigene Umgebung über den Assistenten an – ohne einen
Fork des Python-Skripts zu bauen.

## Schnellstart in wenigen Minuten

Auf dem Linux-Ansible-Controller einmal die festgelegten Abhängigkeiten
installieren:

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-controller.txt
ansible-galaxy collection install -r collections/requirements.yml
python3 mavi_provisioner.py
~~~

Die Startansicht führt in dieser Reihenfolge durch die erste Umgebung:

1. **Schnellstart / Grundprofil** – Name, Controller-IPv4, lokaler
   Softwareordner und optionaler Windows-/Domänen-Benutzer. Der vorgeschlagene
   leere Softwareordner wird im Laufzeitprojekt angelegt.
2. **Zugangsdaten & Vault** – den Windows-Benutzer bestätigen und das Kennwort
   verschlüsselt in Ansible Vault speichern. Es wird kein Kennwort in der
   Konfigurationsdatei oder als Kommandozeilenargument abgelegt.
3. **PCs & Verbindung** – ersten PC ins Inventory aufnehmen und bei Bedarf den
   vorhandenen Ein-Klick-OpenSSH-Weg verwenden.
4. **Software, Kataloge und Microsoft-Produkte** – Installer, WinGet,
   Microsoft Store und Drucker einrichten.

Produktiv ist pro Controller-VM genau ein Laufzeitprojekt vorgesehen. Mit
`--project` wählst du dessen Speicherort:

~~~bash
python3 mavi_provisioner.py --project /srv/mavi/customer-a
~~~

Der Standard liegt unter `$XDG_DATA_HOME/mavi-provisioner`; ohne `XDG_DATA_HOME`
ist das `~/.local/share/mavi-provisioner`. Er liegt bewusst außerhalb des
Quellrepositories.

Mehrere Laufzeitprojekte auf derselben VM sind ausschließlich für Tests oder
Labore vorgesehen. Sie benötigen jeweils unterschiedliche
`bootstrap_base_url`-Ports und `bootstrap_local_dir`-Pfade.

## Was beim ersten Start abgefragt wird

Der einfache Assistent verlangt nicht alles auf einmal:

| Information | Wann nötig | Wo eintragen / ermitteln |
| --- | --- | --- |
| Controller-IPv4 | für OpenSSH und Erreichbarkeit | Schnellstart; die TUI schlägt gefundene lokale IPv4-Adressen vor |
| Softwareordner | vor der ersten Installer-Verteilung | Schnellstart; Standard ist ein leerer Ordner im Laufzeitprojekt |
| Windows-/Domänen-Benutzer | vor dem ersten PC | Schnellstart oder **Zugangsdaten & Vault** |
| Kennwort | vor dem ersten PC | ausschließlich **Zugangsdaten & Vault** |
| AD-DNS-Domäne | nur für PSRP/WinRM mit Kerberos | Schnellstart oder später `setup --advanced` |
| SMB-Quelle / Laufwerk | nur wenn Installer auf einem Share liegen | `setup --advanced` |
| Bootstrap-Webroot | nur wenn OpenSSH bereitgestellt wird | wird aus der Controller-IP vorbereitet oder in `setup --advanced` angepasst |
| Domänencontroller, DNS, DHCP, Netzlaufwerke, Enterprise-CA | zur Bestandsaufnahme, nicht für den ersten Programmstart | Doctor → Offline-Collector oder bestehende Remote-Verbindung |

Die ausführliche Schritt-für-Schritt-Anleitung steht in
[docs/getting-started.md](docs/getting-started.md); die Konfigurations- und
Discovery-Matrix in [docs/configuration-guide.md](docs/configuration-guide.md).

## Vault und Installer-Geheimnisse

Der geführte Weg lautet:

~~~bash
# Interaktiv: Benutzer, Kennwort zweimal und Vault-Passwort eingeben.
python3 mavi_provisioner.py credentials setup

# Optionales Installer-Geheimnis verschlüsselt ablegen.
python3 mavi_provisioner.py credentials set vault_installer_token
~~~

Danach kann ein Katalogargument den Wert mit `{{ vault_installer_token }}`
referenzieren. Geheimnisse gehören nicht in Installer-Argumente als Klartext.
Die Vault-Datei liegt standardmäßig bei
`inventory/group_vars/windows/vault.yml` im Laufzeitprojekt und ist durch
`.gitignore` vom Repository ausgeschlossen.

## Doctor und Discovery

`doctor` ist diagnostisch und verändert weder Projektdateien noch
Konfiguration. Fehlende optionale Wege (beispielsweise SSH oder WinRM) werden
im Gesamtbericht als Hinweise erklärt; ein gezielter Feature-Check bleibt
streng.

~~~bash
python3 mavi_provisioner.py doctor
python3 mavi_provisioner.py doctor --feature software
python3 mavi_provisioner.py doctor --feature ssh
python3 mavi_provisioner.py doctor PC-001 --remote
python3 mavi_provisioner.py doctor-collector --out ./Mavi-Doctor-Collector.ps1
~~~

Der Offline-Collector liest auf einem Windows-PC unter anderem AD-/DC-Infos,
DNS, DHCP, Netzlaufwerke und verfügbare Enterprise-CAs aus und schreibt nur
einen JSON-Bericht. Details: [docs/doctor.md](docs/doctor.md).

## Projekttrennung

| Bereich | Gehört ins Git-Repository? | Inhalt |
| --- | --- | --- |
| Quellrepository | Ja | Python-Code, Dokumentation, generische Beispiele |
| Laufzeitprojekt | Nein | Inventory, Konfiguration, Vault, Schlüssel, PKI, Kataloge und Reports |

## Abhängigkeiten und Release

`requirements-controller.txt` und `collections/requirements.yml` pinnen die
direkten Controller-Abhängigkeiten. Ein plattformspezifischer Hash-Lock und die
zugehörige SBOM werden erst aus der festgelegten Release-Build-Umgebung erzeugt
und zusammen mit dem Release veröffentlicht. Herkunft und Pflege stehen in
[DEPENDENCIES.md](DEPENDENCIES.md).

Vor einem versionierten Release beziehungsweise Git-Tag ist die vollständige
[RELEASE_CHECKLIST.md](RELEASE_CHECKLIST.md) durch den Rechteinhaber
abzuzeichnen. Beiträge sind willkommen; siehe [CONTRIBUTING.md](CONTRIBUTING.md).

## Weitere Funktionen

Die vollständige Funktionsoberfläche enthält weiterhin Katalogverwaltung,
Parameterprofile, Office-/Microsoft-Assistent, Drucker, WinGet, Microsoft
Store, OpenSSH, PSRP/WinRM und Diagnosen. Die Architektur ist in
[docs/architecture.md](docs/architecture.md) beschrieben.
