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
