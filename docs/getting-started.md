# Ersteinrichtung

Diese Anleitung ist für eine neue, leere Umgebung gedacht. Sie setzt keine
Firmenwerte, kein vorhandenes Inventory und keine manuelle YAML-Bearbeitung
voraus.

## 1. Controller vorbereiten

Installiere die festgelegten Python-Abhängigkeiten und die Windows-Collection:

~~~bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements-controller.txt
ansible-galaxy collection install -r collections/requirements.yml
~~~

Danach die TUI starten:

~~~bash
python3 mavi_provisioner.py
~~~

Den Speicherort des produktiv einzigen Laufzeitprojekts dieser Controller-VM
kannst du mit `--project /eigener/pfad` festlegen. Der Projektordner enthält
später Inventory, Kataloge, Vault, Schlüssel und Reports; er gehört nicht in
das Quellrepository. Mehrere Projekte auf derselben VM sind nur für Tests oder
Labore vorgesehen und brauchen getrennte Bootstrap-Ports und Webroots.

## 2. Grundprofil anlegen

Wähle **Schnellstart / Grundprofil**. Der Assistent fragt nur diese vier
nicht-geheimen Werte ab:

1. einen frei wählbaren Namen für die Umgebung;
2. die IPv4-Adresse des Controllers, unter der Windows-PCs ihn erreichen;
3. den Softwareordner auf dem Controller;
4. optional den Windows-/Domänen-Benutzer.

Der vorgeschlagene Softwareordner liegt im Laufzeitprojekt und wird leer
angelegt. Das ist der beste Start für ein Labor oder einen ersten PC. Einen
vorhandenen Mount oder Share kann man jederzeit über **Grundprofil &
Softwarequelle** → **Softwarequelle, UNC und Laufwerk einrichten** ersetzen.

Die AD-DNS-Domäne ist nur für den späteren Kerberos-/WinRM-Weg nötig. Sie kann
im Schnellstart übersprungen werden.

## 3. Zugangsdaten einmal verschlüsselt speichern

Wähle **Zugangsdaten & Vault** → **Windows-/Domänen-Benutzer und Kennwort
verschlüsselt einrichten**.

Der Ablauf fragt nacheinander nach:

1. Windows-/Domänen-Benutzer (falls noch nicht im Grundprofil gesetzt);
2. dessen Kennwort zweimal;
3. einem neuen oder vorhandenen Ansible-Vault-Passwort.

Mavi ruft `ansible-vault encrypt_string` auf und schreibt nur den verschlüsselten
`ansible_password` nach `inventory/group_vars/windows/vault.yml`. Das Kennwort
erscheint weder in `mavi_config.yml` noch in einem Befehlsargument. Das
Vault-Passwort wird für einen einzelnen Verschlüsselungsvorgang in einer
temporären Datei gehalten und anschließend entfernt.

## 4. Ersten PC hinzufügen

Wähle **PCs & Verbindung** → **Neuen PC ins Inventory aufnehmen** und gib einen
eindeutigen Namen sowie die IPv4-Adresse des PCs ein. Der zentrale
`ansible_user` aus dem Vault-Workflow wird automatisch als Gruppenwert genutzt;
er muss nicht für jeden PC erneut eingegeben werden.

Für einen neuen PC ohne vorhandenen Managementzugang gibt es zwei Wege:

- den mitgelieferten Ein-Klick-OpenSSH-Ablauf über **OpenSSH / Windows-
  Verbindung einrichten**;
- oder den Offline-Collector über **Doctor & Bereitschaft**, falls zunächst
  nur die Umgebung erkundet werden soll.

## 5. Software hinzufügen und installieren

Öffne **Software, Kataloge und Microsoft-Produkte**. Lege zunächst einen
Katalog an oder nutze den Standardkatalog. Für lokale Installer werden ein
absoluter Controller-Pfad und ein SHA-256-Hash hinterlegt. Danach kann der
Installer einem oder mehreren PCs zugewiesen werden.

Wenn ein Installer einen Token, Lizenzschlüssel oder ein Kennwort benötigt,
lege den Wert zuerst unter **Zugangsdaten & Vault** → **Installer-Geheimnis
verschlüsselt anlegen** ab. Im Katalog wird nur die Referenz `{{ vault_name }}`
verwendet.

## Spätere, optionale Erweiterungen

| Bedarf | Nächster Schritt |
| --- | --- |
| Software liegt auf SMB/UNC | **Grundprofil & Softwarequelle** → **Softwarequelle, UNC und Laufwerk einrichten**; UNC und Anmeldung werden in der TUI abgefragt |
| Windows-Laufwerk abbilden | **Grundprofil & Softwarequelle** → **Softwarequelle, UNC und Laufwerk einrichten** |
| AD-Domäne/WinRM-Kerberos | AD-DNS-Domäne im Setup setzen, danach Doctor → WinRM prüfen |
| DC, DNS, DHCP, Netzlaufwerke oder CA inventarisieren | Doctor → Offline-Collector oder Remote-Doctor |
| OpenSSH bereitstellen | PCs & Verbindung → OpenSSH / Windows-Verbindung |

Bei Unsicherheit zuerst den Gesamt-Doctor starten. Er ändert nichts und nennt
bei jedem fehlenden Wert den nächsten passenden Menüschritt.
