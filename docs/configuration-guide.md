# Konfigurations- und Discovery-Leitfaden

Mavi trennt bewusst zwischen dem ersten Grundprofil und späteren
Infrastrukturdetails. Damit kann ein neuer Benutzer sofort ein Projekt und
einen ersten PC anlegen, ohne vorab Controller, Domänencontroller, Shares und
Zertifizierungsstelle vollständig kennen zu müssen.

## Welche Information kommt woher?

| Thema | Einfachster Weg | Ergebnis in Mavi |
| --- | --- | --- |
| Controller-IP | IPv4 des Rechners, auf dem Mavi/Ansible läuft und den Windows-PCs erreichen können | `ansible_server_ip` |
| Windows-Anmeldekonto | vorhandenes lokales Admin- oder Domänen-Provisioningkonto | `identity.ansible_user` und verschlüsseltes `ansible_password` im Vault |
| AD-DNS-Domäne | DNS-Suffix der AD-Domäne, z. B. `ad.example.org` | `winrm_https.domain_suffix` |
| DCs/DNS/Kerberos/LDAP | Doctor-Collector auf einem Domänen-PC oder Remote-Doctor | JSON-Faktenbericht und Doctor-Ergebnis |
| DHCP/Gateway/Subnetze | Doctor-Collector | JSON-Faktenbericht und Doctor-Ergebnis |
| Netzlaufwerke/SMB | Doctor-Collector; anschließend **Grundprofil & Softwarequelle** → **Softwarequelle, UNC und Laufwerk einrichten** | `software_source.drive`, `unc_root`, `path_mappings` |
| Enterprise-CA/AD CS | Doctor-Collector oder AD-CS-Team | Faktenbericht; danach nur bei Bedarf WinRM-/CA-Workflow |
| Installerquelle | lokaler Ordner oder gemounteter SMB-Pfad auf dem Controller | `software_source.local_root` |

## Domänencontroller, DNS, DHCP und CA finden

Für einen neuen PC ohne Remote-Zugang wähle in der TUI:

`Doctor & Bereitschaft → Offline-Collector für einen Windows-PC erzeugen`

Kopiere die erzeugte PowerShell-Datei auf einen repräsentativen Windows-PC,
führe sie dort als Administrator aus und importiere die JSON-Datei wieder in
Mavi. Der Collector liest nur. Er installiert keinen Dienst, öffnet keine
Firewall und schreibt außer dem Faktenbericht keine Systemkonfiguration.

Der Bericht enthält insbesondere:

- Domänenmitgliedschaft, Logon-Server und gefundene LDAP-/Kerberos-SRV-Ziele;
- aktive IPv4-Netze, DNS-Server, DHCP-Server und Standardgateways;
- gemappte Netzlaufwerke und SMB-Mappings im aktuellen Kontext;
- veröffentlichte Enterprise-CAs und Enrollment-Templates;
- Status von OpenSSH und WinRM.

Wenn bereits SSH oder PSRP funktioniert, ist `Doctor → Einen bereits
erreichbaren Windows-PC remote prüfen` bequemer. Auch dieser Modus sammelt nur
temporäre Fakten.

## SMB-Quelle und Windows-Laufwerk

Der Standardordner im Laufzeitprojekt ist ideal für lokal abgelegte Installer.
Liegen die Installer auf einem Share, öffne in der TUI **Grundprofil &
Softwarequelle** → **Softwarequelle, UNC und Laufwerk einrichten**.

Wähle dort **Windows-Freigabe / UNC** und gib die UNC-Wurzel sowie optional den
Windows-Laufwerksbuchstaben an. Mavi wählt den internen Controller-Pfad selbst,
installiert bei Bedarf `cifs-utils` und bindet die Freigabe direkt aus der TUI
ein. Falls die Freigabe eine Anmeldung verlangt, werden Benutzer und Kennwort
ebenfalls im Dialog abgefragt. Kann der Linux-Controller einen kurzen
Windows-Servernamen nicht per DNS auflösen, fragt Mavi in derselben TUI nach
der zugehörigen IP-Adresse oder dem vollständigen DNS-Namen.

## AD und WinRM erst dann aktivieren, wenn benötigt

OpenSSH eignet sich für den ersten Managementkontakt. PSRP/WinRM mit Kerberos
ist ein optionaler Domänenweg. Vor dessen Einrichtung sollten vorliegen:

1. korrekte AD-DNS-Domäne;
2. funktionierende Namensauflösung zum DC;
3. ein Vault-gesichertes Domänenkonto;
4. die vom Doctor geforderten Controller-Voraussetzungen.

Danach den gezielten Check ausführen:

~~~bash
python3 mavi_provisioner.py doctor --feature winrm
~~~

## CA-Informationen

Eine Enterprise-CA wird nicht im Grundprofil abgefragt. Der Collector zeigt
veröffentlichte CA- und Template-Informationen, damit klar ist, was in der
Umgebung tatsächlich vorhanden ist. Erst der gewünschte WinRM-/PKI-Schritt
braucht daraus konkrete Werte. So werden neue Benutzer nicht mit einer
Domänen-PKI-Konfiguration blockiert, die sie für Softwareverteilung oder den
ersten SSH-PC gar nicht brauchen.

## Konfiguration korrigieren

- Grunddaten ändern: **Schnellstart / Grundprofil** erneut öffnen.
- SMB, Laufwerk und UNC ändern: **Grundprofil & Softwarequelle** → **Softwarequelle, UNC und Laufwerk einrichten**.
- Benutzer/Kennwort ändern: **Zugangsdaten & Vault**.
- Fehlende Fakten verstehen: **Doctor & Bereitschaft**.

Die Datei `software/mavi_config.yml` im Laufzeitprojekt bleibt eine
nicht-geheime Konfiguration. Sie kann geprüft werden, sollte aber nicht als
Ort für Kennwörter oder Tokens verwendet werden.
