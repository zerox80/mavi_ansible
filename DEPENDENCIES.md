# Abhängigkeiten und Herkunft

Die für den unterstützten Controller festgelegten direkten Abhängigkeiten
stehen in `requirements-controller.txt` und `collections/requirements.yml`.
Versionsänderungen sind ein bewusster Wartungsvorgang und dürfen nicht durch
breite Mindestversionen unbemerkt in produktive Controller gelangen.

| Komponente | Festgelegte Version | Zweck | Lizenz / Herkunft |
| --- | ---: | --- | --- |
| Python | 3.11 oder neuer | Controller-Laufzeit | PSF License / python.org |
| PyYAML | 6.0.3 | Sichere YAML-Verarbeitung mit `safe_load` | MIT / PyPI |
| pefile | 2024.8.26 | Optionaler PE-Metadaten-Scan | MIT / PyPI |
| ansible-core | 2.19.12 | Controller und SSH-/PSRP-Ausführung | GPL-3.0-or-later / PyPI |
| ansible.windows | 3.7.0 | Windows-Module und PowerShell-Transport | GPL-3.0-or-later / Ansible Galaxy |

Die Dateien pinnen die direkten Komponenten. Vor einem öffentlichen Release
muss zusätzlich ein plattformspezifischer, hashgesicherter Lock aus der
freigegebenen Build-Umgebung erzeugt und zusammen mit einer SPDX- oder
CycloneDX-SBOM veröffentlicht werden. Ein Lock wird hier nicht vorgetäuscht,
solange diese Build-Umgebung und ihre Zielplattform nicht festgelegt sind.

Mavi lädt oder aktualisiert diese Komponenten bei normalen Provisionierungs-
läufen nicht automatisch. Änderungen an Systempaketen erfolgen nur in einem
ausdrücklich gestarteten Setup-Schritt und müssen vorab angezeigt werden.
