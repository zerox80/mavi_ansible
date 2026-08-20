# Contributing

## Grundregeln

- Keine Domains, IPs, Hostnamen, Shares, Benutzer, Zertifikate, Installermedien oder Secrets aus echten Kunden- oder Firmenumgebungen committen.
- Neue Defaults müssen generisch und funktionslos sein, bis der Setup-Assistent sie befüllt.
- Änderungen an Transport, Firewall, PKI oder Authentifizierung brauchen eine Sicherheitsbegründung in der Pull Request.
- Neue TUI-Funktionen brauchen eine klare, nicht technische Handlungsempfehlung für den Doctor.

## Lokale Umgebung

~~~bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
~~~

Für die eigentliche Windows-Provisionierung wird Ansible auf einem Linux-Controller benötigt. Verwende für Entwicklung ein vollständig synthetisches Lab, nie Produktionsinventories.

## Pull Requests

Beschreibe:

1. die Nutzerwirkung;
2. welche Daten im Laufzeitprojekt landen;
3. ob sich Rechte, Netzwerkzugriffe oder Sicherheitseigenschaften ändern;
4. wie die Änderung in einem synthetischen Lab validiert wurde.
