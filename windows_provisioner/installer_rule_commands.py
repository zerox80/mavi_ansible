# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""CLI-Befehle für Installerregeln.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    pefile,
    re,
    shutil,
    struct,
    subprocess,
    sys,
)




def cmd_rules_list(args: argparse.Namespace) -> None:
    from .installer_analysis import (
        load_installer_rules,
    )

    data = load_installer_rules(args.project)
    rules = data.get("installer_rules", {})

    print()
    print("GELERNTE INSTALLER-REGELN")
    print("=========================")

    if not rules:
        print("Noch keine lokalen Regeln gespeichert.")
        return

    for idx, (key, rule) in enumerate(
        sorted(rules.items()),
        start=1,
    ):
        print(
            f"{idx:>3}) {rule.get('label', key)}"
            f"  [{rule.get('arguments', '')}]"
        )


def cmd_rules_remove(args: argparse.Namespace) -> None:
    from .installer_analysis import (
        load_installer_rules,
        save_installer_rules,
    )

    from .catalogs import (
        select_from_list,
        yes_no,
    )
    from .environment import die

    data = load_installer_rules(args.project)
    rules = data.get("installer_rules", {})

    if not rules:
        print("Keine lokalen Installer-Regeln vorhanden.")
        return

    key = args.key

    if not key and sys.stdin.isatty():
        key = select_from_list(
            "Gelernte Regel entfernen",
            [
                (rule_key, str(rule.get("label", rule_key)))
                for rule_key, rule in sorted(rules.items())
            ],
        )

    if key not in rules:
        die(f"Installer-Regel '{key}' nicht gefunden.")

    label = str(rules[key].get("label", key))

    if not getattr(args, "yes", False):
        if not yes_no(
            f"Gelernte Regel '{label}' wirklich entfernen?",
            False,
        ):
            print("Abgebrochen.")
            return

    del rules[key]
    save_installer_rules(args.project, data)
    print(f"✓ Gelernte Installer-Regel '{label}' entfernt.")
