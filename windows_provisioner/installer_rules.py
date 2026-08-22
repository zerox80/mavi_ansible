# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Gelernte Installerregeln.

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


SILENT_SWITCH_DEFINITIONS: dict[str, dict[str, Any]] = {
    "/silent": {
        "kind": "silent",
        "weight": 9,
        "canonical": "/silent",
    },
    "--silent": {
        "kind": "silent",
        "weight": 9,
        "canonical": "--silent",
    },
    "/verysilent": {
        "kind": "silent",
        "weight": 10,
        "canonical": "/VERYSILENT",
    },
    "/quiet": {
        "kind": "silent",
        "weight": 9,
        "canonical": "/quiet",
    },
    "--quiet": {
        "kind": "silent",
        "weight": 9,
        "canonical": "--quiet",
    },
    "/qn": {
        "kind": "silent",
        "weight": 10,
        "canonical": "/qn",
    },
    "/passive": {
        "kind": "passive",
        "weight": 5,
        "canonical": "/passive",
    },
    "/s": {
        "kind": "silent_ambiguous",
        "weight": 3,
        "canonical": "/S",
    },
    "-s": {
        "kind": "silent_ambiguous",
        "weight": 2,
        "canonical": "-s",
    },
    "/norestart": {
        "kind": "restart",
        "weight": 7,
        "canonical": "/norestart",
    },
    "/noreboot": {
        "kind": "restart",
        "weight": 7,
        "canonical": "/noreboot",
    },
    "/suppressmsgboxes": {
        "kind": "ui",
        "weight": 7,
        "canonical": "/SUPPRESSMSGBOXES",
    },
    "/exenoui": {
        "kind": "ui",
        "weight": 6,
        "canonical": "/exenoui",
    },
    "/install": {
        "kind": "action",
        "weight": 3,
        "canonical": "/install",
    },
    "--install": {
        "kind": "action",
        "weight": 3,
        "canonical": "--install",
    },
}

HELP_CONTEXT_MARKERS = (
    "usage",
    "command line",
    "command-line",
    "commandline",
    "options",
    "arguments",
    "switches",
    "silent",
    "quiet",
    "unattended",
    "unattend",
    "norestart",
    "noreboot",
    "install",
    "setup",
)


def normalize_rule_key(value: str) -> str:
    value = (value or "").lower().strip()
    value = re.sub(r"[^a-z0-9äöüß]+", "_", value)
    return value.strip("_")


def learned_rule_identity(
    path: Path,
    metadata: dict[str, Any],
) -> tuple[str, str]:
    """
    Stable Produktidentität:
    Company + Product bevorzugt, sonst OriginalFilename, sonst Dateiname.
    """
    from .installer_analysis import (
        _clean_pe_text,
        normalize_rule_key,
    )

    company = _clean_pe_text(metadata.get("CompanyName", ""))
    product = _clean_pe_text(metadata.get("ProductName", ""))
    original = _clean_pe_text(metadata.get("OriginalFilename", ""))

    if company and product:
        label = f"{company} | {product}"
        key = normalize_rule_key(f"{company}__{product}")
        return key, label

    if product:
        label = product
        key = normalize_rule_key(product)
        return key, label

    if original:
        label = original
        key = normalize_rule_key(original)
        return key, label

    label = path.name
    key = normalize_rule_key(path.name)
    return key, label


def load_installer_rules(project: Path) -> dict[str, Any]:
    from .environment import (
        ensure_initialized,
        load_yaml,
        project_paths,
    )

    ensure_initialized(project, quiet=True)
    p = project_paths(project)

    if not p["installer_rules"].exists():
        return {"installer_rules": {}}

    data = load_yaml(p["installer_rules"])
    if not isinstance(data, dict):
        return {"installer_rules": {}}

    rules = data.get("installer_rules")
    if not isinstance(rules, dict):
        data["installer_rules"] = {}

    return data


def save_installer_rules(project: Path, data: dict[str, Any]) -> None:
    from .environment import (
        atomic_write_yaml,
        project_paths,
    )

    p = project_paths(project)
    p["installer_rules"].parent.mkdir(parents=True, exist_ok=True)
    atomic_write_yaml(p["installer_rules"], data)


def find_learned_installer_rule(
    project: Path,
    path: Path,
    metadata: dict[str, Any],
) -> tuple[str, dict[str, Any]] | None:
    from .installer_analysis import (
        learned_rule_identity,
        load_installer_rules,
    )

    data = load_installer_rules(project)
    rules = data.get("installer_rules", {})

    rule_key, _ = learned_rule_identity(path, metadata)
    rule = rules.get(rule_key)

    if isinstance(rule, dict):
        return rule_key, rule

    return None


def remember_installer_rule(
    project: Path,
    path: Path,
    analysis: dict[str, Any],
    *,
    arguments: str,
    context: str,
    creates_path: str,
) -> tuple[str, str]:
    from .installer_analysis import (
        learned_rule_identity,
        load_installer_rules,
        save_installer_rules,
    )

    metadata = analysis.get("metadata", {}) or {}
    key, label = learned_rule_identity(path, metadata)

    data = load_installer_rules(project)
    rules = data.setdefault("installer_rules", {})

    rules[key] = {
        "label": label,
        "company": metadata.get("CompanyName", ""),
        "product": metadata.get("ProductName", ""),
        "original_filename": metadata.get("OriginalFilename", ""),
        "arguments": arguments,
        "context": context,
        "creates_path": creates_path,
        "source": "user_confirmed",
    }

    save_installer_rules(project, data)
    return key, label
