# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Portable Erkennung und Analyse von Installationsprogrammen."""

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



def _ascii_readability(value: str) -> float:
    """
    Anteil normal lesbarer ASCII-Zeichen.
    Binär-/Mojibake-Strings wie 'ñëäõ.../qn...' sollen durchfallen.
    """
    if not value:
        return 0.0

    allowed = 0
    total = 0

    for ch in value:
        if ch in "\r\n\t":
            allowed += 1
            total += 1
            continue

        total += 1

        code = ord(ch)
        if 32 <= code <= 126:
            allowed += 1

    return allowed / max(total, 1)


def _word_quality(value: str) -> dict[str, Any]:
    """
    Prüft, ob ein String nach menschlich lesbarem CLI-/Hilfetext aussieht.
    """
    value = value.strip()
    lower = value.lower()

    ascii_ratio = _ascii_readability(value)
    words = re.findall(r"[a-zA-Z]{3,}", value)
    help_hits = [
        marker
        for marker in HELP_CONTEXT_MARKERS
        if marker in lower
    ]

    # Typische CLI-Erklärungen.
    semantic_hits = [
        marker
        for marker in (
            "silent",
            "quiet",
            "install",
            "installation",
            "setup",
            "option",
            "usage",
            "argument",
            "switch",
            "reboot",
            "restart",
            "unattended",
            "msiexec",
            "windows installer",
            "user interface",
            "no ui",
            "without ui",
        )
        if marker in lower
    ]

    # Muss fast komplett lesbar sein. Unicode-Müll aus zufälligem UTF-16
    # wird dadurch nicht als CLI-Hilfe akzeptiert.
    human_readable = (
        ascii_ratio >= 0.92
        and (
            len(words) >= 2
            or len(help_hits) >= 1
            or len(semantic_hits) >= 1
        )
    )

    return {
        "ascii_ratio": round(ascii_ratio, 3),
        "word_count": len(words),
        "help_hits": help_hits,
        "semantic_hits": semantic_hits,
        "human_readable": human_readable,
    }


def _embedded_cli_records_from_binary(
    sample: bytes,
) -> list[dict[str, Any]]:
    """
    Extrahiert tatsächliche ASCII-/UTF-16LE-Strings aus der Binärdatei,
    statt die gesamte EXE blind als Text zu decodieren.
    """
    strings = _printable_pe_strings(sample)
    records: list[dict[str, Any]] = []

    for idx, (offset, value) in enumerate(strings):
        current = _clean_pe_text(value)
        if not current:
            continue

        # Nachbarstrings helfen bei Ressourcen wie:
        #   "/silent"
        #   "Perform silent installation"
        neighbours: list[str] = []

        for neighbour_idx in (idx - 1, idx, idx + 1):
            if 0 <= neighbour_idx < len(strings):
                neighbour_offset, neighbour_value = strings[neighbour_idx]

                # Nur nahe beieinanderliegende Resource-/Stringdaten verbinden.
                if abs(neighbour_offset - offset) <= 2048:
                    cleaned = _clean_pe_text(neighbour_value)
                    if cleaned:
                        neighbours.append(cleaned)

        context = " | ".join(dict.fromkeys(neighbours))
        quality = _word_quality(context)

        records.append({
            "offset": offset,
            "value": current,
            "context": context[:600],
            "quality": quality,
        })

    return records


def _switch_context_is_plausible(
    switch: str,
    context: str,
    quality: dict[str, Any],
) -> tuple[bool, str, int]:
    """
    Sicherheits-Gate vor dem Scoring.
    """
    lower = context.lower()
    switch_lower = switch.lower()

    if not quality.get("human_readable"):
        return (
            False,
            "verworfen: Kontext sieht nach Binär-/Mojibake-Daten aus",
            -100,
        )

    semantic = set(quality.get("semantic_hits", []))
    help_hits = set(quality.get("help_hits", []))

    # /qn ist ein MSI-UI-Schalter. Bei einer beliebigen EXE nur akzeptieren,
    # wenn der Kontext klar MSI/Windows Installer/quiet-install beschreibt.
    if switch_lower == "/qn":
        if not any(
            marker in lower
            for marker in (
                "msiexec",
                "windows installer",
                " msi",
                "msi ",
                "quiet",
                "silent",
                "no ui",
                "user interface",
            )
        ):
            return (
                False,
                "verworfen: /qn ohne MSI-/Quiet-/UI-Kontext",
                -30,
            )
        return True, "plausibel: /qn mit MSI-/Quiet-Kontext", 2

    # /S und -s sind extrem mehrdeutig. Nur bei Help-/Silent-Kontext.
    if switch_lower in {"/s", "-s"}:
        if not any(
            marker in lower
            for marker in (
                "silent",
                "quiet",
                "unattended",
                "usage",
                "options",
                "command line",
                "switch",
            )
        ):
            return (
                False,
                "verworfen: /S bzw. -s ohne Silent-/Help-Kontext",
                -30,
            )
        return True, "plausibel: /S mit Silent-/Help-Kontext", 0

    # Restart-Schalter alleine sagen noch nichts über Silent-Installation,
    # dürfen aber als Zusatzkandidat erkannt werden.
    if switch_lower in {"/norestart", "/noreboot"}:
        if not any(
            marker in lower
            for marker in (
                "restart",
                "reboot",
                "install",
                "setup",
                "option",
                "usage",
            )
        ):
            return (
                False,
                "verworfen: Neustart-Schalter ohne CLI-/Installationskontext",
                -20,
            )

    # Starke Silent-Schalter brauchen wenigstens lesbaren Kontext.
    if switch_lower in {
        "/silent",
        "--silent",
        "/verysilent",
        "/quiet",
        "--quiet",
        "/passive",
        "/suppressmsgboxes",
        "/exenoui",
    }:
        if not (
            semantic
            or help_hits
            or any(
                marker in lower
                for marker in (
                    "silent",
                    "quiet",
                    "install",
                    "setup",
                )
            )
        ):
            return (
                False,
                "verworfen: Silent-Schalter ohne semantischen CLI-Kontext",
                -20,
            )

    return True, "plausibler lesbarer CLI-Kontext", 0


def _extract_switch_occurrences_from_binary(
    sample: bytes,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Liefert akzeptierte UND verworfene Kandidaten.
    """
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []

    for record in _embedded_cli_records_from_binary(sample):
        value = str(record["value"])
        context = str(record["context"])
        context_lower = context.lower()
        quality = record["quality"]

        for switch, definition in SILENT_SWITCH_DEFINITIONS.items():
            pattern = (
                r"(?<![a-z0-9])"
                + re.escape(switch)
                + r"(?![a-z0-9])"
            )

            if not (
                re.search(pattern, value, re.IGNORECASE)
                or re.search(pattern, context, re.IGNORECASE)
            ):
                continue

            plausible, evidence, evidence_bonus = _switch_context_is_plausible(
                switch,
                context,
                quality,
            )

            base_score = int(definition["weight"])

            context_hits = [
                marker
                for marker in HELP_CONTEXT_MARKERS
                if marker in context_lower
            ]
            context_bonus = min(8, 2 + len(context_hits)) if context_hits else 0

            direct_help_bonus = 0
            if any(
                marker in context_lower
                for marker in (
                    "usage:",
                    "options:",
                    "command line",
                    "silent install",
                    "quiet install",
                    "perform silent",
                    "installs silently",
                )
            ):
                direct_help_bonus = 5

            score = (
                base_score
                + context_bonus
                + direct_help_bonus
                + evidence_bonus
            )

            item = {
                "switch": switch,
                "canonical": definition["canonical"],
                "kind": definition["kind"],
                "score": score,
                "offset": record["offset"],
                "context": context[:300],
                "ascii_ratio": quality.get("ascii_ratio"),
                "word_count": quality.get("word_count"),
                "evidence": evidence,
            }

            if plausible:
                accepted.append(item)
            else:
                rejected.append(item)

    return accepted, rejected



def _extract_switch_occurrences(text_data: str) -> list[dict[str, Any]]:
    """
    Findet CLI-Schalter nur statisch in eingebetteten Strings.
    Die EXE wird NICHT ausgeführt.
    """
    occurrences: list[dict[str, Any]] = []

    # Zeilen begrenzen, damit sehr lange Binär-Decodes nicht wild korrelieren.
    lines = text_data.splitlines()

    for line_no, raw_line in enumerate(lines):
        line = raw_line.strip()
        if not line:
            continue

        line_lower = line.lower()
        if len(line_lower) > 3000:
            line_lower = line_lower[:3000]

        context_bonus = 0
        context_hits = [
            marker for marker in HELP_CONTEXT_MARKERS
            if marker in line_lower
        ]
        if context_hits:
            context_bonus = min(8, 2 + len(context_hits))

        for switch, definition in SILENT_SWITCH_DEFINITIONS.items():
            # /S ist extrem häufig als Zufall in Pfaden/Strings.
            # Deshalb nur als eigenständiges Token werten.
            pattern = (
                r"(?<![a-z0-9])"
                + re.escape(switch)
                + r"(?![a-z0-9])"
            )

            if not re.search(pattern, line_lower, re.IGNORECASE):
                continue

            score = int(definition["weight"]) + context_bonus

            # Extra Bonus wenn die Zeile direkt nach Hilfe aussieht.
            if any(
                marker in line_lower
                for marker in (
                    "usage:",
                    "options:",
                    "command line",
                    "silent install",
                    "quiet install",
                )
            ):
                score += 5

            occurrences.append({
                "switch": switch,
                "canonical": definition["canonical"],
                "kind": definition["kind"],
                "score": score,
                "line_no": line_no,
                "context": line[:240],
            })

    return occurrences


def _dedupe_switch_candidates(
    occurrences: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}

    for item in occurrences:
        canonical = str(item["canonical"]).lower()
        current = best.get(canonical)

        if current is None or item["score"] > current["score"]:
            best[canonical] = item

    return sorted(
        best.values(),
        key=lambda item: (-int(item["score"]), str(item["canonical"]).lower()),
    )



def infer_silent_arguments_from_binary(
    sample: bytes,
    *,
    engine: str = "unbekannt",
) -> dict[str, Any]:
    """
    Statische Silent-Erkennung direkt aus echten eingebetteten Strings.
    Die komplette EXE wird NICHT als Text interpretiert.
    """
    occurrences, rejected = _extract_switch_occurrences_from_binary(sample)
    candidates = _dedupe_switch_candidates(occurrences)

    engine_lower = engine.lower()

    if "inno setup" in engine_lower:
        return {
            "arguments": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "rejected_candidates": rejected[:12],
            "reason": "Inno Setup erkannt.",
        }

    if "nsis" in engine_lower or "nullsoft" in engine_lower:
        return {
            "arguments": "/S",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "rejected_candidates": rejected[:12],
            "reason": "NSIS/Nullsoft erkannt.",
        }

    if "wix burn" in engine_lower:
        return {
            "arguments": "/quiet /norestart",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "rejected_candidates": rejected[:12],
            "reason": "WiX Burn erkannt.",
        }

    silent = [
        x
        for x in candidates
        if x["kind"] in {"silent", "silent_ambiguous"}
    ]
    restart = [
        x
        for x in candidates
        if x["kind"] == "restart"
    ]
    ui = [
        x
        for x in candidates
        if x["kind"] == "ui"
    ]

    strong_silent = [
        x
        for x in silent
        if int(x["score"]) >= 13
    ]
    medium_silent = [
        x
        for x in silent
        if int(x["score"]) >= 10
    ]

    chosen: list[str] = []
    confidence = "niedrig"
    reason = (
        "Keine belastbare Silent-Kombination in lesbaren "
        "CLI-/Help-Strings erkannt."
    )

    if strong_silent:
        best = strong_silent[0]

        # /qn und /S bleiben selbst bei gutem Kontext vorsichtiger,
        # solange keine passende Engine erkannt wurde.
        if str(best["canonical"]).lower() not in {"/qn", "/s", "-s"}:
            chosen.append(str(best["canonical"]))

            strong_restart = [
                x for x in restart
                if int(x["score"]) >= 10
            ]
            if strong_restart:
                chosen.append(
                    str(strong_restart[0]["canonical"])
                )

            strong_ui = [
                x for x in ui
                if int(x["score"]) >= 11
            ]
            if strong_ui:
                chosen.append(str(strong_ui[0]["canonical"]))

            confidence = "hoch"
            reason = (
                "Starke, lesbare eingebettete CLI-/Help-Strings erkannt."
            )

        elif str(best["canonical"]).lower() == "/qn":
            # /qn ohne erkannte MSI-Wrapper-Engine niemals automatisch
            # als EXE-Argument setzen.
            confidence = "niedrig"
            reason = (
                "/qn wurde in lesbarem Kontext gefunden, aber ohne "
                "erkannte MSI-/Wrapper-Engine nicht automatisch verwendet."
            )

        else:
            confidence = "niedrig"
            reason = (
                "/S bzw. -s ist ohne erkannte Installer-Engine zu mehrdeutig "
                "und wird nicht automatisch verwendet."
            )

    elif medium_silent:
        best = medium_silent[0]

        if str(best["canonical"]).lower() not in {"/qn", "/s", "-s"}:
            chosen.append(str(best["canonical"]))

            medium_restart = [
                x
                for x in restart
                if int(x["score"]) >= 9
            ]
            if medium_restart:
                chosen.append(
                    str(medium_restart[0]["canonical"])
                )

            confidence = "mittel"
            reason = (
                "Plausible, lesbare CLI-Strings erkannt, "
                "aber keine eindeutige Installer-Engine."
            )

    return {
        "arguments": " ".join(dict.fromkeys(chosen)),
        "confidence": confidence,
        "method": "embedded_cli_strings",
        "source_label": "EINGEBETTETE CLI-STRINGS",
        "candidates": candidates[:12],
        "rejected_candidates": rejected[:12],
        "reason": reason,
    }



def infer_silent_arguments_from_strings(
    text_data: str,
    *,
    engine: str = "unbekannt",
) -> dict[str, Any]:
    """
    Liefert Vorschlag + Evidenz + Konfidenz.
    Nichts wird ausgeführt.
    """
    occurrences = _extract_switch_occurrences(text_data)
    candidates = _dedupe_switch_candidates(occurrences)

    # Engine-spezifische sichere Regeln zuerst.
    engine_lower = engine.lower()

    if "inno setup" in engine_lower:
        return {
            "arguments": "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "reason": "Inno Setup erkannt.",
        }

    if "nsis" in engine_lower or "nullsoft" in engine_lower:
        return {
            "arguments": "/S",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "reason": "NSIS/Nullsoft erkannt.",
        }

    if "wix burn" in engine_lower:
        return {
            "arguments": "/quiet /norestart",
            "confidence": "hoch",
            "method": "installer_engine",
            "source_label": "INSTALLER-ENGINE",
            "candidates": candidates,
            "reason": "WiX Burn erkannt.",
        }

    # Statischer Kandidaten-Score.
    silent = [
        x for x in candidates
        if x["kind"] in {"silent", "silent_ambiguous"}
    ]
    restart = [
        x for x in candidates
        if x["kind"] == "restart"
    ]
    ui = [
        x for x in candidates
        if x["kind"] == "ui"
    ]

    # Nur starke Kandidaten automatisch kombinieren.
    strong_silent = [x for x in silent if int(x["score"]) >= 11]
    medium_silent = [x for x in silent if int(x["score"]) >= 8]

    chosen: list[str] = []
    confidence = "niedrig"
    reason = "Keine belastbare Silent-Kombination erkannt."

    if strong_silent:
        chosen.append(str(strong_silent[0]["canonical"]))

        strong_restart = [
            x for x in restart if int(x["score"]) >= 9
        ]
        if strong_restart:
            chosen.append(str(strong_restart[0]["canonical"]))

        strong_ui = [
            x for x in ui if int(x["score"]) >= 10
        ]
        if strong_ui:
            chosen.append(str(strong_ui[0]["canonical"]))

        confidence = "hoch"
        reason = (
            "Starke eingebettete CLI-/Help-Strings mit Silent-Schalter erkannt."
        )

    elif medium_silent:
        # /S alleine ist zu mehrdeutig.
        best = medium_silent[0]
        if str(best["canonical"]).lower() not in {"/s", "-s"}:
            chosen.append(str(best["canonical"]))

            medium_restart = [
                x for x in restart if int(x["score"]) >= 7
            ]
            if medium_restart:
                chosen.append(str(medium_restart[0]["canonical"]))

            confidence = "mittel"
            reason = (
                "Plausible eingebettete CLI-Strings erkannt, "
                "aber keine eindeutige Installer-Engine."
            )

    return {
        "arguments": " ".join(dict.fromkeys(chosen)),
        "confidence": confidence,
        "method": "embedded_cli_strings",
        "source_label": "EINGEBETTETE CLI-STRINGS",
        "candidates": candidates[:12],
        "reason": reason,
    }


def print_silent_detection(analysis: dict[str, Any]) -> None:
    detection = analysis.get("silent_detection") or {}
    candidates = detection.get("candidates") or []
    rejected = detection.get("rejected_candidates") or []

    if not detection:
        print()
        print("Silent-Erkennung")
        print("================")
        print("Quelle:      KEINE")
        print("Ergebnis:    kein belastbarer Silent-Parameter")
        return

    method = str(detection.get("method", "unbekannt"))
    source_label = str(
        detection.get("source_label")
        or {
            "known_product_rule": "FESTE PRODUKTREGEL",
            "learned_product_rule": "GELERNTE REGEL",
            "installer_engine": "INSTALLER-ENGINE",
            "embedded_cli_strings": "EINGEBETTETE CLI-STRINGS",
        }.get(method, method.upper())
    )

    print()
    print("Silent-Erkennung")
    print("================")
    print(f"Quelle:      {source_label}")
    print(f"Technisch:   {method}")
    print(
        f"Ergebnis:    "
        f"{detection.get('arguments') or analysis.get('arguments') or '(keins)'}"
    )
    print(
        f"Konfidenz:   "
        f"{detection.get('confidence', analysis.get('confidence', 'niedrig'))}"
    )

    reason = detection.get("reason")
    if reason:
        print(f"Bewertung:   {reason}")

    if candidates:
        print()
        print("Akzeptierte CLI-Kandidaten")
        print("--------------------------")

        for item in candidates[:10]:
            print(
                f"  {item.get('canonical', '?'):<18} "
                f"Score {item.get('score', '?')}  "
                f"ASCII {item.get('ascii_ratio', '?')}"
            )
            if item.get("evidence"):
                print(f"      Evidenz: {item['evidence']}")
            context = str(item.get("context", "")).strip()
            if context:
                print(f"      Kontext: {context[:180]}")

    if rejected:
        print()
        print("Verworfene Treffer")
        print("------------------")

        for item in rejected[:8]:
            print(
                f"  {item.get('canonical', '?'):<18} "
                f"{item.get('evidence', 'verworfen')}"
            )
            context = str(item.get("context", "")).strip()
            if context:
                print(f"      Kontext: {context[:160]}")



def cmd_rules_list(args: argparse.Namespace) -> None:
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



PE_VERSION_KEYS = (
    "CompanyName",
    "ProductName",
    "FileDescription",
    "ProductVersion",
    "FileVersion",
    "OriginalFilename",
    "InternalName",
    "LegalCopyright",
)


def _clean_pe_text(value: Any) -> str:
    if isinstance(value, bytes):
        for encoding in ("utf-8", "utf-16le", "latin-1"):
            try:
                value = value.decode(encoding, errors="ignore")
                break
            except Exception:
                continue

    value = str(value or "")
    value = value.replace("\x00", "").strip()
    value = re.sub(r"\s+", " ", value)
    return value


def _pe_architecture_from_bytes(data: bytes) -> str:
    """
    Liest nur DOS/PE-Header. Keine Ausführung der EXE.
    """
    try:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return ""

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 6 > len(data):
            return ""

        if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
            return ""

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        return {
            0x014C: "x86",
            0x8664: "x64",
            0xAA64: "arm64",
        }.get(machine, f"0x{machine:04x}")
    except (struct.error, IndexError):
        return ""


def _printable_pe_strings(data: bytes) -> list[tuple[int, str]]:
    """
    Extrahiert ASCII- und UTF-16LE-Strings inklusive Position.
    Das dient als Fallback, wenn python-pefile nicht installiert ist.
    """
    found: list[tuple[int, str]] = []

    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){3,}", data):
        try:
            value = match.group(0).decode("utf-16le", errors="ignore").strip()
        except Exception:
            continue
        if value:
            found.append((match.start(), value))

    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        try:
            value = match.group(0).decode("latin-1", errors="ignore").strip()
        except Exception:
            continue
        if value:
            found.append((match.start(), value))

    found.sort(key=lambda item: item[0])
    return found


def _versioninfo_from_strings(data: bytes) -> dict[str, str]:
    """
    Windows VERSIONINFO besteht häufig aus UTF-16LE-Schlüsseln wie
    CompanyName/ProductName und dem direkt folgenden Wert.
    """
    strings = _printable_pe_strings(data)
    result: dict[str, str] = {}
    key_lookup = {key.lower(): key for key in PE_VERSION_KEYS}
    ignored_values = {
        "StringFileInfo",
        "VarFileInfo",
        "Translation",
        "VS_VERSION_INFO",
    }

    for idx, (offset, value) in enumerate(strings):
        canonical = key_lookup.get(value.lower())
        if not canonical or canonical in result:
            continue

        # Der Wert folgt im VERSIONINFO normalerweise kurz nach dem Schlüssel.
        for next_offset, candidate in strings[idx + 1: idx + 8]:
            if next_offset - offset > 2048:
                break

            candidate = _clean_pe_text(candidate)
            if not candidate:
                continue

            if candidate in ignored_values:
                continue

            if candidate.lower() in key_lookup:
                break

            # Binärrauschen und offensichtliche Struktur-Strings ignorieren.
            if len(candidate) > 300:
                continue
            if candidate.count("\\") > 8:
                continue

            result[canonical] = candidate
            break

    return result


def _versioninfo_with_pefile(path: Path) -> dict[str, str]:
    if pefile is None:
        return {}

    result: dict[str, str] = {}

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
            ]
        )

        for block in getattr(pe, "FileInfo", []) or []:
            # pefile kann FileInfo als verschachtelte Listen liefern.
            entries = block if isinstance(block, list) else [block]

            for entry in entries:
                key = _clean_pe_text(getattr(entry, "Key", ""))

                if key != "StringFileInfo":
                    continue

                for table in getattr(entry, "StringTable", []) or []:
                    for raw_key, raw_value in (
                        getattr(table, "entries", {}) or {}
                    ).items():
                        k = _clean_pe_text(raw_key)
                        v = _clean_pe_text(raw_value)
                        if k in PE_VERSION_KEYS and v:
                            result[k] = v

        try:
            pe.close()
        except Exception:
            pass

    except Exception:
        return {}

    return result


def inspect_pe_metadata(path: Path, sample: bytes | None = None) -> dict[str, Any]:
    """
    Deep-Scan einer Windows-EXE, ohne sie auszuführen.

    Reihenfolge:
      1. PE-Header / Architektur
      2. python-pefile, falls vorhanden
      3. eigener VERSIONINFO-String-Fallback
      4. optional Authenticode-Info über osslsigncode, falls installiert
    """
    from .environment import read_binary_sample

    metadata: dict[str, Any] = {}
    sources: list[str] = []

    try:
        if sample is None:
            sample = read_binary_sample(path)
    except OSError:
        sample = b""

    arch = _pe_architecture_from_bytes(sample or b"")
    if arch:
        metadata["PEArchitecture"] = arch
        sources.append("PE-Header")

    precise = _versioninfo_with_pefile(path)
    if precise:
        metadata.update(precise)
        sources.append("PE-VersionInfo (pefile)")

    fallback = _versioninfo_from_strings(sample or b"")
    for key, value in fallback.items():
        metadata.setdefault(key, value)
    if fallback:
        sources.append("PE-VersionInfo (String-Fallback)")

    # Optional: Signaturinformationen lesen, wenn osslsigncode vorhanden ist.
    # Fehlt das Tool, funktioniert der Scanner trotzdem vollständig weiter.
    osslsigncode = shutil.which("osslsigncode")
    if osslsigncode:
        try:
            proc = subprocess.run(
                [osslsigncode, "verify", "-in", str(path)],
                capture_output=True,
                text=True,
                timeout=20,
            )
            output = (proc.stdout or "") + "\n" + (proc.stderr or "")

            subject_patterns = [
                r"Subject:\s*(.+)",
                r"Signer Certificate:\s*\n\s*Subject:\s*(.+)",
            ]
            for pattern in subject_patterns:
                match = re.search(pattern, output, re.IGNORECASE)
                if match:
                    subject = _clean_pe_text(match.group(1))
                    if subject:
                        metadata["SignatureSubject"] = subject
                        sources.append("Authenticode (osslsigncode)")
                        break
        except (OSError, subprocess.TimeoutExpired):
            pass

    if sources:
        metadata["ScanSources"] = list(dict.fromkeys(sources))

    return metadata


def _metadata_blob(path: Path, metadata: dict[str, Any]) -> str:
    values = [str(path)]
    for key in (
        "CompanyName",
        "ProductName",
        "FileDescription",
        "OriginalFilename",
        "InternalName",
        "SignatureSubject",
    ):
        value = metadata.get(key)
        if value:
            values.append(str(value))
    return "\n".join(values).lower()


def _citrix_detection_path(metadata: dict[str, Any]) -> str:
    """
    Native x64 Citrix Workspace landet systemweit unter Program Files.
    Für x86 verwenden wir Program Files (x86).
    """
    arch = str(metadata.get("PEArchitecture", "")).lower()

    if arch == "x64":
        return (
            r"C:\Program Files\Citrix\ICA Client"
            r"\SelfServicePlugin\SelfService.exe"
        )

    return (
        r"C:\Program Files (x86)\Citrix\ICA Client"
        r"\Receiver\receiver.exe"
    )


def _apply_known_exe_product_rule(
    path: Path,
    result: dict[str, Any],
    metadata: dict[str, Any],
) -> bool:
    """
    Produktregeln verwenden Dateiname UND PE-Metadaten.
    Rückgabe True bedeutet: sichere bekannte Regel, Analyse ist fertig.
    """
    blob = _metadata_blob(path, metadata)

    # PASCOM
    if "pascom" in blob:
        result.update(
            type="exe",
            engine="PASCOM Windows App",
            arguments="/S",
            context="user_interactive",
            confidence="hoch",
            admin_requirement="nein",
            name_guess=metadata.get("ProductName") or "PASCOM",
            note=(
                "Bekannte PASCOM-Regel. Für den normalen Client wird der "
                "nicht erhöhte Benutzerkontext verwendet."
            ),
        )
        result["reasons"].extend([
            "PASCOM über Dateiname oder PE-Metadaten erkannt.",
            "Bekannte Mavi-Regel: Silent-Schalter /S.",
            "Bekannte Mavi-Regel: interaktive Installation im angemeldeten Benutzerkontext.",
        ])
        return True

    # FortiClient
    if "forticlient" in blob or "fortivpn" in blob:
        result.update(
            type="exe",
            engine="FortiClient VPN",
            arguments="/quiet /norestart",
            context="machine",
            confidence="hoch",
            admin_requirement="ja",
            name_guess=metadata.get("ProductName") or "FortiClient VPN",
            note=(
                "FortiClient über Dateiname oder PE-Metadaten erkannt. "
                "Systemweite Installation wird als Machine/Admin behandelt."
            ),
        )
        result["reasons"].extend([
            "FortiClient/FortiVPN über Dateiname oder PE-Metadaten erkannt.",
            "Bekannte Mavi-Regel: /quiet /norestart.",
            "Systemweite VPN-Client-Installation.",
        ])
        return True

    # Citrix Workspace
    citrix_workspace = (
        "citrixworkspaceapp" in blob.replace(" ", "")
        or (
            "citrix" in blob
            and (
                "workspace" in blob
                or "receiver" in blob
            )
        )
    )

    if citrix_workspace:
        detection_path = _citrix_detection_path(metadata)
        result.update(
            type="exe",
            engine="Citrix Workspace",
            arguments="/silent /noreboot",
            context="machine",
            confidence="hoch",
            admin_requirement="ja",
            name_guess=metadata.get("ProductName") or "Citrix Workspace",
            creates_path=detection_path,
            note=(
                "Citrix Workspace über Dateiname/PE-Metadaten erkannt. "
                "Für Mavi wird die systemweite unbeaufsichtigte Installation verwendet."
            ),
        )
        result["metadata"]["DetectedProduct"] = "Citrix Workspace"
        result["reasons"].extend([
            "Citrix Workspace über Dateiname oder PE-VersionInfo erkannt.",
            "Silent-Installation: /silent /noreboot.",
            "Mavi-Provisioner: systemweit als Machine/Admin.",
            f"Detection-Datei: {detection_path}",
        ])
        return True

    return False




def analyze_installer(
    path: Path,
    project: Path | None = None,
    *,
    use_known_rules: bool = True,
    use_learned_rules: bool = False,
) -> dict[str, Any]:
    """
    v0.8: bewusst KEIN Deep-Scan mehr.

    Es werden nur noch:
      - Dateityp MSI/EXE,
      - feste, im Skript hinterlegte Produktregeln
    verwendet.

    Unbekannte EXE-Parameter werden immer vom Benutzer eingetragen.
    Keine Binary-String-Suche, keine Engine-Raterei, keine gelernten
    Regeln und keine automatische Silent-Erkennung.
    """
    ext = path.suffix.lower()

    result: dict[str, Any] = {
        "type": ext.lstrip("."),
        "engine": "unbekannt",
        "arguments": "",
        "context": "machine",
        "confidence": "manuell",
        "admin_requirement": "unbekannt",
        "name_guess": path.stem,
        "creates_path": "",
        "note": "",
        "reasons": [],
        "metadata": {},
    }

    if ext == ".msi":
        result.update(
            type="msi",
            engine="MSI / Windows Installer",
            arguments="",
            context="machine",
            confidence="fest",
            admin_requirement="wahrscheinlich",
            note=(
                "MSI erkannt. Kein Deep-Scan und keine Silent-Parameter-"
                "Raterei. Ansible win_package behandelt MSI direkt."
            ),
        )
        result["reasons"].append("Dateiendung .msi erkannt.")
        return result

    if ext != ".exe":
        result["note"] = (
            "Nur MSI und EXE werden für normale Software unterstützt."
        )
        return result

    result.update(
        type="exe",
        engine="EXE / manuelle Parameter",
        context="machine",
        confidence="manuell",
        note=(
            "Deep-Scan ist deaktiviert. Für unbekannte EXE-Dateien werden "
            "Silent-Parameter ausschließlich manuell eingetragen."
        ),
    )

    if use_known_rules and _apply_known_exe_product_rule(
        path,
        result,
        {},
    ):
        result["reasons"].append(
            "Parameter stammen ausschließlich aus einer festen "
            "Produktregel im Python-Skript."
        )
        return result

    result["reasons"].append(
        "Keine feste Produktregel gefunden. Parameter werden manuell gesetzt."
    )
    return result

__all__ = (
    "SILENT_SWITCH_DEFINITIONS",
    "HELP_CONTEXT_MARKERS",
    "normalize_rule_key",
    "learned_rule_identity",
    "load_installer_rules",
    "save_installer_rules",
    "find_learned_installer_rule",
    "remember_installer_rule",
    "_ascii_readability",
    "_word_quality",
    "_embedded_cli_records_from_binary",
    "_switch_context_is_plausible",
    "_extract_switch_occurrences_from_binary",
    "_extract_switch_occurrences",
    "_dedupe_switch_candidates",
    "infer_silent_arguments_from_binary",
    "infer_silent_arguments_from_strings",
    "print_silent_detection",
    "cmd_rules_list",
    "cmd_rules_remove",
    "PE_VERSION_KEYS",
    "_clean_pe_text",
    "_pe_architecture_from_bytes",
    "_printable_pe_strings",
    "_versioninfo_from_strings",
    "_versioninfo_with_pefile",
    "inspect_pe_metadata",
    "_metadata_blob",
    "_citrix_detection_path",
    "_apply_known_exe_product_rule",
    "analyze_installer",
)
