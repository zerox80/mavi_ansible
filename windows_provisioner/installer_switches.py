# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Silent-Switch-Analyse.

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
    from .installer_analysis import (
        HELP_CONTEXT_MARKERS,
        _ascii_readability,
    )

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
    from .installer_analysis import (
        _clean_pe_text,
        _printable_pe_strings,
        _word_quality,
    )

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
    from .installer_analysis import (
        HELP_CONTEXT_MARKERS,
        SILENT_SWITCH_DEFINITIONS,
        _embedded_cli_records_from_binary,
        _switch_context_is_plausible,
    )

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
    from .installer_analysis import (
        HELP_CONTEXT_MARKERS,
        SILENT_SWITCH_DEFINITIONS,
    )

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
    from .installer_analysis import (
        _dedupe_switch_candidates,
        _extract_switch_occurrences_from_binary,
    )

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
    from .installer_analysis import (
        _dedupe_switch_candidates,
        _extract_switch_occurrences,
    )

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
