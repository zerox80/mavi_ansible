# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rujbin N.
"""Ansible-Prozess- und Liveausführung.

Interne Implementierung; der stabile Importpfad liegt in der zugehörigen Fassade.
"""

from __future__ import annotations

from ._dependencies import (
    Any,
    Path,
    argparse,
    base64,
    json,
    os,
    queue,
    re,
    subprocess,
    sys,
    tempfile,
    threading,
    time,
    yaml,
)



def shlex_quote(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9_./:=,@+-]+", value):
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def run_subprocess(
    cmd: list[str],
    cwd: Path,
    *,
    env: dict[str, str] | None = None,
) -> int:
    from .execution import (
        shlex_quote,
    )

    from .environment import die
    from .reports import redact_sensitive_text

    shown_command = " ".join(shlex_quote(x) for x in cmd)
    print("\n→ " + redact_sensitive_text(shown_command))
    print()
    try:
        return subprocess.call(cmd, cwd=str(cwd), env=env)
    except FileNotFoundError:
        die(f"Befehl nicht gefunden: {cmd[0]}")
    return 1



ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(value: str) -> str:
    from .execution import (
        ANSI_ESCAPE_RE,
    )

    return ANSI_ESCAPE_RE.sub("", value)


def format_elapsed(seconds: float) -> str:
    seconds_i = max(0, int(seconds))
    minutes, seconds_i = divmod(seconds_i, 60)
    hours, minutes = divmod(minutes, 60)

    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds_i:02d}"

    return f"{minutes:02d}:{seconds_i:02d}"


def is_live_install_task(task_name: str) -> bool:
    """
    Nur Aufgaben markieren, bei denen der eigentliche Installer läuft.
    Kopieren, Prüfen, Diagnose usw. erzeugen keinen Heartbeat.
    """
    markers = (
        " | Systemweit installieren",
        " | Als SYSTEM installieren",
        " | Detached systemweit installieren",
        " | Interaktiv über Task Scheduler installieren",
        " | Microsoft Office / Project / Visio per ODT installieren",
        " | ODT-Task auf Abschluss warten",
        " | WinGet MACHINE installieren",
        " | WinGet USER über angemeldeten Benutzer installieren",
    )
    return any(marker in task_name for marker in markers)


def task_software_key(task_name: str) -> str:
    if " | " not in task_name:
        return ""
    return task_name.split(" | ", 1)[0].strip()


def print_live_install_status(
    *,
    host: str,
    task_name: str,
    task_started: float,
    last_output: float,
    apps: dict[str, dict[str, Any]],
) -> None:
    from .execution import (
        format_elapsed,
        task_software_key,
    )

    from .reports import redact_sensitive_text

    key = task_software_key(task_name)
    app = apps.get(key, {}) if key else {}

    now = time.monotonic()
    elapsed = format_elapsed(now - task_started)
    silent_for = max(0, int(now - last_output))

    name = str(app.get("name") or key or "unbekannt")
    context = str(app.get("context") or "machine")
    installer = (
        f"WinGet:{app.get('winget_id')}"
        if str(app.get("type") or "").lower() == "winget"
        else (Path(str(app.get("installer") or "")).name or "(unbekannt)")
    )

    arguments = app.get("arguments")
    if arguments in (None, ""):
        arguments_text = "(KEINE)"
    else:
        arguments_text = redact_sensitive_text(arguments)

    print()
    print(
        f"[Mavi LIVE {elapsed}] Installer läuft noch, "
        "Ansible wartet auf Rückmeldung."
    )
    print(f"  Host:       {host}")
    print(f"  Programm:   {name}")
    print(f"  Task:       {task_name}")
    print(f"  Kontext:    {context}")
    print(f"  Installer:  {installer}")
    print(f"  Parameter:  {arguments_text}")
    print(
        f"  Letzte Ansible-Ausgabe: vor {silent_for}s"
    )
    print(
        "  Hinweis: Der Prozess wurde NICHT abgebrochen. "
        "Das ist nur die Live-Statusanzeige."
    )
    print(flush=True)



def print_general_wait_status(
    *,
    host: str,
    current_task: str,
    task_started: float,
    last_output: float,
    apps: dict[str, dict[str, Any]],
) -> None:
    """
    Heartbeat auch dann, wenn Ansible noch keine neue TASK-Zeile geliefert
    hat. Das ist wichtig, wenn die Ausgabe selbst puffert oder ein Modul
    zwischen zwei sichtbaren Tasks hängt.
    """
    from .execution import (
        format_elapsed,
        task_software_key,
    )

    from .reports import redact_sensitive_text

    now = time.monotonic()
    elapsed = format_elapsed(now - task_started)
    silent_for = max(0, int(now - last_output))

    key = task_software_key(current_task)
    app = apps.get(key, {}) if key else {}

    name = str(app.get("name") or key or "unbekannt")
    context = str(app.get("context") or "machine")
    installer = (
        f"WinGet:{app.get('winget_id')}"
        if str(app.get("type") or "").lower() == "winget"
        else (Path(str(app.get("installer") or "")).name or "(unbekannt)")
    )
    arguments = app.get("arguments")

    if arguments in (None, ""):
        arguments_text = "(KEINE)"
    else:
        arguments_text = redact_sensitive_text(arguments)

    print()
    print(
        f"[Mavi LIVE {elapsed}] Ansible läuft noch, "
        "aber liefert gerade keine neue Ausgabe."
    )
    print(f"  Host:       {host}")
    print(f"  Programm:   {name}")
    print(f"  Letzter sichtbarer Task: {current_task or '(noch keiner)'}")
    print(f"  Kontext:    {context}")
    print(f"  Installer:  {installer}")
    print(f"  Parameter:  {arguments_text}")
    print(f"  Keine neue Ansible-Ausgabe seit: {silent_for}s")
    print(
        "  Der Provisioner läuft weiter. Das ist KEIN Fehler und "
        "es wurde nichts abgebrochen."
    )
    print(flush=True)


def _stdout_reader(
    stream: Any,
    output_queue: "queue.Queue[str | None]",
) -> None:
    """
    Eigener Reader-Thread statt selectors + TextIOWrapper.

    Grund: TextIOWrapper kann mehrere Zeilen intern puffern. selectors sieht
    dann am OS-Handle keine neuen Bytes mehr, obwohl Python noch komplette
    Zeilen im eigenen Buffer hat. Genau dadurch konnte v0.8.4 nach einem
    'skipping:' scheinbar einfrieren.
    """
    try:
        for line in iter(stream.readline, ""):
            output_queue.put(line)
    finally:
        output_queue.put(None)



def create_temporary_vault_password_file(password: str) -> Path:
    """
    Einmal eingegebenes Vault-Passwort für Hauptlauf und parallele
    Live-Probes verwenden. Datei ist 0600 und wird nach dem Lauf gelöscht.
    """
    fd, raw_path = tempfile.mkstemp(
        prefix=".mavi-vault-",
        suffix=".txt",
    )

    path = Path(raw_path)

    try:
        os.fchmod(fd, 0o600)

        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(password)
            handle.write("\n")

    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass

        path.unlink(missing_ok=True)
        raise

    return path


def redact_live_text(value: Any) -> str:
    """Kompatibilitätsname für die zentrale Secret-Schwärzung."""
    from .reports import redact_sensitive_text

    return redact_sensitive_text(value)


def _probe_process_map(
    probe: dict[str, Any] | None,
) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}

    for item in (probe or {}).get("Processes", []) or []:
        try:
            pid = int(item.get("Pid"))
        except (TypeError, ValueError):
            continue

        result[pid] = item

    return result


def print_remote_live_probe(
    probe: dict[str, Any],
    previous_probe: dict[str, Any] | None = None,
) -> None:
    """
    Kompakte Remote-Sicht auf den tatsächlich laufenden Installer.
    """
    from .execution import (
        _probe_process_map,
        format_elapsed,
        redact_live_text,
    )

    from .reports import redact_sensitive_text

    processes = probe.get("Processes", []) or []
    current_map = _probe_process_map(probe)
    previous_map = _probe_process_map(previous_probe)

    current_pids = set(current_map)
    previous_pids = set(previous_map)

    new_pids = sorted(current_pids - previous_pids)
    gone_pids = sorted(previous_pids - current_pids)

    current_cpu = sum(
        float(item.get("CpuSeconds") or 0)
        for item in current_map.values()
    )
    previous_cpu = sum(
        float(item.get("CpuSeconds") or 0)
        for item in previous_map.values()
    )

    cpu_delta = (
        current_cpu - previous_cpu
        if previous_probe is not None
        else None
    )

    print()
    print("[Mavi REMOTE LIVE] Zustand auf dem Windows-PC")
    print(
        "  Ziel-Installer läuft: "
        + ("JA" if probe.get("TargetRunning") else "NEIN")
    )
    print(
        "  Pending Reboot:       "
        + ("JA" if probe.get("PendingReboot") else "NEIN")
    )
    print(f"  Relevante Prozesse:    {len(processes)}")

    if previous_probe is not None:
        activity: list[str] = []

        if cpu_delta is not None and cpu_delta > 0.05:
            activity.append(f"CPU +{cpu_delta:.2f}s")

        if new_pids:
            activity.append(
                "neue PID(s) " + ",".join(map(str, new_pids))
            )

        if gone_pids:
            activity.append(
                "beendete PID(s) " + ",".join(map(str, gone_pids))
            )

        if activity:
            print("  Aktivität seit Probe:  " + " | ".join(activity))
        else:
            print(
                "  Aktivität seit Probe:  "
                "keine sichtbare CPU-/Prozessänderung "
                "(nicht automatisch ein Fehler)"
            )

    if processes:
        print()
        print("  PROZESSE:")

        for item in processes[:12]:
            role = str(item.get("Role") or "RELATED")
            pid = item.get("Pid", "?")
            ppid = item.get("ParentPid", "?")
            name = str(item.get("Name") or "?")
            cpu = item.get("CpuSeconds")
            ram = item.get("WorkingSetMB")
            uptime = item.get("UptimeSeconds")

            cpu_text = "?" if cpu is None else f"{float(cpu):.2f}s"
            ram_text = "?" if ram is None else f"{float(ram):.1f} MB"

            if uptime is None:
                uptime_text = "?"
            else:
                uptime_text = format_elapsed(float(uptime))

            print(
                f"    [{role:<7}] PID={pid} PPID={ppid} "
                f"{name} | Laufzeit={uptime_text} "
                f"| CPU={cpu_text} | RAM={ram_text}"
            )

            command_line = redact_live_text(
                item.get("CommandLine")
            ).strip()

            if command_line:
                if len(command_line) > 220:
                    command_line = command_line[:220] + "..."

                print(f"              CMD: {command_line}")

    logs = probe.get("Logs", []) or []

    if logs:
        print()
        print("  AKTUELLE INSTALLER-LOGS:")

        for item in logs[:8]:
            print(
                f"    {item.get('LastWriteTime', '?')} | "
                f"{item.get('SizeKB', '?')} KB | "
                f"{item.get('Path', '?')}"
            )

    events = probe.get("MsiEvents", []) or []

    if events:
        print()
        print("  LETZTE MSI-EVENTS:")

        for item in events[:5]:
            message = redact_sensitive_text(item.get("Message"))
            if len(message) > 260:
                message = message[:260] + "..."

            print(
                f"    {item.get('Time', '?')} | "
                f"ID={item.get('Id', '?')} | {message}"
            )

    print()


def _bound_ansible_session_context(
    *,
    host: str,
    ansible_session: dict[str, Any],
) -> tuple[Path, Path, Path, dict[str, str], dict[str, Any]]:
    """Prozesskontext einer bereits geöffneten Ansible-Sitzung validieren."""
    if str(ansible_session.get("host") or "") != host:
        raise RuntimeError("Die Ansible-Sitzung gehört zu einem anderen PC.")

    ansible_executable = ansible_session.get("ansible_executable")
    ansible_python = ansible_session.get("ansible_python")
    inventory_path = ansible_session.get("inventory_path")
    if not all(isinstance(value, Path) for value in (
        ansible_executable,
        ansible_python,
        inventory_path,
    )):
        raise RuntimeError("Die Ansible-Sitzung ist unvollständig.")

    raw_environment = ansible_session.get("environment")
    raw_extra_vars = ansible_session.get("extra_vars")
    if not isinstance(raw_environment, dict) or not isinstance(raw_extra_vars, dict):
        raise RuntimeError("Der Prozesskontext der Ansible-Sitzung ist ungültig.")

    environment = {
        str(key): str(value)
        for key, value in raw_environment.items()
    }
    return (
        ansible_executable,
        ansible_python,
        inventory_path,
        environment,
        dict(raw_extra_vars),
    )


def run_remote_live_probe(
    *,
    project: Path,
    host: str,
    app: dict[str, Any],
    vault_password_file: Path,
    ansible_session: dict[str, Any],
    timeout: float = 12.0,
) -> tuple[dict[str, Any] | None, str | None]:
    """
    Zweite kurze Ansible-Verbindung während der Hauptinstallation.
    Keine Änderung auf dem Ziel-PC, nur Prozess-/Log-/Reboot-Abfrage.
    """
    from .execution import (
        _bound_ansible_session_context,
    )

    from .environment import project_paths
    from .reports import redact_sensitive_text

    probe_playbook = project_paths(project)["live_probe_playbook"]

    if not probe_playbook.exists():
        return None, f"Probe-Playbook fehlt: {probe_playbook}"

    if str(app.get("type") or "").lower() == "winget":
        installer_name = "winget.exe"
        remote_installer = ""
    else:
        installer_name = Path(
            str(app.get("installer") or "")
        ).name
        remote_installer = (
            "C:\\Mavi-Provisioner\\Installers\\"
            + installer_name
        )

    fd, raw_output = tempfile.mkstemp(
        prefix=".mavi-live-probe-",
        suffix=".json",
    )
    os.close(fd)

    output_path = Path(raw_output)

    try:
        output_path.unlink(missing_ok=True)

        (
            ansible_executable,
            ansible_python,
            inventory_path,
            runtime_environment,
            transport_vars,
        ) = _bound_ansible_session_context(
            host=host,
            ansible_session=ansible_session,
        )

        extra = {
            "mavi_probe_installer_path": remote_installer,
            "mavi_probe_installer_name": installer_name,
            "mavi_probe_software_name": str(
                app.get("name") or ""
            ),
            "mavi_probe_output_file": str(output_path),
        }
        extra.update(transport_vars)

        cmd = [
            str(ansible_python),
            "-I",
            str(ansible_executable),
            "-i",
            str(inventory_path),
            str(probe_playbook),
            "--limit",
            host,
            "--vault-password-file",
            str(vault_password_file),
            "-e",
            json.dumps(extra, ensure_ascii=False),
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=timeout,
                env=runtime_environment,
            )
        except subprocess.TimeoutExpired:
            return (
                None,
                f"Remote-Probe nach {timeout:g}s ohne Antwort "
                "abgebrochen. Hauptinstallation läuft weiter.",
            )

        if result.returncode != 0:
            combined = (
                (result.stdout or "")
                + "\n"
                + (result.stderr or "")
            ).strip()

            lines = [
                line.strip()
                for line in combined.splitlines()
                if line.strip()
            ]

            detail = redact_sensitive_text(" | ".join(lines[-4:]))

            if len(detail) > 700:
                detail = detail[-700:]

            return (
                None,
                "Remote-Probe fehlgeschlagen"
                + (f": {detail}" if detail else "."),
            )

        if not output_path.exists():
            return None, "Remote-Probe lieferte keine Ergebnisdatei."

        payload = output_path.read_text(
            encoding="utf-8"
        ).strip()

        if not payload:
            return None, "Remote-Probe lieferte ein leeres Ergebnis."

        parsed = json.loads(payload)

        if not isinstance(parsed, dict):
            return None, "Remote-Probe lieferte unerwartete Daten."

        return parsed, None

    except (OSError, json.JSONDecodeError) as exc:
        return None, f"Remote-Probe konnte nicht ausgewertet werden: {exc}"

    finally:
        output_path.unlink(missing_ok=True)


def run_install_subprocess(
    cmd: list[str],
    cwd: Path,
    *,
    host: str,
    apps: dict[str, dict[str, Any]],
    ansible_session: dict[str, Any],
    status_interval: float = 10.0,
    vault_password_file: Path | None = None,
    live_probe: bool = True,
) -> int:
    """
    Ansible-Ausgabe live durchreichen.

    v0.8.5 benutzt einen Reader-Thread + Queue, damit keine bereits von
    Python gepufferten Ansible-Zeilen verloren/unsichtbar bleiben.

    Zusätzlich:
    - bei echtem Installer-Task: detaillierter Installer-Heartbeat
    - bei sonstiger Ansible-Stille: allgemeiner Heartbeat
    - KEIN automatischer Abbruch
    - KEINE manuellen Befehle auf dem Ziel-PC
    """
    from .execution import (
        _bound_ansible_session_context,
        _stdout_reader,
        is_live_install_task,
        print_general_wait_status,
        print_live_install_status,
        print_remote_live_probe,
        run_remote_live_probe,
        shlex_quote,
        strip_ansi,
        task_software_key,
    )

    from .environment import die
    from .reports import redact_sensitive_text

    shown_command = " ".join(shlex_quote(x) for x in cmd)
    print("\n→ " + redact_sensitive_text(shown_command))
    print()

    _, _, _, env, _ = _bound_ansible_session_context(
        host=host,
        ansible_session=ansible_session,
    )
    # Hilft Python-basierten Child-Prozessen, Ausgaben zeitnah zu flushen.
    env["PYTHONUNBUFFERED"] = "1"

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdin=None,  # Terminal geerbt, --ask-vault-pass bleibt nutzbar.
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
    except FileNotFoundError:
        die(f"Befehl nicht gefunden: {cmd[0]}")
        return 1

    assert proc.stdout is not None

    output_queue: "queue.Queue[str | None]" = queue.Queue()

    reader = threading.Thread(
        target=_stdout_reader,
        args=(proc.stdout, output_queue),
        name="mavi-ansible-output-reader",
        daemon=True,
    )
    reader.start()

    current_task = ""
    task_started = time.monotonic()
    last_output = time.monotonic()
    last_status = time.monotonic()
    stream_closed = False
    previous_probe: dict[str, Any] | None = None
    previous_probe_task = ""

    try:
        while True:
            try:
                item = output_queue.get(timeout=0.25)
            except queue.Empty:
                item = "__Mavi_NO_LINE__"

            if item is None:
                stream_closed = True

            elif item != "__Mavi_NO_LINE__":
                line = item
                print(redact_sensitive_text(line), end="", flush=True)

                now = time.monotonic()
                last_output = now

                clean = strip_ansi(line).strip()
                match = re.match(r"^TASK \[(.+)\]", clean)

                if match:
                    new_task = match.group(1).strip()

                    if new_task != current_task:
                        previous_probe = None
                        previous_probe_task = ""

                    current_task = new_task
                    task_started = now
                    last_status = now

            return_code = proc.poll()

            if return_code is not None and stream_closed and output_queue.empty():
                return return_code

            now = time.monotonic()

            if (
                status_interval > 0
                and now - last_status >= status_interval
                and proc.poll() is None
            ):
                if is_live_install_task(current_task):
                    print_live_install_status(
                        host=host,
                        task_name=current_task,
                        task_started=task_started,
                        last_output=last_output,
                        apps=apps,
                    )

                    key = task_software_key(current_task)
                    app = apps.get(key, {}) if key else {}

                    if (
                        live_probe
                        and vault_password_file is not None
                        and app
                    ):
                        probe, probe_error = run_remote_live_probe(
                            project=cwd,
                            host=host,
                            app=app,
                            vault_password_file=vault_password_file,
                            ansible_session=ansible_session,
                        )

                        if probe is not None:
                            print_remote_live_probe(
                                probe,
                                previous_probe=(
                                    previous_probe
                                    if previous_probe_task == current_task
                                    else None
                                ),
                            )
                            previous_probe = probe
                            previous_probe_task = current_task

                        elif probe_error:
                            print()
                            print("[Mavi REMOTE LIVE] Detailprobe nicht verfügbar:")
                            print(f"  {probe_error}")
                            print(
                                "  Hauptinstallation läuft unverändert weiter."
                            )
                            print()
                else:
                    print_general_wait_status(
                        host=host,
                        current_task=current_task,
                        task_started=task_started,
                        last_output=last_output,
                        apps=apps,
                    )

                last_status = time.monotonic()

    except KeyboardInterrupt:
        print()
        print(
            "Abbruch angefordert. Ansible-Prozess wird beendet. "
            "Ein bereits gestarteter Windows-Installer kann auf dem "
            "Ziel-PC noch weiterlaufen."
        )
        proc.terminate()

        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

        return 130

    finally:
        try:
            proc.stdout.close()
        except Exception:
            pass
