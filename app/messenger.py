"""
messenger.py — trimite un mesaj pop-up (msg.exe) sesiunilor logate pe o
stație, folosit de POST /statie/<name>/mesaj din webapp.py.

Ca și colectorul, comunicarea cu stația se face exclusiv prin CIM peste DCOM
(fără WinRM, vezi CLAUDE.md) — script-ul PowerShell
collector/Send-StationMessage.ps1 creează un task Scheduler temporar,
interactiv, care rulează msg.exe în sesiunea utilizatorului logat, apoi îl
șterge (necesită drepturi de admin pe stația țintă; vezi excepția explicită
documentată în CLAUDE.md pentru "fără scheduled task").

Spre deosebire de Collect-Inventory.ps1, acțiunea de aici NU e read-only —
constrângerea "strict read-only" din CLAUDE.md privește colectorul automat de
inventariere, nu o acțiune explicită cerută de operator dintr-o pagină web.
"""

import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = BASE_DIR / "collector" / "Send-StationMessage.ps1"


class MessengerError(RuntimeError):
    """Ridicată când script-ul de trimitere a mesajului eșuează."""


def send_message(computer_name: str, message: str, admin_user: str | None = None,
                  admin_pass: str | None = None, timeout_sec: int = 90) -> None:
    # 90s, nu 30s: fluxul prin task Scheduler (creare + rulare + verificare +
    # ștergere) înseamnă multe apeluri CIM secvențiale, fiecare cu propria
    # latență de rețea reală — pe o stație de domeniu reală, suma lor a
    # depășit 30s (confirmat: eroarea de timeout a apărut corect, dar prea
    # devreme, nu era un blocaj real).
    args = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
        "-File", str(SCRIPT_PATH),
        "-ComputerName", computer_name,
        "-Message", message,
    ]
    if admin_user:
        args += ["-AdminUser", admin_user]

    # Parola merge pe stdin, nu ca argument de linie de comandă — la fel ca la
    # scanare (scanner.py), ca să nu rămână vizibilă oricui inspectează
    # procesul (ex. Task Manager).
    stdin_data = (admin_pass + "\n") if (admin_user and admin_pass) else None

    try:
        proc = subprocess.run(
            args, input=stdin_data, capture_output=True, text=True,
            encoding="utf-8", errors="replace", cwd=str(BASE_DIR), timeout=timeout_sec,
        )
    except subprocess.TimeoutExpired:
        raise MessengerError("Trimiterea mesajului a durat prea mult (timeout).")

    # Stdout-ul scriptului nu ajunge altfel nicaieri (nu e in raspunsul catre
    # browser, vezi ruta /statie/<name>/mesaj din webapp.py) - il scoatem in
    # consola unde ruleaza aplicatia, utila pentru diagnostic ulterior.
    if proc.stdout:
        print("[mesaj]", proc.stdout.strip(), flush=True)

    if proc.returncode != 0:
        raise MessengerError(proc.stderr.strip() or "Script-ul de trimitere a mesajului a eșuat.")
