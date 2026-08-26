"""
scanner.py — pornește Collect-Inventory.ps1 ca subproces și ingerează NDJSON-ul
pe măsură ce sosește pe stdout, astfel încât rezultatele apar în interfață în
timp real, nu abia la finalul scanării.

O singură scanare poate rula simultan (§8): starea partajată e protejată de un
lock; webapp.py verifică Scanner.is_running() înainte de a porni una nouă și
întoarce 409 dacă una e deja activă.
"""

import json
import re
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import alerts  # noqa: E402
import db  # noqa: E402
import ingest  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
COLLECTOR_PATH = BASE_DIR / "collector" / "Collect-Inventory.ps1"
RUNS_DIR = BASE_DIR / "runs"
LOGS_DIR = BASE_DIR / "logs"

# Ținută manual în pas cu $CollectorVersion din Collect-Inventory.ps1 — colectorul
# nu expune un flag -Version (nu face parte din semnătura §5.1), deci nu-l putem
# citi dinamic fără să lansăm un proces suplimentar doar pentru atât.
COLLECTOR_VERSION = "1.0"

_PROGRESS_RE = re.compile(r"^PROGRESS (\d+)/(\d+) (.*)$")


class ScanAlreadyRunningError(RuntimeError):
    """Ridicată când se cere pornirea unei scanări cât timp alta rulează deja."""


def _prune_old_runs(conn, keep: int) -> None:
    """Păstrează doar cele mai recente `keep_runs` rulări (config.json §4) —
    șterge rândurile mai vechi din DB (CASCADE ia snapshots/alerts) și
    arhivele NDJSON/meta/log asociate, ca runs\\ și logs\\ să nu crească
    nelimitat pe durata pilotului de 2-3 săptămâni."""
    if keep is None or keep <= 0:
        return
    old_runs = conn.execute(
        "SELECT id, ndjson_path FROM runs ORDER BY started_at DESC LIMIT -1 OFFSET ?",
        (keep,),
    ).fetchall()
    for row in old_runs:
        conn.execute("DELETE FROM runs WHERE id = ?", (row["id"],))
        if row["ndjson_path"]:
            ndjson_path = Path(row["ndjson_path"])
            meta_path = ndjson_path.with_suffix("").with_suffix(".meta.json")
            for p in (ndjson_path, meta_path):
                try:
                    p.unlink(missing_ok=True)
                except OSError:
                    pass
        for log_file in LOGS_DIR.glob(f"run-{row['id']}-*.log"):
            try:
                log_file.unlink()
            except OSError:
                pass
    conn.commit()


class Scanner:
    def __init__(self):
        self._lock = threading.Lock()
        self._process = None
        self._thread = None
        self._stop_requested = False
        self._state = self._idle_state()

    @staticmethod
    def _idle_state():
        return {
            "running": False,
            "done": 0,
            "total": 0,
            "current_host": None,
            "elapsed_sec": 0,
            "run_id": None,
            "_start_time": None,
        }

    def is_running(self) -> bool:
        with self._lock:
            return self._state["running"]

    def get_status(self) -> dict:
        """Format JSON pentru polling (§8): running, done, total, current_host,
        elapsed_sec, run_id."""
        with self._lock:
            state = dict(self._state)
        start_time = state.pop("_start_time", None)
        if state["running"] and start_time:
            state["elapsed_sec"] = round(time.time() - start_time, 1)
        return state

    def start(self, level: int, ou_base: str | None = None) -> int:
        """Pornește o scanare nouă într-un fir separat. Ridică
        ScanAlreadyRunningError dacă una e deja în curs — webapp.py o traduce
        în răspuns HTTP 409."""
        with self._lock:
            if self._state["running"]:
                raise ScanAlreadyRunningError("O scanare este deja în curs.")
            self._stop_requested = False
            self._state = self._idle_state()
            self._state["running"] = True
            self._state["_start_time"] = time.time()

        cfg = db.load_config()
        effective_ou = ou_base or "auto (OU curent)"
        started_at = ingest.now_iso()

        conn = db.get_connection()
        try:
            run_id = ingest.create_run(
                conn, level, effective_ou,
                started_at=started_at,
                collector_version=COLLECTOR_VERSION,
            )
        finally:
            conn.close()

        with self._lock:
            self._state["run_id"] = run_id

        self._thread = threading.Thread(
            target=self._run, args=(run_id, level, ou_base, effective_ou, started_at, cfg),
            daemon=True,
        )
        self._thread.start()
        return run_id

    def stop(self) -> bool:
        """Termină procesul curent; rularea va fi marcată 'interrupted' de
        firul de scanare, o dată ce Popen.wait() se întoarce."""
        with self._lock:
            proc = self._process
            running = self._state["running"]
            if running:
                self._stop_requested = True
        if not running or proc is None:
            return False
        try:
            proc.terminate()
        except OSError:
            pass
        return True

    def _read_stderr(self, proc, collected_lines: list):
        """Fir separat: citește stderr linie cu linie, extrage liniile
        PROGRESS pentru actualizarea stării live, păstrează tot restul pentru
        arhivarea integrală în logs\\ (cerută explicit de §8)."""
        for line in proc.stderr:
            line = line.rstrip("\n")
            collected_lines.append(line)
            m = _PROGRESS_RE.match(line)
            if m:
                done, total, hostname = int(m.group(1)), int(m.group(2)), m.group(3)
                with self._lock:
                    self._state["done"] = done
                    self._state["total"] = total
                    self._state["current_host"] = hostname
        proc.stderr.close()

    def _run(self, run_id, level, ou_base, effective_ou, started_at, cfg):
        timestamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        ndjson_path = RUNS_DIR / f"run-{run_id}-{timestamp}.ndjson"
        meta_path = ndjson_path.with_suffix("").with_suffix(".meta.json")
        log_path = LOGS_DIR / f"run-{run_id}-{timestamp}.log"

        # Sidecar cu metadatele rulării — folosit de ingest.rebuild_from_runs()
        # ca să reconstruiască runs.level/ou_base fără să fi păstrat starea în DB.
        meta_path.write_text(
            json.dumps({
                "run_id": run_id, "started_at": started_at, "level": level,
                "ou_base": effective_ou, "collector_version": COLLECTOR_VERSION,
            }, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

        conn = db.get_connection()
        conn.execute("UPDATE runs SET ndjson_path = ? WHERE id = ?", (str(ndjson_path), run_id))
        conn.commit()

        args = [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", str(COLLECTOR_PATH),
            "-Level", str(level),
            "-Throughput", str(cfg.get("throughput", 12)),
            "-TcpProbeTimeoutMs", str(cfg.get("tcp_probe_timeout_ms", 400)),
            "-CimTimeoutSec", str(cfg.get("cim_timeout_sec", 45)),
            "-RegTimeoutSec", str(cfg.get("reg_timeout_sec", 60)),
        ]
        if ou_base:
            args += ["-OuBase", ou_base]

        stderr_lines: list = []
        run_status = "completed"
        try:
            proc = subprocess.Popen(
                args,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", errors="replace", bufsize=1,
                cwd=str(BASE_DIR),
            )
            with self._lock:
                self._process = proc

            stderr_thread = threading.Thread(
                target=self._read_stderr, args=(proc, stderr_lines), daemon=True
            )
            stderr_thread.start()

            # Ingestie incrementală: fiecare linie NDJSON e arhivată ȘI scrisă
            # în SQLite imediat ce sosește — de-asta rezultatele apar live.
            with open(ndjson_path, "w", encoding="utf-8") as archive:
                for line in proc.stdout:
                    line = line.rstrip("\n")
                    if not line.strip():
                        continue
                    archive.write(line + "\n")
                    try:
                        ingest.ingest_line(conn, run_id, line)
                    except (json.JSONDecodeError, ValueError) as exc:
                        stderr_lines.append(f"[ingest] linie NDJSON ignorată: {exc}")

            proc.stdout.close()
            proc.wait()
            stderr_thread.join(timeout=5)

            with self._lock:
                was_stopped = self._stop_requested
            run_status = "interrupted" if was_stopped else "completed"
        except Exception as exc:
            stderr_lines.append(f"[scanner] eroare neașteptată: {exc}")
            run_status = "interrupted"
        finally:
            try:
                log_path.write_text("\n".join(stderr_lines), encoding="utf-8")
            except OSError:
                pass

            ingest.finalize_run(conn, run_id, run_status=run_status)
            try:
                alerts.evaluate_run(conn, run_id)
            except Exception as exc:
                with open(log_path, "a", encoding="utf-8") as f:
                    f.write(f"\n[alerts] eroare la evaluarea regulilor: {exc}\n")
            _prune_old_runs(conn, cfg.get("keep_runs", 60))
            conn.close()

            with self._lock:
                self._process = None
                self._stop_requested = False
                self._state["running"] = False


# Instanță unică, importată de webapp.py — o singură scanare are sens pentru
# un pilot local, un singur utilizator (§8).
scanner = Scanner()
