"""
db.py — schema SQLite și acces la baza de date pentru Inventar AD.

De ce SQLite fără ORM: volumul de date e mic (sute de stații, zeci de rulări pe
lună), iar interogările din paginile web sunt JOIN-uri simple pe câteva tabele;
un ORM ar adăuga un strat de indirecție fără beneficiu real la scara asta.

Toate datele-timp se stochează exact cum vin din colector (text ISO 8601 cu
offset) — fără nicio conversie de fus orar aici sau în restul aplicației.
"""

import json
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = BASE_DIR / "config.json"

# Schema completă, așa cum e descrisă în SPEC_InventarAD.md §6.
# CREATE TABLE/INDEX IF NOT EXISTS ca init_db() să poată fi rulat oricând,
# inclusiv pe o bază deja existentă (criteriul de acceptanță #8: baza poate fi
# ștearsă și reconstruită din NDJSON-urile arhivate în runs\).
SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id                INTEGER PRIMARY KEY,
    started_at        TEXT NOT NULL,
    finished_at       TEXT,
    level             INTEGER NOT NULL,
    ou_base           TEXT NOT NULL,
    host_count        INTEGER DEFAULT 0,
    ok_count          INTEGER DEFAULT 0,
    partial_count     INTEGER DEFAULT 0,
    offline_count     INTEGER DEFAULT 0,
    error_count       INTEGER DEFAULT 0,
    duration_sec      REAL,
    avg_cim_ms        REAL,
    avg_reg_ms        REAL,
    collector_version TEXT,
    ndjson_path       TEXT,
    status            TEXT DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS hosts (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE COLLATE NOCASE,
    dns_name            TEXT,
    distinguished_name  TEXT,
    ou_path             TEXT,
    ad_description      TEXT,
    ad_os               TEXT,
    ad_os_version       TEXT,
    ad_last_logon       TEXT,
    first_seen          TEXT NOT NULL,
    last_seen           TEXT,          -- ultima dată cu status OK/PARTIAL
    last_status         TEXT
);

CREATE TABLE IF NOT EXISTS snapshots (
    id                  INTEGER PRIMARY KEY,
    run_id              INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host_id             INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    collected_at        TEXT NOT NULL,
    level               INTEGER NOT NULL,
    status              TEXT NOT NULL,
    error_message       TEXT,
    duration_cim_ms     INTEGER,
    duration_reg_ms     INTEGER,
    manufacturer        TEXT,
    model               TEXT,
    serial_number       TEXT,
    bios_version        TEXT,
    cpu_name            TEXT,
    ram_total_mb        INTEGER,
    os_caption          TEXT,
    os_build            TEXT,
    os_display_version  TEXT,
    os_arch             TEXT,
    os_install_date     TEXT,
    last_boot           TEXT,
    uptime_days         REAL,
    ip_address          TEXT,
    mac_address          TEXT,
    dhcp_enabled        INTEGER,
    logged_on_user      TEXT,
    last_logged_on_user TEXT,
    logged_on_user_display_name      TEXT,   -- DisplayName din AD pentru logged_on_user (§5.7)
    last_logged_on_user_display_name TEXT,   -- idem, pentru last_logged_on_user
    av_name             TEXT,
    av_enabled          INTEGER,
    av_up_to_date       INTEGER,
    av_signature_date   TEXT,
    reboot_pending      INTEGER,
    wu_last_success     TEXT,
    UNIQUE(run_id, host_id)
);

CREATE TABLE IF NOT EXISTS snapshot_disks (
    id           INTEGER PRIMARY KEY,
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    volume_name  TEXT,
    size_mb      INTEGER,
    free_mb      INTEGER,
    free_pct     REAL
);

CREATE TABLE IF NOT EXISTS snapshot_antivirus (
    id             INTEGER PRIMARY KEY,
    snapshot_id    INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name           TEXT,
    enabled        INTEGER,
    up_to_date     INTEGER,
    signature_date TEXT
);

CREATE TABLE IF NOT EXISTS snapshot_software (
    id           INTEGER PRIMARY KEY,
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT,
    publisher    TEXT,
    install_date TEXT,
    scope        TEXT,              -- 'machine' | 'machine_x86' | 'user'
    user_name    TEXT               -- numele contului, doar când scope = 'user' (§5.5f)
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rule         TEXT NOT NULL,
    severity     TEXT NOT NULL,     -- 'info' | 'warn' | 'crit'
    message      TEXT NOT NULL,
    value        TEXT
);

CREATE INDEX IF NOT EXISTS ix_snap_host ON snapshots(host_id, collected_at DESC);
CREATE INDEX IF NOT EXISTS ix_snap_run  ON snapshots(run_id);
CREATE INDEX IF NOT EXISTS ix_sw_name   ON snapshot_software(name, version);
CREATE INDEX IF NOT EXISTS ix_alerts    ON alerts(run_id, severity);
"""

_config_cache = None


def load_config():
    """Citește config.json o singură dată per proces și îl ține în memorie.

    Cache simplu în modul: aplicația web nu are nevoie să detecteze modificări
    live ale config.json — un restart e suficient pentru un pilot local.
    """
    global _config_cache
    if _config_cache is None:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            _config_cache = json.load(f)
    return _config_cache


def get_db_path() -> Path:
    cfg = load_config()
    db_path = Path(cfg.get("db_path", "inventar.db"))
    if not db_path.is_absolute():
        db_path = BASE_DIR / db_path
    return db_path


def get_connection() -> sqlite3.Connection:
    """Deschide o conexiune nouă cu PRAGMA-urile cerute de spec.

    - foreign_keys=ON: SQLite le dezactivează implicit; fără asta ON DELETE
      CASCADE din schemă n-ar avea niciun efect.
    - journal_mode=WAL: scanarea ingerează incremental (scrie) în timp ce
      interfața web citește în paralel; WAL permite exact asta fără blocaje.
    """
    conn = sqlite3.connect(str(get_db_path()), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


# Coloane adăugate după lansarea inițială a schemei — CREATE TABLE IF NOT EXISTS
# de mai sus nu le adaugă pe o bază deja existentă, așa că se migrează explicit
# aici, o singură dată, verificând întâi dacă lipsesc (PRAGMA table_info).
_MIGRATIONS = [
    ("snapshot_software", "user_name", "TEXT"),
    ("snapshots", "logged_on_user_display_name", "TEXT"),
    ("snapshots", "last_logged_on_user_display_name", "TEXT"),
]


def _migrate_schema(conn) -> None:
    for table, column, coltype in _MIGRATIONS:
        cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
    conn.commit()


def init_db() -> None:
    """Creează schema dacă lipsește. Idempotent — sigur de rulat la fiecare pornire."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
        _migrate_schema(conn)
    finally:
        conn.close()


if __name__ == "__main__":
    import sys

    # Consola Windows nu e mereu UTF-8 (cp1252/cp850 după locale); fără asta
    # print() cu diacritice pică cu UnicodeEncodeError în loc să afișeze text.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    init_db()
    print(f"Bază de date inițializată: {get_db_path()}")
