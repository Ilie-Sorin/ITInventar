"""
ingest.py — transformă fluxul NDJSON produs de Collect-Inventory.ps1 în rânduri SQLite.

Fiecare linie NDJSON descrie o stație la un moment dat (§5.7 din spec). O linie
poate fi ingerată izolat, ceea ce permite atât ingestia incrementală în timpul
unei scanări live (scanner.py citește stdout linie cu linie), cât și
re-ingestia unui fișier arhivat din runs/ fără să mai fie nevoie de o scanare
nouă — util când se schimbă schema sau când baza de date trebuie reconstruită
(criteriul de acceptanță #8).
"""

import json
import re
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import db  # noqa: E402  (import local, după ajustarea sys.path pentru rulare ca script)

BASE_DIR = Path(__file__).resolve().parent.parent
RUNS_DIR = BASE_DIR / "runs"

# Statusurile care înseamnă „stația a răspuns și a produs date" — folosite ca
# să decidem dacă actualizăm hosts.last_seen. OFFLINE/RPC_DENIED/TIMEOUT/
# WMI_ERROR nu avansează last_seen: nu vrem să pară "văzută" o stație la care
# de fapt colectorul n-a ajuns.
STATUSES_SEEN = ("OK", "PARTIAL")

# Statusurile tratate drept eșec de colectare propriu-zis (folosite de
# runs.error_count și de regula de alertă collect_failed). OFFLINE e ținut
# separat pentru că nu e o eroare a colectorului, ci starea stației.
STATUSES_ERROR = ("RPC_DENIED", "TIMEOUT", "WMI_ERROR")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Cicluri de viață pentru o rulare (runs)
# ---------------------------------------------------------------------------

def create_run(conn, level, ou_base, started_at=None, collector_version=None,
                ndjson_path=None, run_id=None):
    """Deschide o nouă rulare. Dacă run_id e dat explicit (folosit la rebuild,
    ca id-ul din numele fișierului arhivat să rămână stabil), se inserează cu
    acel id — SQLite permite valori explicite pe o coloană INTEGER PRIMARY KEY.
    """
    if started_at is None:
        started_at = now_iso()
    if run_id is not None:
        conn.execute(
            """
            INSERT INTO runs (id, started_at, level, ou_base, collector_version,
                               ndjson_path, status)
            VALUES (?, ?, ?, ?, ?, ?, 'running')
            """,
            (run_id, started_at, level, ou_base, collector_version, ndjson_path),
        )
    else:
        cur = conn.execute(
            """
            INSERT INTO runs (started_at, level, ou_base, collector_version,
                               ndjson_path, status)
            VALUES (?, ?, ?, ?, ?, 'running')
            """,
            (started_at, level, ou_base, collector_version, ndjson_path),
        )
        run_id = cur.lastrowid
    conn.commit()
    return run_id


def finalize_run(conn, run_id, finished_at=None, run_status="completed"):
    """Recalculează contoarele și mediile unei rulări din snapshots (sursa de
    adevăr), în loc să le acumulăm manual pe măsură ce vin liniile — mai
    robust la re-ingestie și la reluarea unei rulări întrerupte.
    """
    if finished_at is None:
        finished_at = now_iso()

    row = conn.execute(
        """
        SELECT
            COUNT(*) AS host_count,
            SUM(CASE WHEN status = 'OK' THEN 1 ELSE 0 END) AS ok_count,
            SUM(CASE WHEN status = 'PARTIAL' THEN 1 ELSE 0 END) AS partial_count,
            SUM(CASE WHEN status = 'OFFLINE' THEN 1 ELSE 0 END) AS offline_count,
            SUM(CASE WHEN status IN ('RPC_DENIED','TIMEOUT','WMI_ERROR') THEN 1 ELSE 0 END) AS error_count,
            AVG(duration_cim_ms) AS avg_cim_ms,
            AVG(duration_reg_ms) AS avg_reg_ms
        FROM snapshots WHERE run_id = ?
        """,
        (run_id,),
    ).fetchone()

    started_at = conn.execute(
        "SELECT started_at FROM runs WHERE id = ?", (run_id,)
    ).fetchone()["started_at"]
    duration_sec = None
    try:
        t0 = datetime.fromisoformat(started_at)
        t1 = datetime.fromisoformat(finished_at)
        duration_sec = (t1 - t0).total_seconds()
    except (TypeError, ValueError):
        pass  # timestamp lipsă/malformat — lăsăm duration_sec necunoscut, nu blocăm finalizarea

    conn.execute(
        """
        UPDATE runs SET
            finished_at = ?, host_count = ?, ok_count = ?, partial_count = ?,
            offline_count = ?, error_count = ?, avg_cim_ms = ?, avg_reg_ms = ?,
            duration_sec = ?, status = ?
        WHERE id = ?
        """,
        (
            finished_at,
            row["host_count"] or 0,
            row["ok_count"] or 0,
            row["partial_count"] or 0,
            row["offline_count"] or 0,
            row["error_count"] or 0,
            row["avg_cim_ms"],
            row["avg_reg_ms"],
            duration_sec,
            run_status,
            run_id,
        ),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Ingestia unei singure stații
# ---------------------------------------------------------------------------

def ingest_record(conn, run_id, record) -> int:
    """Ingerează o singură înregistrare (o stație) într-o singură tranzacție,
    așa cum cere §6. Face upsert pe hosts.name (COLLATE NOCASE definit în
    schemă), apoi upsert pe snapshots(run_id, host_id), apoi înlocuiește
    disk-urile și software-ul snapshot-ului curent.

    Returnează host_id, util apelantului (ex. scanner.py) pentru progres.
    """
    ad = record.get("ad") or {}
    system = record.get("system") or {}
    osinfo = record.get("os") or {}
    network = record.get("network") or {}
    antivirus = record.get("antivirus") or {}
    registry = record.get("registry")  # None la Nivel 1 — intenționat, vezi §5.7
    disks = record.get("disks") or []

    name = ad.get("name")
    if not name:
        raise ValueError("Înregistrare NDJSON fără ad.name — nu poate fi asociată unei stații")

    status = record.get("status")
    collected_at = record.get("collected_at")
    seen_now = collected_at if status in STATUSES_SEEN else None

    try:
        conn.execute(
            """
            INSERT INTO hosts (name, dns_name, distinguished_name, ou_path, ad_description,
                                ad_os, ad_os_version, ad_last_logon, first_seen, last_seen, last_status)
            VALUES (:name, :dns_name, :dn, :ou_path, :descr, :ad_os, :ad_os_version,
                    :ad_last_logon, :first_seen, :last_seen, :status)
            ON CONFLICT(name) DO UPDATE SET
                dns_name           = excluded.dns_name,
                distinguished_name = excluded.distinguished_name,
                ou_path             = excluded.ou_path,
                ad_description      = excluded.ad_description,
                ad_os               = excluded.ad_os,
                ad_os_version       = excluded.ad_os_version,
                ad_last_logon       = excluded.ad_last_logon,
                last_seen           = COALESCE(excluded.last_seen, hosts.last_seen),
                last_status         = excluded.last_status
            """,
            {
                "name": name,
                "dns_name": ad.get("dns_name"),
                "dn": ad.get("distinguished_name"),
                "ou_path": ad.get("ou_path"),
                "descr": ad.get("description"),
                "ad_os": ad.get("os"),
                "ad_os_version": ad.get("os_version"),
                "ad_last_logon": ad.get("last_logon"),
                "first_seen": collected_at or now_iso(),
                "last_seen": seen_now,
                "status": status,
            },
        )
        host_id = conn.execute(
            "SELECT id FROM hosts WHERE name = ?", (name,)
        ).fetchone()["id"]

        conn.execute(
            """
            INSERT INTO snapshots (
                run_id, host_id, collected_at, level, status, error_message,
                duration_cim_ms, duration_reg_ms, manufacturer, model, serial_number,
                bios_version, cpu_name, ram_total_mb, os_caption, os_build,
                os_display_version, os_arch, os_install_date, last_boot, uptime_days,
                ip_address, mac_address, dhcp_enabled, logged_on_user, last_logged_on_user,
                av_name, av_enabled, av_up_to_date, av_signature_date, reboot_pending,
                wu_last_success
            ) VALUES (
                :run_id, :host_id, :collected_at, :level, :status, :error_message,
                :duration_cim_ms, :duration_reg_ms, :manufacturer, :model, :serial_number,
                :bios_version, :cpu_name, :ram_total_mb, :os_caption, :os_build,
                :os_display_version, :os_arch, :os_install_date, :last_boot, :uptime_days,
                :ip_address, :mac_address, :dhcp_enabled, :logged_on_user, :last_logged_on_user,
                :av_name, :av_enabled, :av_up_to_date, :av_signature_date, :reboot_pending,
                :wu_last_success
            )
            ON CONFLICT(run_id, host_id) DO UPDATE SET
                collected_at        = excluded.collected_at,
                level                = excluded.level,
                status               = excluded.status,
                error_message        = excluded.error_message,
                duration_cim_ms      = excluded.duration_cim_ms,
                duration_reg_ms      = excluded.duration_reg_ms,
                manufacturer         = excluded.manufacturer,
                model                = excluded.model,
                serial_number        = excluded.serial_number,
                bios_version         = excluded.bios_version,
                cpu_name             = excluded.cpu_name,
                ram_total_mb         = excluded.ram_total_mb,
                os_caption           = excluded.os_caption,
                os_build             = excluded.os_build,
                os_display_version   = excluded.os_display_version,
                os_arch              = excluded.os_arch,
                os_install_date      = excluded.os_install_date,
                last_boot            = excluded.last_boot,
                uptime_days          = excluded.uptime_days,
                ip_address           = excluded.ip_address,
                mac_address          = excluded.mac_address,
                dhcp_enabled         = excluded.dhcp_enabled,
                logged_on_user       = excluded.logged_on_user,
                last_logged_on_user  = excluded.last_logged_on_user,
                av_name              = excluded.av_name,
                av_enabled           = excluded.av_enabled,
                av_up_to_date        = excluded.av_up_to_date,
                av_signature_date    = excluded.av_signature_date,
                reboot_pending       = excluded.reboot_pending,
                wu_last_success      = excluded.wu_last_success
            """,
            {
                "run_id": run_id,
                "host_id": host_id,
                "collected_at": collected_at,
                "level": record.get("level"),
                "status": status,
                "error_message": record.get("error_message"),
                "duration_cim_ms": record.get("duration_cim_ms"),
                "duration_reg_ms": record.get("duration_reg_ms"),
                "manufacturer": system.get("manufacturer"),
                "model": system.get("model"),
                "serial_number": system.get("serial_number"),
                "bios_version": system.get("bios_version"),
                "cpu_name": system.get("cpu_name"),
                "ram_total_mb": system.get("ram_total_mb"),
                "os_caption": osinfo.get("caption"),
                "os_build": osinfo.get("build"),
                "os_display_version": osinfo.get("display_version"),
                "os_arch": osinfo.get("arch"),
                "os_install_date": osinfo.get("install_date"),
                "last_boot": osinfo.get("last_boot"),
                "uptime_days": osinfo.get("uptime_days"),
                "ip_address": network.get("ip_address"),
                "mac_address": network.get("mac_address"),
                "dhcp_enabled": network.get("dhcp_enabled"),
                "logged_on_user": system.get("logged_on_user"),
                "last_logged_on_user": (registry or {}).get("last_logged_on_user"),
                "av_name": antivirus.get("name"),
                "av_enabled": antivirus.get("enabled"),
                "av_up_to_date": antivirus.get("up_to_date"),
                "av_signature_date": antivirus.get("signature_date"),
                "reboot_pending": (registry or {}).get("reboot_pending"),
                "wu_last_success": (registry or {}).get("wu_last_success"),
            },
        )
        snapshot_id = conn.execute(
            "SELECT id FROM snapshots WHERE run_id = ? AND host_id = ?",
            (run_id, host_id),
        ).fetchone()["id"]

        # Reinserăm integral copiii snapshot-ului — mai simplu și mai sigur
        # decât un diff, iar volumul (disk-uri, software) e mic per stație.
        conn.execute("DELETE FROM snapshot_disks WHERE snapshot_id = ?", (snapshot_id,))
        for disk in disks:
            size_mb = disk.get("size_mb")
            free_mb = disk.get("free_mb")
            free_pct = (free_mb / size_mb * 100.0) if size_mb else None
            conn.execute(
                """
                INSERT INTO snapshot_disks (snapshot_id, device_id, volume_name, size_mb, free_mb, free_pct)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (snapshot_id, disk.get("device_id"), disk.get("volume_name"), size_mb, free_mb, free_pct),
            )

        conn.execute("DELETE FROM snapshot_software WHERE snapshot_id = ?", (snapshot_id,))
        if registry:
            for sw in registry.get("software") or []:
                conn.execute(
                    """
                    INSERT INTO snapshot_software (snapshot_id, name, version, publisher, install_date, scope)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (snapshot_id, sw.get("name"), sw.get("version"), sw.get("publisher"),
                     sw.get("install_date"), sw.get("scope")),
                )

        conn.commit()
    except Exception:
        conn.rollback()
        raise

    return host_id


def ingest_line(conn, run_id, raw_line: str):
    """Parsează și ingerează o singură linie NDJSON. Întoarce înregistrarea
    ingerată, sau None dacă linia era goală. O linie nevalidă (JSON stricat)
    propagă excepția — apelantul decide dacă o loghează și continuă sau oprește.
    """
    raw_line = raw_line.strip()
    if not raw_line:
        return None
    record = json.loads(raw_line)
    ingest_record(conn, run_id, record)
    return record


def ingest_file(conn, run_id, ndjson_path) -> int:
    """Ingerează un fișier NDJSON complet (folosit pentru re-ingestie manuală
    și pentru rebuild). Întoarce numărul de linii ingerate cu succes.
    """
    count = 0
    with open(ndjson_path, "r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                ingest_record(conn, run_id, json.loads(line))
                count += 1
            except (json.JSONDecodeError, ValueError) as exc:
                print(f"  linia {lineno}: ignorată ({exc})", file=sys.stderr)
    return count


# ---------------------------------------------------------------------------
# Reconstrucție completă din arhiva runs\ (criteriul de acceptanță #8)
# ---------------------------------------------------------------------------

_RUN_ID_RE = re.compile(r"^run-(\d+)-")


def rebuild_from_runs(conn) -> int:
    """Șterge tot conținutul bazei și îl reconstruiește din fișierele
    run-<id>-<timestamp>.ndjson arhivate în runs/. Metadatele rulării
    (nivel, OU de bază, oră de start) vin din sidecar-ul
    run-<id>-<timestamp>.meta.json scris de scanner.py; dacă lipsește
    (ex. fișier NDJSON adăugat manual), se aproximează din conținut.

    Întoarce numărul de rulări reconstruite.
    """
    conn.executescript(
        """
        DELETE FROM alerts;
        DELETE FROM snapshot_software;
        DELETE FROM snapshot_disks;
        DELETE FROM snapshots;
        DELETE FROM hosts;
        DELETE FROM runs;
        """
    )
    conn.commit()

    files = sorted(RUNS_DIR.glob("run-*.ndjson"))
    rebuilt = 0
    for ndjson_path in files:
        m = _RUN_ID_RE.match(ndjson_path.name)
        run_id = int(m.group(1)) if m else None

        meta_path = ndjson_path.with_suffix("").with_suffix(".meta.json")
        meta = {}
        if meta_path.exists():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))

        started_at = meta.get("started_at")
        if started_at is None:
            started_at = datetime.fromtimestamp(
                ndjson_path.stat().st_mtime
            ).astimezone().isoformat(timespec="seconds")

        level = meta.get("level")
        if level is None:
            # cel mai bun efort: nivelul primei înregistrări valide din fișier
            with open(ndjson_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        level = json.loads(line).get("level", 1)
                        break
            level = level or 1

        run_id = create_run(
            conn, level, meta.get("ou_base", "necunoscut"),
            started_at=started_at,
            collector_version=meta.get("collector_version"),
            ndjson_path=str(ndjson_path),
            run_id=run_id,
        )
        ingest_file(conn, run_id, ndjson_path)
        finalize_run(conn, run_id, finished_at=meta.get("finished_at"))
        rebuilt += 1

    # Alertele se recalculează după ce toate rulările există, ca regulile care
    # se uită înapoi în timp (reboot_pending, collect_failed) să vadă istoricul complet.
    import alerts as alerts_module  # import târziu — evită dependența circulară la încărcarea modulului
    for row in conn.execute("SELECT id FROM runs ORDER BY id").fetchall():
        alerts_module.evaluate_run(conn, row["id"])

    return rebuilt


# ---------------------------------------------------------------------------
# CLI — folosit pentru testare manuală (Ordinea de dezvoltare, pasul 1) și
# pentru rebuild la schimbarea schemei.
# ---------------------------------------------------------------------------

def _main():
    import argparse

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Ingerează NDJSON în SQLite (Inventar AD).")
    parser.add_argument("file", nargs="?", help="Fișier NDJSON de ingerat")
    parser.add_argument("--level", type=int, default=1, help="Nivelul rulării (1 sau 2)")
    parser.add_argument("--ou-base", default="manual", help="OU de bază asociat rulării")
    parser.add_argument("--rebuild", action="store_true",
                         help="Reconstruiește integral baza din runs\\*.ndjson")
    args = parser.parse_args()

    db.init_db()
    conn = db.get_connection()
    try:
        if args.rebuild:
            n = rebuild_from_runs(conn)
            print(f"Reconstruit din arhivă: {n} rulări.")
            return
        if not args.file:
            parser.error("dați un fișier NDJSON sau folosiți --rebuild")
        run_id = create_run(conn, args.level, args.ou_base)
        count = ingest_file(conn, run_id, args.file)
        finalize_run(conn, run_id)
        run = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        print(f"Rulare #{run_id}: {count} stații ingerate.")
        print(f"  OK={run['ok_count']} PARTIAL={run['partial_count']} "
              f"OFFLINE={run['offline_count']} ERROR={run['error_count']}")
        print(f"  avg_cim_ms={run['avg_cim_ms']} avg_reg_ms={run['avg_reg_ms']}")
    finally:
        conn.close()


if __name__ == "__main__":
    _main()
