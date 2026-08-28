"""
alerts.py — evaluează regulile de alertare din §7 pe snapshot-urile unei
rulări și le scrie în tabela alerts.

Pragurile vin din config.json (secțiunea "alerts"). Regulile care depind de
registry (reboot_pending) se evaluează doar la rulări de Nivel 2 — la Nivel 1
sunt pur și simplu sărite, nu raportate ca „OK" (webapp.py le arată separat
ca „indisponibil la Nivel 1", nu ca stare bună).
"""

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import db  # noqa: E402

# Statusurile tratate ca eșec de colectare pentru regula collect_failed —
# aceleași ca STATUSES_ERROR din ingest.py (OFFLINE nu e inclus: e starea
# stației, nu un eșec al colectorului).
STATUSES_COLLECT_FAILED = ("RPC_DENIED", "TIMEOUT", "WMI_ERROR")


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def evaluate_run(conn, run_id: int) -> int:
    """(Re)evaluează toate regulile pentru snapshot-urile rulării run_id.

    Șterge întâi alertele existente ale acestei rulări — idempotent, ca să
    poată fi apelată de mai multe ori (ex. la rebuild din runs\\) fără să
    dubleze rândurile. Întoarce numărul de alerte scrise.
    """
    run = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        return 0

    cfg = db.load_config().get("alerts", {})
    now = datetime.now().astimezone()

    conn.execute("DELETE FROM alerts WHERE run_id = ?", (run_id,))

    snapshots = conn.execute(
        """
        SELECT s.*, h.last_seen AS host_last_seen
        FROM snapshots s JOIN hosts h ON h.id = s.host_id
        WHERE s.run_id = ?
        """,
        (run_id,),
    ).fetchall()

    new_alerts = []
    for snap in snapshots:
        host_id = snap["host_id"]
        new_alerts.extend(_check_disk_low(conn, run_id, host_id, snap, cfg))
        new_alerts.extend(_check_uptime_high(run_id, host_id, snap, cfg))
        new_alerts.extend(_check_av(conn, run_id, host_id, snap, cfg, now))
        new_alerts.extend(_check_os_unsupported(run_id, host_id, snap, cfg))
        new_alerts.extend(_check_not_seen(run_id, host_id, snap, cfg, now))
        new_alerts.extend(_check_collect_failed(conn, run_id, host_id, snap))
        if run["level"] == 2:
            new_alerts.extend(_check_reboot_pending(conn, run_id, host_id, snap, cfg, now))

    if new_alerts:
        conn.executemany(
            """
            INSERT INTO alerts (run_id, host_id, rule, severity, message, value)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            new_alerts,
        )
    conn.commit()
    return len(new_alerts)


def _check_disk_low(conn, run_id, host_id, snap, cfg):
    # crit sub 5%, altfel warn — pragul de bază (disk_free_pct_min) vine din config.
    threshold = cfg.get("disk_free_pct_min", 10)
    disks = conn.execute(
        "SELECT device_id, free_pct FROM snapshot_disks WHERE snapshot_id = ?",
        (snap["id"],),
    ).fetchall()
    out = []
    for d in disks:
        if d["free_pct"] is None or d["free_pct"] >= threshold:
            continue
        severity = "crit" if d["free_pct"] < 5 else "warn"
        msg = f"Spațiu liber redus pe {d['device_id']}: {d['free_pct']:.1f}% (prag {threshold}%)"
        out.append((run_id, host_id, "disk_low", severity, msg, f"{d['free_pct']:.1f}"))
    return out


def _check_uptime_high(run_id, host_id, snap, cfg):
    threshold = cfg.get("uptime_days_max", 30)
    uptime = snap["uptime_days"]
    if uptime is None or uptime <= threshold:
        return []
    msg = f"Stație pornită continuu de {uptime:.1f} zile (prag {threshold})"
    return [(run_id, host_id, "uptime_high", "warn", msg, f"{uptime:.1f}")]


def _check_av(conn, run_id, host_id, snap, cfg, now):
    # Doar pentru stații care au răspuns efectiv — la OFFLINE/RPC_DENIED lipsa
    # datelor AV e o consecință a eșecului de colectare, nu o problemă de AV.
    if snap["status"] not in ("OK", "PARTIAL"):
        return []

    # Se pot raporta MAI MULTE produse AV simultan (ex. Windows Defender +
    # Bitdefender Endpoint Security Tools) — Windows dezactivează de regulă
    # protecția Defender-ului când alt AV preia rolul, dar Defender rămâne
    # înregistrat ca produs "dezactivat" în Security Center. De-asta evaluăm
    # pe LISTA completă din snapshot_antivirus, nu pe un singur produs: altfel
    # am fi putut declanșa av_disabled fals pentru un Defender rezidual cât
    # timp AV-ul terț chiar protejează stația.
    rows = conn.execute(
        "SELECT name, enabled, up_to_date, signature_date FROM snapshot_antivirus WHERE snapshot_id = ?",
        (snap["id"],),
    ).fetchall()
    products = [dict(r) for r in rows]

    if not products:
        # Compatibilitate cu snapshot-uri ingerate înainte de introducerea
        # tabelei snapshot_antivirus (sau cu un colector mai vechi) — ne
        # întoarcem la coloana scalară unică a snapshot-ului.
        if snap["av_name"]:
            products = [{
                "name": snap["av_name"], "enabled": snap["av_enabled"],
                "up_to_date": snap["av_up_to_date"], "signature_date": snap["av_signature_date"],
            }]

    if not products:
        return [(run_id, host_id, "av_missing", "crit",
                 "Niciun produs antivirus raportat", None)]

    out = []
    enabled_products = [p for p in products if p["enabled"]]
    if not enabled_products:
        names = ", ".join(p["name"] for p in products if p["name"]) or "necunoscut"
        out.append((run_id, host_id, "av_disabled", "crit",
                     f"Protecția în timp real este dezactivată la toate produsele AV raportate ({names})", names))

    # Prospețimea semnăturilor contează doar pentru produsele ACTIVE — dacă un
    # AV e oricum dezactivat, semnăturile lui vechi nu mai sunt relevante, iar
    # cazul "niciun AV activ" e deja acoperit de av_disabled mai sus.
    max_age = cfg.get("av_signature_age_days_max", 7)
    stale = []
    for p in enabled_products:
        sig_date = _parse_dt(p["signature_date"])
        if sig_date is None:
            continue
        age_days = (now - sig_date).total_seconds() / 86400.0
        if age_days > max_age:
            stale.append((p["name"], age_days))
    if stale:
        worst_name, worst_age = max(stale, key=lambda t: t[1])
        msg = f"Semnături antivirus vechi de {worst_age:.1f} zile la {worst_name or 'AV activ'} (prag {max_age})"
        out.append((run_id, host_id, "av_stale", "warn", msg, f"{worst_age:.1f}"))
    return out


def _check_os_unsupported(run_id, host_id, snap, cfg):
    unsupported = {str(b) for b in cfg.get("unsupported_os_builds", [])}
    build = snap["os_build"]
    if not build or str(build) not in unsupported:
        return []
    return [(run_id, host_id, "os_unsupported", "warn",
             f"Build de Windows nesuportat: {build}", str(build))]


def _check_not_seen(run_id, host_id, snap, cfg, now):
    max_days = cfg.get("not_seen_days_max", 21)
    last_seen = _parse_dt(snap["host_last_seen"])
    if last_seen is None:
        return []  # niciodată văzută cu succes — nu avem un moment de referință
    age_days = (now - last_seen).total_seconds() / 86400.0
    if age_days <= max_days:
        return []
    msg = f"Stație nevăzută de {age_days:.1f} zile (prag {max_days})"
    return [(run_id, host_id, "not_seen", "warn", msg, f"{age_days:.1f}")]


def _check_collect_failed(conn, run_id, host_id, snap):
    rows = conn.execute(
        """
        SELECT status FROM snapshots
        WHERE host_id = ?
        ORDER BY collected_at DESC, id DESC
        LIMIT 3
        """,
        (host_id,),
    ).fetchall()
    if len(rows) < 3 or not all(r["status"] in STATUSES_COLLECT_FAILED for r in rows):
        return []
    msg = f"Colectarea eșuează consecutiv de 3 rulări (ultimul status: {snap['status']})"
    return [(run_id, host_id, "collect_failed", "info", msg, snap["status"])]


def _check_reboot_pending(conn, run_id, host_id, snap, cfg, now):
    # Doar la Nivel 2 (apelantul filtrează deja pe run.level == 2). Alertăm
    # doar dacă TOATE rulările de Nivel 2 din fereastră au raportat reboot
    # pending — o singură zi nu alertează, ca să nu facă zgomot la fiecare
    # ciclu normal de patching.
    days = cfg.get("reboot_pending_days_max", 7)
    since = (now - timedelta(days=days)).isoformat(timespec="seconds")
    rows = conn.execute(
        """
        SELECT reboot_pending FROM snapshots
        WHERE host_id = ? AND level = 2 AND collected_at >= ?
        """,
        (host_id, since),
    ).fetchall()
    if not rows or not all(r["reboot_pending"] == 1 for r in rows):
        return []
    msg = f"Reboot în așteptare de cel puțin {days} zile"
    return [(run_id, host_id, "reboot_pending", "warn", msg, None)]


def _main():
    import argparse

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(description="Reevaluează regulile de alertare pentru o rulare.")
    parser.add_argument("run_id", type=int)
    args = parser.parse_args()

    conn = db.get_connection()
    try:
        n = evaluate_run(conn, args.run_id)
        print(f"Rulare #{args.run_id}: {n} alerte scrise.")
    finally:
        conn.close()


if __name__ == "__main__":
    _main()
