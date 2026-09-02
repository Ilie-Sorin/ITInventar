"""
webapp.py — aplicația Flask a pilotului: pornește scanări, afișează inventarul,
alertele și pagina de decizie Nivel 1 vs. Nivel 2.

Leagă pe toate interfețele (0.0.0.0:5057), fără autentificare — pilot local,
un singur operator, dar cu pagini de consultare vizibile și din alte PC-uri
din rețea (§8). Rutele care pot porni o scanare sau primi o parolă de admin AD
(`/scan`, `/scan/stop`, `/ous`) rămân restricționate explicit la 127.0.0.1 —
vezi `_restrict_sensitive_routes_to_localhost` mai jos — altfel acea parolă
ar circula necriptat (HTTP simplu) către oricine ajunge la server din rețea.
Interfața e în limba română.
"""

import csv
import io
import sys
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, send_file, url_for

sys.path.insert(0, str(Path(__file__).resolve().parent))
import alerts as alerts_module  # noqa: E402
import db  # noqa: E402
import formatting  # noqa: E402
import ingest  # noqa: E402
import messenger  # noqa: E402
import xlsx_export  # noqa: E402
from scanner import OuListError, ScanAlreadyRunningError, list_ous, scanner  # noqa: E402

app = Flask(__name__)
db.init_db()

# Endpoint-uri care pot porni/opri o scanare, interoga direct AD, sau trimite
# o comandă de scriere unei stații (mesaj + parolă de admin) — separate de
# paginile de consultare, care rămân vizibile din toată rețeaua. Numele sunt
# cele implicite Flask (numele funcției), nu URL-urile.
_LOCAL_ONLY_ENDPOINTS = {"start_scan", "stop_scan", "ous", "send_station_message"}


@app.before_request
def _restrict_sensitive_routes_to_localhost():
    """Serverul ascultă acum pe toate interfețele, ca alte PC-uri din rețea să
    poată consulta datele — dar pornirea unei scanări (care poate primi o
    parolă de admin AD, trimisă necriptat) și selectorul de OU rămân utilizabile
    doar de pe stația însăși."""
    if request.endpoint in _LOCAL_ONLY_ENDPOINTS and request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)


# ---------------------------------------------------------------------------
# Conexiune SQLite per-request (închisă automat la finalul fiecărei cereri)
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = db.get_connection()
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


# ---------------------------------------------------------------------------
# Filtre Jinja — formatare consistentă în toate paginile
# ---------------------------------------------------------------------------

@app.template_filter("fmt_dt")
def fmt_dt(value):
    """'2026-08-26T09:14:03+03:00' -> '26.08.2026 09:14' — fără conversii de fus,
    doar reformatare pentru citire (§6: timpii rămân exact cum vin din colector).
    Logica e în formatting.py, partajată cu exportul .xlsx (xlsx_export.py)."""
    return formatting.fmt_dt(value)


@app.template_filter("fmt_mb")
def fmt_mb(value):
    if value is None:
        return "—"
    value = float(value)
    if value >= 1024:
        return f"{value / 1024:.1f} GB"
    return f"{value:.0f} MB"


@app.template_filter("fmt_pct")
def fmt_pct(value):
    if value is None:
        return "—"
    return f"{float(value):.1f}%"


@app.template_filter("fmt_num")
def fmt_num(value, digits=1):
    if value is None:
        return "—"
    return f"{float(value):.{digits}f}"


@app.template_filter("fmt_ms_to_s")
def fmt_ms_to_s(value):
    if value is None:
        return "—"
    return f"{float(value) / 1000:.2f} s"


@app.template_filter("fmt_duration_sec")
def fmt_duration_sec(value):
    if value is None:
        return "—"
    value = float(value)
    minutes, seconds = divmod(int(value), 60)
    if minutes:
        return f"{minutes} min {seconds} s"
    return f"{seconds} s"


# Statusurile de colectare mapate pe clasele CSS de severitate din style.css —
# culoarea e folosită doar pentru semnificație (§8), niciodată decorativ.
_STATUS_CLASS = {
    "OK": "ok", "PARTIAL": "warn", "OFFLINE": "muted",
    "RPC_DENIED": "crit", "TIMEOUT": "crit", "WMI_ERROR": "crit",
    "AD_ONLY": "muted",
}


@app.template_filter("status_class")
def status_class(value):
    return _STATUS_CLASS.get(value, "muted")


@app.context_processor
def inject_globals():
    return {"active_run": None}


# ---------------------------------------------------------------------------
# Interogări partajate
# ---------------------------------------------------------------------------

def get_latest_run(conn, level=None):
    """Ultima rulare finalizată. Cu level=2, ultima rulare de Nivel 2 specific —
    folosit la intrarea în aplicație (§ Sumar) ca datele complete (software,
    reboot în așteptare) să fie cele afișate implicit, chiar dacă între timp
    a mai rulat și o scanare de Nivel 1 (mai rapidă, fără să le înlocuiască
    aici — cele două nivele sunt urmărite separat, vezi /rulari)."""
    if level is not None:
        return conn.execute(
            "SELECT * FROM runs WHERE finished_at IS NOT NULL AND level = ? "
            "ORDER BY started_at DESC LIMIT 1",
            (level,),
        ).fetchone()
    return conn.execute(
        "SELECT * FROM runs WHERE finished_at IS NOT NULL ORDER BY started_at DESC LIMIT 1"
    ).fetchone()


# Coloanele pe care se poate sorta /statii — whitelist explicit, ca parametrul
# de sortare din query string să nu poată injecta SQL arbitrar.
_STATION_SORT_COLUMNS = {
    "name": "h.name",
    "ou": "h.ou_path",
    "model": "s.model",
    "os": "s.os_caption",
    "ip": "s.ip_address",
    "user": """COALESCE(
        NULLIF(s.logged_on_user_display_name, ''), NULLIF(s.last_logged_on_user_display_name, ''),
        NULLIF(s.logged_on_user, ''), s.last_logged_on_user
    )""",
    "disk": "c_free_pct",
    "uptime": "s.uptime_days",
    "av": "s.av_name",
    "status": "s.status",
    "last_seen": "h.last_seen",
}


def _stations_where(search=None, ou=None, status=None, os_filter=None):
    """Construiește clauza WHERE partajată de query_stations() și
    query_stations_export(), ca filtrele din /statii și din /export să se
    comporte identic pe același set de coloane."""
    clauses = ["1 = 1"]
    params = []
    if search:
        like = f"%{search}%"
        clauses.append("(h.name LIKE ? OR h.ou_path LIKE ? OR s.os_caption LIKE ? OR s.ip_address LIKE ?)")
        params += [like, like, like, like]
    if ou:
        clauses.append("h.ou_path = ?")
        params.append(ou)
    if status:
        clauses.append("s.status = ?")
        params.append(status)
    if os_filter:
        clauses.append("s.os_caption = ?")
        params.append(os_filter)
    return " AND ".join(clauses), params


def query_stations(conn, search=None, ou=None, status=None, os_filter=None,
                    sort="name", direction="asc"):
    """Toate stațiile cu cel mai recent snapshot al lor (indiferent de rulare),
    plus procentul liber pe C:. Folosită atât de /statii cât și de export CSV,
    ca cele două să rămână mereu în acord."""
    where_sql, params = _stations_where(search, ou, status, os_filter)
    sql = f"""
        SELECT
            h.id AS host_id, h.name, h.ou_path, h.ad_description, h.last_seen,
            s.id AS snapshot_id, s.run_id, s.status, s.error_message,
            s.manufacturer, s.model, s.os_caption, s.os_build, s.os_display_version,
            s.ip_address, s.logged_on_user, s.last_logged_on_user,
            s.logged_on_user_display_name, s.last_logged_on_user_display_name, s.uptime_days,
            s.av_name, s.av_enabled, s.av_up_to_date, s.level, s.collected_at,
            s.last_boot, s.reboot_pending,
            d.free_pct AS c_free_pct, d.free_mb AS c_free_mb, d.size_mb AS c_size_mb
        FROM hosts h
        LEFT JOIN snapshots s ON s.id = (
            SELECT s2.id FROM snapshots s2 WHERE s2.host_id = h.id
            ORDER BY s2.collected_at DESC, s2.id DESC LIMIT 1
        )
        LEFT JOIN snapshot_disks d ON d.snapshot_id = s.id AND d.device_id = 'C:'
        WHERE {where_sql}
    """
    col = _STATION_SORT_COLUMNS.get(sort, "h.name")
    order = "DESC" if direction == "desc" else "ASC"
    sql += f" ORDER BY {col} {order}"

    return conn.execute(sql, params).fetchall()


def query_stations_export(conn, search=None, ou=None, status=None, os_filter=None,
                           sort="name", direction="asc"):
    """Ca query_stations(), dar cu toate coloanele din secțiunea "Valori curente"
    a fișei stației (nu doar cele afișate în tabelul /statii) — sursă pentru
    foaia "Valori curente" a exportului .xlsx (§ /export)."""
    where_sql, params = _stations_where(search, ou, status, os_filter)
    sql = f"""
        SELECT
            h.id AS host_id, h.name, h.ou_path, h.ad_description,
            s.id AS snapshot_id, s.status, s.error_message, s.level,
            s.manufacturer, s.model, s.serial_number, s.bios_version, s.cpu_name, s.ram_total_mb,
            s.os_caption, s.os_build, s.os_display_version, s.os_arch,
            s.last_boot, s.uptime_days, s.ip_address, s.mac_address, s.dhcp_enabled,
            s.logged_on_user, s.last_logged_on_user,
            s.logged_on_user_display_name, s.last_logged_on_user_display_name,
            s.av_name, s.av_enabled, s.av_up_to_date, s.reboot_pending, s.wu_last_success,
            s.collected_at,
            d.free_pct AS c_free_pct, d.free_mb AS c_free_mb, d.size_mb AS c_size_mb
        FROM hosts h
        LEFT JOIN snapshots s ON s.id = (
            SELECT s2.id FROM snapshots s2 WHERE s2.host_id = h.id
            ORDER BY s2.collected_at DESC, s2.id DESC LIMIT 1
        )
        LEFT JOIN snapshot_disks d ON d.snapshot_id = s.id AND d.device_id = 'C:'
        WHERE {where_sql}
    """
    col = _STATION_SORT_COLUMNS.get(sort, "h.name")
    order = "DESC" if direction == "desc" else "ASC"
    sql += f" ORDER BY {col} {order}"

    return conn.execute(sql, params).fetchall()


def query_export_disks_antivirus(conn, snapshot_ids):
    """Discuri + produse antivirus pentru exact snapshot-urile din
    query_stations_export() (nu recalculează filtrul — refolosește
    snapshot_id-urile deja obținute)."""
    snapshot_ids = [sid for sid in snapshot_ids if sid is not None]
    if not snapshot_ids:
        return [], []
    placeholders = ",".join("?" for _ in snapshot_ids)
    disks = conn.execute(
        f"""
        SELECT h.name AS host_name, d.device_id, d.volume_name, d.size_mb, d.free_mb, d.free_pct
        FROM snapshot_disks d
        JOIN snapshots s ON s.id = d.snapshot_id
        JOIN hosts h ON h.id = s.host_id
        WHERE d.snapshot_id IN ({placeholders})
        ORDER BY h.name COLLATE NOCASE, d.device_id
        """,
        snapshot_ids,
    ).fetchall()
    antivirus = conn.execute(
        f"""
        SELECT h.name AS host_name, a.name, a.enabled, a.up_to_date, a.signature_date
        FROM snapshot_antivirus a
        JOIN snapshots s ON s.id = a.snapshot_id
        JOIN hosts h ON h.id = s.host_id
        WHERE a.snapshot_id IN ({placeholders})
        ORDER BY h.name COLLATE NOCASE, a.name COLLATE NOCASE
        """,
        snapshot_ids,
    ).fetchall()
    return disks, antivirus


def query_export_software(conn, host_ids):
    """Software (mașină + per utilizator) de pe cel mai recent snapshot de
    Nivel 2 al fiecărei stații din `host_ids` — la fel ca fișa stației
    (station_detail), nu neapărat de pe snapshot-ul CEL MAI RECENT (care ar
    putea fi de Nivel 1, fără date de software)."""
    host_ids = [hid for hid in host_ids if hid is not None]
    if not host_ids:
        return [], []
    placeholders = ",".join("?" for _ in host_ids)
    sql = f"""
        WITH latest_l2 AS (
            SELECT s.id AS snapshot_id, s.host_id
            FROM snapshots s
            WHERE s.level = 2 AND s.host_id IN ({placeholders}) AND s.id = (
                SELECT s2.id FROM snapshots s2
                WHERE s2.host_id = s.host_id AND s2.level = 2
                ORDER BY s2.collected_at DESC, s2.id DESC LIMIT 1
            )
        )
        SELECT h.name AS host_name, sw.name, sw.version, sw.publisher, sw.install_date,
               sw.scope, sw.user_name
        FROM snapshot_software sw
        JOIN latest_l2 l ON l.snapshot_id = sw.snapshot_id
        JOIN hosts h ON h.id = l.host_id
        ORDER BY h.name COLLATE NOCASE, sw.name COLLATE NOCASE
    """
    rows = conn.execute(sql, host_ids).fetchall()
    machine = [r for r in rows if r["scope"] != "user"]
    user = [r for r in rows if r["scope"] == "user"]
    return machine, user


def query_software_aggregate(conn):
    """Agregare 'produs + versiune -> nr. stații', pe cel mai recent snapshot
    de Nivel 2 al fiecărei stații (nu pe toate snapshot-urile istorice — altfel
    o stație ar apărea de mai multe ori pentru același produs)."""
    sql = """
        WITH latest_l2 AS (
            SELECT s.id AS snapshot_id, s.host_id
            FROM snapshots s
            WHERE s.level = 2 AND s.id = (
                SELECT s2.id FROM snapshots s2
                WHERE s2.host_id = s.host_id AND s2.level = 2
                ORDER BY s2.collected_at DESC, s2.id DESC LIMIT 1
            )
        )
        SELECT sw.name, sw.version, COUNT(DISTINCT l.host_id) AS host_count
        FROM snapshot_software sw
        JOIN latest_l2 l ON l.snapshot_id = sw.snapshot_id
        GROUP BY sw.name, sw.version
        ORDER BY sw.name COLLATE NOCASE, sw.version
    """
    return conn.execute(sql).fetchall()


def query_software_hosts(conn, name, version):
    sql = """
        WITH latest_l2 AS (
            SELECT s.id AS snapshot_id, s.host_id
            FROM snapshots s
            WHERE s.level = 2 AND s.id = (
                SELECT s2.id FROM snapshots s2
                WHERE s2.host_id = s.host_id AND s2.level = 2
                ORDER BY s2.collected_at DESC, s2.id DESC LIMIT 1
            )
        )
        SELECT h.name, h.ou_path, sw.publisher, sw.install_date, sw.scope, sw.user_name
        FROM snapshot_software sw
        JOIN latest_l2 l ON l.snapshot_id = sw.snapshot_id
        JOIN hosts h ON h.id = l.host_id
        WHERE sw.name = ? AND (sw.version IS ? OR sw.version = ?)
        ORDER BY h.name COLLATE NOCASE
    """
    return conn.execute(sql, (name, version, version)).fetchall()


# ---------------------------------------------------------------------------
# Rute
# ---------------------------------------------------------------------------

@app.route("/")
def dashboard():
    conn = get_db()
    # Implicit arătăm ultima rulare de Nivel 2 (date complete: software,
    # reboot în așteptare) — fără asta, o scanare de Nivel 1 pornită ulterior
    # (mai rapidă, des repetată) ar înlocui pe Sumar date mai complete cu
    # unele parțiale, deși cele de Nivel 2 sunt tot ce are operatorul nevoie
    # să vadă fără să mai pornească nimic manual (cerința: date vizibile la
    # intrarea în aplicație, fără o scanare nouă).
    run = get_latest_run(conn, level=2)
    used_fallback_level = False
    if run is None:
        run = get_latest_run(conn)
        used_fallback_level = run is not None
    host_total = conn.execute("SELECT COUNT(*) AS n FROM hosts").fetchone()["n"]

    status_dist = []
    os_dist = []
    top_disks = []
    crit_alerts = []

    if run:
        status_dist = [
            ("OK", run["ok_count"]), ("PARTIAL", run["partial_count"]),
            ("OFFLINE", run["offline_count"]), ("EROARE", run["error_count"]),
        ]
        os_dist = conn.execute(
            """
            SELECT os_caption, COUNT(*) AS cnt FROM snapshots
            WHERE run_id = ? AND os_caption IS NOT NULL
            GROUP BY os_caption ORDER BY cnt DESC
            """,
            (run["id"],),
        ).fetchall()
        top_disks = conn.execute(
            """
            SELECT h.name, d.device_id, d.free_pct, d.free_mb, d.size_mb
            FROM snapshot_disks d
            JOIN snapshots s ON s.id = d.snapshot_id
            JOIN hosts h ON h.id = s.host_id
            WHERE s.run_id = ? AND d.free_pct IS NOT NULL
            ORDER BY d.free_pct ASC LIMIT 10
            """,
            (run["id"],),
        ).fetchall()
        crit_alerts = conn.execute(
            """
            SELECT a.*, h.name AS host_name FROM alerts a
            JOIN hosts h ON h.id = a.host_id
            WHERE a.run_id = ? AND a.severity = 'crit'
            ORDER BY a.id LIMIT 10
            """,
            (run["id"],),
        ).fetchall()

    return render_template(
        "dashboard.html", run=run, host_total=host_total, status_dist=status_dist,
        os_dist=os_dist, top_disks=top_disks, crit_alerts=crit_alerts,
        used_fallback_level=used_fallback_level,
    )


@app.route("/statii")
def stations():
    conn = get_db()
    search = request.args.get("q", "").strip()
    ou = request.args.get("ou", "").strip()
    status = request.args.get("status", "").strip()
    os_filter = request.args.get("os", "").strip()
    sort = request.args.get("sort", "name")
    direction = request.args.get("dir", "asc")

    rows = query_stations(conn, search or None, ou or None, status or None,
                           os_filter or None, sort, direction)

    ou_options = [r[0] for r in conn.execute(
        "SELECT DISTINCT ou_path FROM hosts WHERE ou_path IS NOT NULL ORDER BY ou_path COLLATE NOCASE"
    ).fetchall()]
    status_options = [r[0] for r in conn.execute(
        "SELECT DISTINCT status FROM snapshots WHERE status IS NOT NULL ORDER BY status"
    ).fetchall()]
    os_options = [r[0] for r in conn.execute(
        "SELECT DISTINCT os_caption FROM snapshots WHERE os_caption IS NOT NULL ORDER BY os_caption"
    ).fetchall()]

    return render_template(
        "statii.html", rows=rows, search=search, ou=ou, status=status, os_filter=os_filter,
        sort=sort, direction=direction,
        ou_options=ou_options, status_options=status_options, os_options=os_options,
    )


@app.route("/statie/<name>")
def station_detail(name):
    conn = get_db()
    host = conn.execute("SELECT * FROM hosts WHERE name = ?", (name,)).fetchone()
    if host is None:
        abort(404)

    current = conn.execute(
        "SELECT * FROM snapshots WHERE host_id = ? ORDER BY collected_at DESC, id DESC LIMIT 1",
        (host["id"],),
    ).fetchone()

    current_disks = []
    current_antivirus = []
    if current:
        current_disks = conn.execute(
            "SELECT * FROM snapshot_disks WHERE snapshot_id = ? ORDER BY device_id",
            (current["id"],),
        ).fetchall()
        current_antivirus = conn.execute(
            "SELECT * FROM snapshot_antivirus WHERE snapshot_id = ? ORDER BY name COLLATE NOCASE",
            (current["id"],),
        ).fetchall()

    disk_history = conn.execute(
        """
        SELECT s.collected_at, d.free_pct
        FROM snapshots s JOIN snapshot_disks d ON d.snapshot_id = s.id
        WHERE s.host_id = ? AND d.device_id = 'C:' AND d.free_pct IS NOT NULL
        ORDER BY s.collected_at
        """,
        (host["id"],),
    ).fetchall()

    status_history = conn.execute(
        """
        SELECT id, run_id, collected_at, level, status, error_message,
               duration_cim_ms, duration_reg_ms
        FROM snapshots WHERE host_id = ? ORDER BY collected_at DESC
        """,
        (host["id"],),
    ).fetchall()

    software = []
    software_snapshot = None
    if current and current["level"] == 2:
        software_snapshot = current
    else:
        software_snapshot = conn.execute(
            """
            SELECT * FROM snapshots WHERE host_id = ? AND level = 2
            ORDER BY collected_at DESC, id DESC LIMIT 1
            """,
            (host["id"],),
        ).fetchone()
    software_machine = []
    software_user = []
    if software_snapshot:
        software = conn.execute(
            "SELECT name, version, publisher, install_date, scope, user_name FROM snapshot_software "
            "WHERE snapshot_id = ? ORDER BY name COLLATE NOCASE",
            (software_snapshot["id"],),
        ).fetchall()
        # Despărțim aici (nu în template) softul mașinii de cel per utilizator —
        # sunt surse de date diferite (HKLM vs. hive-ul fiecărui profil logat,
        # §5.5f) și au sens ca secțiuni separate în UI.
        software_machine = [s for s in software if s["scope"] != "user"]
        software_user = [s for s in software if s["scope"] == "user"]

    recent_alerts = conn.execute(
        """
        SELECT a.*, r.started_at FROM alerts a
        JOIN runs r ON r.id = a.run_id
        WHERE a.host_id = ? ORDER BY a.id DESC LIMIT 20
        """,
        (host["id"],),
    ).fetchall()

    # Grafic simplu (§8: "istoricul spațiului liber") — polilinie SVG pe scară
    # fixă 0-100%, calculată aici ca template-ul să rămână doar prezentare.
    chart_w, chart_h = 640, 160
    chart_points = []
    n = len(disk_history)
    for i, row in enumerate(disk_history):
        x = 0 if n <= 1 else round((i / (n - 1)) * chart_w, 1)
        pct = row["free_pct"]
        y = round(chart_h - (max(0, min(100, pct)) / 100.0) * chart_h, 1)
        chart_points.append({"x": x, "y": y, "date": row["collected_at"], "pct": pct})
    disk_threshold = db.load_config().get("alerts", {}).get("disk_free_pct_min", 10)
    threshold_y = round(chart_h - (disk_threshold / 100.0) * chart_h, 1)

    return render_template(
        "statie.html", host=host, current=current, current_disks=current_disks,
        current_antivirus=current_antivirus,
        disk_history=disk_history, status_history=status_history,
        software=software, software_machine=software_machine, software_user=software_user,
        software_snapshot=software_snapshot, recent_alerts=recent_alerts,
        chart_points=chart_points, chart_w=chart_w, chart_h=chart_h,
        disk_threshold=disk_threshold, threshold_y=threshold_y,
    )


@app.route("/statie/<name>/mesaj", methods=["POST"])
def send_station_message(name):
    """Trimite un mesaj pop-up (msg.exe) stației, prin CIM/DCOM — vezi
    messenger.py și collector/Send-StationMessage.ps1. Restricționată la
    127.0.0.1 (_LOCAL_ONLY_ENDPOINTS), la fel ca /scan: poate primi o parolă
    de admin AD, dată separat doar pentru acest apel."""
    conn = get_db()
    host = conn.execute("SELECT * FROM hosts WHERE name = ?", (name,)).fetchone()
    if host is None:
        abort(404)

    data = request.get_json(silent=True) or request.form
    message = (data.get("message") or "").strip()
    if not message:
        return jsonify({"error": "Mesajul nu poate fi gol."}), 400
    # Limită confirmată empiric 2026-09-02: peste ~240-250 caractere, msg.exe
    # nu mai afișează deloc fereastra pe stația țintă - fără nicio eroare,
    # Task Scheduler raportează în continuare succes (Last Result=0). Validăm
    # și aici (nu doar în JS/maxlength din UI), ca un apel direct la API să nu
    # poată trimite un mesaj care "reușește" dar nu se vede niciodată.
    MSG_MAX_CHARS = 240
    if len(message) > MSG_MAX_CHARS:
        return jsonify({"error": (
            f"Mesajul depășește {MSG_MAX_CHARS} de caractere - msg.exe nu mai afișează "
            "fereastra peste această limită (verificat empiric)."
        )}), 400

    admin_user = (data.get("admin_user") or "").strip() or None
    admin_pass = data.get("admin_pass") or None
    if admin_user and not admin_pass:
        return jsonify({"error": "Lipsește parola pentru contul de admin dat."}), 400

    try:
        messenger.send_message(name, message, admin_user, admin_pass)
    except messenger.MessengerError as exc:
        return jsonify({"error": str(exc)}), 502

    return jsonify({"ok": True})


@app.route("/software")
def software():
    conn = get_db()
    name = request.args.get("name", "").strip()
    version = request.args.get("version", "").strip()

    drilldown_hosts = None
    if name:
        drilldown_hosts = query_software_hosts(conn, name, version or None)

    rows = query_software_aggregate(conn)
    return render_template(
        "software.html", rows=rows, drilldown_hosts=drilldown_hosts,
        drilldown_name=name, drilldown_version=version,
    )


@app.route("/alerte")
def alerte():
    conn = get_db()
    run = get_latest_run(conn)
    rule_filter = request.args.get("rule", "").strip()

    grouped = {"crit": [], "warn": [], "info": []}
    if run:
        sql = """
            SELECT a.*, h.name AS host_name FROM alerts a
            JOIN hosts h ON h.id = a.host_id
            WHERE a.run_id = ?
        """
        params = [run["id"]]
        if rule_filter:
            sql += " AND a.rule = ?"
            params.append(rule_filter)
        sql += " ORDER BY h.name COLLATE NOCASE"
        rows = conn.execute(sql, params).fetchall()
        for r in rows:
            grouped.setdefault(r["severity"], []).append(r)

    # Catalogul de reguli pentru filtru: toate regulile văzute vreodată (nu doar
    # în ultima rulare), ca opțiunea aleasă să rămână valabilă și dacă rularea
    # curentă întâmplător n-are nicio alertă de acel tip.
    rule_options = [r[0] for r in conn.execute(
        "SELECT DISTINCT rule FROM alerts ORDER BY rule"
    ).fetchall()]

    return render_template(
        "alerte.html", run=run, grouped=grouped,
        rule_filter=rule_filter, rule_options=rule_options,
    )


@app.route("/rulari")
def rulari():
    conn = get_db()
    runs = conn.execute("SELECT * FROM runs ORDER BY started_at DESC").fetchall()
    comparison = conn.execute(
        """
        SELECT level, COUNT(*) AS run_count,
               AVG(duration_sec) AS avg_duration_sec,
               AVG(avg_cim_ms) AS avg_cim_ms,
               AVG(avg_reg_ms) AS avg_reg_ms,
               AVG(1.0 * ok_count / NULLIF(host_count, 0)) AS avg_success_rate
        FROM runs WHERE finished_at IS NOT NULL
        GROUP BY level ORDER BY level
        """
    ).fetchall()
    return render_template("rulari.html", runs=runs, comparison=comparison)


# ---------------------------------------------------------------------------
# Scanare
# ---------------------------------------------------------------------------

@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True) or request.form
    try:
        level = int(data.get("level", 1))
    except (TypeError, ValueError):
        return jsonify({"error": "Nivel invalid."}), 400
    if level not in (1, 2):
        return jsonify({"error": "Nivelul trebuie să fie 1 sau 2."}), 400

    ou_base = (data.get("ou_base") or "").strip() or None

    # Mecanism de elevare (§8): cont de admin AD opțional, dat separat doar
    # pentru această scanare — permite pornirea serverului sub un cont
    # obișnuit ("user pentru consultare") și totuși scanare cu drepturi de
    # admin ("admin pentru scanare"). Nu se loghează, nu se persistă nicăieri —
    # scanner._run() le trimite pe stdin colectorului și le uită imediat.
    admin_user = (data.get("admin_user") or "").strip() or None
    admin_pass = data.get("admin_pass") or None
    if admin_user and not admin_pass:
        return jsonify({"error": "Lipsește parola pentru contul de admin dat."}), 400

    try:
        run_id = scanner.start(level, ou_base, admin_user, admin_pass)
    except ScanAlreadyRunningError as exc:
        return jsonify({"error": str(exc)}), 409

    return jsonify({"run_id": run_id}), 202


@app.route("/scan/stop", methods=["POST"])
def stop_scan():
    stopped = scanner.stop()
    return jsonify({"stopped": stopped})


@app.route("/scan/status")
def scan_status():
    return jsonify(scanner.get_status())


@app.route("/ous")
def ous():
    """Selectorul de OU din antet: fără ou_base, arată OU-ul curent + sub-OU-uri
    (auto-detecție, ca la o scanare fără -OuBase); cu ou_base, drill-down în
    acel subarbore. Nu ține de Scanner — poate rula și cu o scanare în curs."""
    ou_base = (request.args.get("ou_base") or "").strip() or None
    try:
        rows = list_ous(ou_base)
    except OuListError as exc:
        return jsonify({"error": str(exc)}), 502
    return jsonify({"ous": rows})


# ---------------------------------------------------------------------------
# Exporturi CSV
# ---------------------------------------------------------------------------

def _csv_response(fieldnames, rows_dicts, filename):
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows_dicts:
        writer.writerow(row)
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/export/statii.csv")
def export_stations_csv():
    conn = get_db()
    search = request.args.get("q", "").strip()
    ou = request.args.get("ou", "").strip()
    status = request.args.get("status", "").strip()
    os_filter = request.args.get("os", "").strip()
    sort = request.args.get("sort", "name")
    direction = request.args.get("dir", "asc")

    rows = query_stations(conn, search or None, ou or None, status or None,
                           os_filter or None, sort, direction)

    fieldnames = ["name", "ou_path", "model", "os_caption", "os_build", "ip_address",
                  "logged_on_user", "last_logged_on_user",
                  "logged_on_user_display_name", "last_logged_on_user_display_name",
                  "c_free_pct", "uptime_days",
                  "av_name", "av_enabled", "status", "last_seen"]
    return _csv_response(fieldnames, (dict(r) for r in rows), "statii.csv")


@app.route("/export/software.csv")
def export_software_csv():
    conn = get_db()
    rows = query_software_aggregate(conn)
    fieldnames = ["name", "version", "host_count"]
    return _csv_response(fieldnames, (dict(r) for r in rows), "software.csv")


# ---------------------------------------------------------------------------
# Export .xlsx (Valori curente → Software instalat), pentru stațiile filtrate
# ---------------------------------------------------------------------------

def _export_filters_from_request():
    return (
        request.args.get("q", "").strip() or None,
        request.args.get("ou", "").strip() or None,
        request.args.get("status", "").strip() or None,
        request.args.get("os", "").strip() or None,
    )


@app.route("/export")
def export_page():
    conn = get_db()
    search, ou, status, os_filter = _export_filters_from_request()
    sort = request.args.get("sort", "name")
    direction = request.args.get("dir", "asc")

    rows = query_stations(conn, search, ou, status, os_filter, sort, direction)

    ou_options = [r[0] for r in conn.execute(
        "SELECT DISTINCT ou_path FROM hosts WHERE ou_path IS NOT NULL ORDER BY ou_path COLLATE NOCASE"
    ).fetchall()]
    status_options = [r[0] for r in conn.execute(
        "SELECT DISTINCT status FROM snapshots WHERE status IS NOT NULL ORDER BY status"
    ).fetchall()]
    os_options = [r[0] for r in conn.execute(
        "SELECT DISTINCT os_caption FROM snapshots WHERE os_caption IS NOT NULL ORDER BY os_caption"
    ).fetchall()]

    return render_template(
        "export.html", rows=rows,
        search=search or "", ou=ou or "", status=status or "", os_filter=os_filter or "",
        sort=sort, direction=direction,
        ou_options=ou_options, status_options=status_options, os_options=os_options,
    )


@app.route("/export/inventar.xlsx")
def export_inventory_xlsx():
    """Exportul .xlsx propriu-zis (§ /export) — pagina de filtrare face fetch()
    la această rută și scrie răspunsul unde alege utilizatorul (File System
    Access API în browser, când e disponibilă — vezi app.js), nu neapărat în
    folderul implicit de descărcări."""
    conn = get_db()
    search, ou, status, os_filter = _export_filters_from_request()
    sort = request.args.get("sort", "name")
    direction = request.args.get("dir", "asc")

    stations = query_stations_export(conn, search, ou, status, os_filter, sort, direction)
    disks, antivirus = query_export_disks_antivirus(conn, (r["snapshot_id"] for r in stations))
    software_machine, software_user = query_export_software(conn, (r["host_id"] for r in stations))

    xlsx_bytes = xlsx_export.build_workbook(stations, disks, antivirus, software_machine, software_user)
    return send_file(
        io.BytesIO(xlsx_bytes),
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True,
        download_name="inventar.xlsx",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5057, debug=False)
