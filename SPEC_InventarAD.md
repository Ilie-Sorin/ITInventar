# SPEC — Inventar stații AD (aplicație pilot web)

Versiune spec: 1.0
Director proiect propus: `D:\ITInventar`

---

## 1. Scopul pilotului

Aplicație web locală care inventariază stațiile Windows dintr-un OU din Active Directory
(inclusiv sub-OU-uri), stochează rezultatele în SQLite cu istoric și le afișează într-o
interfață simplă.

**Obiectivul real al pilotului nu este inventarul în sine, ci decizia:** aplicația trebuie
să poată rula la **Nivel 1** (doar CIM/DCOM) sau la **Nivel 2** (CIM/DCOM + registry prin
StdRegProv), pe același set de stații, astfel încât după 2–3 săptămâni de rulare să se poată
compara concret:

- ce informații în plus aduce Nivelul 2,
- cât costă în timp de scanare,
- cât de des eșuează fiecare nivel și din ce motiv.

Aplicația trebuie deci să **măsoare și să expună aceste diferențe**, nu doar să colecteze date.

---

## 2. Constrângeri obligatorii

- **Fără WinRM.** Comunicarea cu stațiile se face exclusiv prin CIM peste **DCOM**
  (`New-CimSessionOption -Protocol Dcom`), nu prin WSMan.
- **Fără GPO.** Nu se implementează nimic pe stații: fără agent, fără scheduled task,
  fără logon script.
- **Strict read-only.** Colectorul nu scrie, nu instalează, nu repornește și nu modifică
  absolut nimic pe stațiile interogate. Orice apel care ar putea produce efecte secundare
  este interzis (vezi §5.4).
- **PowerShell 5.1** pentru colector (Windows PowerShell nativ, fără dependențe externe).
- **Python 3 + Flask + SQLite** pentru aplicația web (fără ORM greu; `sqlite3` din stdlib
  este suficient).
- Aplicația rulează **local, pe stația de administrare**, sub contul de administrator de
  domeniu al operatorului. Leagă pe **`0.0.0.0:5057`** (paginile de consultare sunt vizibile
  din alte PC-uri din rețea), dar `/scan`, `/scan/stop` și `/ous` rămân restricționate la
  `127.0.0.1` (§8) — nicio parolă de admin AD nu circulă către alte stații.
- Modul `ActiveDirectory` (RSAT) este disponibil pe stația de administrare.

---

## 3. Arhitectură

Trei componente, cu contract clar între ele:

```
┌────────────────────────┐
│  collector/            │   PowerShell 5.1
│  Collect-Inventory.ps1 │   AD → TCP 445 → CIM/DCOM → (opțional) StdRegProv
└───────────┬────────────┘
            │  NDJSON pe stdout (o linie = o stație)
            ▼
┌────────────────────────┐
│  app/ingest.py         │   parsează NDJSON, scrie în SQLite
└───────────┬────────────┘
            ▼
┌────────────────────────┐
│  app/webapp.py (Flask) │   pornește scanarea, afișează datele
│  inventar.db (SQLite)  │
└────────────────────────┘
```

Motivul separării: PowerShell face cel mai bine partea de AD/WMI/registry, Python face cel
mai bine partea de web și de bază de date. Contractul dintre ele este un flux **NDJSON**
(o linie JSON per stație), care poate fi inspectat, salvat și rulat și manual.

### Structura de fișiere

```
D:\ITInventar\
├─ CLAUDE.md                 # constrângerile de mai sus, pentru sesiunile viitoare
├─ SPEC_InventarAD.md        # acest document
├─ config.json               # configurația aplicației
├─ inventar.db               # baza SQLite (creată automat)
├─ collector\
│  └─ Collect-Inventory.ps1
├─ app\
│  ├─ webapp.py              # rutele Flask
│  ├─ db.py                  # schema + acces la SQLite
│  ├─ ingest.py              # NDJSON → SQLite
│  ├─ alerts.py              # evaluarea regulilor
│  ├─ scanner.py             # lansare subprocess PowerShell + progres
│  ├─ templates\
│  └─ static\
├─ runs\                     # NDJSON brut arhivat, un fișier per rulare
└─ logs\
```

---

## 4. Configurația (`config.json`)

```json
{
  "ou_base": null,
  "level": 1,
  "throughput": 12,
  "tcp_probe_timeout_ms": 400,
  "cim_timeout_sec": 45,
  "reg_timeout_sec": 60,
  "db_path": "inventar.db",
  "keep_runs": 60,
  "alerts": {
    "disk_free_pct_min": 10,
    "uptime_days_max": 30,
    "av_signature_age_days_max": 7,
    "reboot_pending_days_max": 7,
    "not_seen_days_max": 21,
    "unsupported_os_builds": ["19045", "19044", "19043"]
  }
}
```

`ou_base: null` înseamnă **auto-detecție**: se folosește OU-ul stației pe care rulează
aplicația. Valoarea poate fi suprascrisă din interfață pentru o rulare punctuală.

---

## 5. Colectorul (`Collect-Inventory.ps1`)

### 5.1 Semnătura

```powershell
param(
    [ValidateSet(1,2)] [int]    $Level = 1,
    [string] $OuBase,                       # gol = auto-detecție
    [int]    $Throughput = 12,
    [int]    $TcpProbeTimeoutMs = 400,
    [int]    $CimTimeoutSec = 45,
    [int]    $RegTimeoutSec = 60,
    [string[]] $ComputerName,               # opțional: listă explicită (pentru test)
    [switch] $WhatIfDiscoveryOnly,          # doar interogarea AD, fără contact cu stațiile
    [System.Management.Automation.PSCredential] $Credential,  # opțional: cont AD, dacă diferă de sesiunea curentă
    [switch] $ListOusOnly                   # doar listează OU-urile (DN + nr. stații), ajutor pentru -OuBase
)
```

`-Credential` e opțional și se folosește atât pentru interogările AD (`Get-ADComputer`,
`Get-ADOrganizationalUnit`, `Get-ADDomain`) cât și pentru sesiunea CIM/DCOM
(`New-CimSession -Credential ...`) — util când operatorul nu e logat pe stația de
administrare cu contul de admin de domeniu.

`-AdminUser <string>` e o alternativă la `-Credential`, gândită pentru apelul din
`app/scanner.py` (mecanismul de elevare, §8): serverul web poate rula sub un cont
obișnuit ("user pentru consultare"), iar operatorul dă separat, doar pentru o
anumită scanare, un cont de admin AD ("admin pentru scanare"). Parola **nu** e
argument de linie de comandă (ar rămâne vizibilă oricui inspectează procesul, ex.
Task Manager / `Get-CimInstance Win32_Process`) — colectorul o citește o singură
dată de pe STDIN, imediat la pornire, și construiește intern un `PSCredential`.
`scanner.py` scrie parola pe stdin-ul subprocesului chiar după ce îl pornește.

`-ListOusOnly` interoghează doar AD (fără contact cu stațiile, la fel ca
`-WhatIfDiscoveryOnly`) și scrie pe stdout un tabel simplu `StatiiActive` / `DistinguishedName`
pentru OU-ul de bază + fiecare sub-OU din subarbore, ca operatorul să aleagă DN-ul potrivit
pentru `-OuBase`. Fără `-OuBase` explicit, se auto-detectează OU-ul stației curente (la fel
ca la scanarea normală) — NU rădăcina domeniului, ca să nu parcurgă tot AD-ul pe domenii
mari; pentru tot domeniul se dă explicit DN-ul rădăcinii ca `-OuBase`. Nu face parte din
contractul NDJSON (nu produce JSON).

Scrie pe **stdout** câte o linie JSON compactă per stație (`ConvertTo-Json -Compress -Depth 6`).
Progresul și erorile merg pe **stderr**, în format `PROGRESS <done>/<total> <hostname>`, ca
să poată fi citite separat de aplicația web.

### 5.2 Descoperirea stațiilor

```powershell
if (-not $OuBase) {
    $myDN   = (Get-ADComputer $env:COMPUTERNAME).DistinguishedName
    $OuBase = $myDN -replace '^CN=[^,]+,',''
}

Get-ADComputer -SearchBase $OuBase -SearchScope Subtree `
    -Filter 'Enabled -eq $true' `
    -Properties DNSHostName,OperatingSystem,OperatingSystemVersion,
                LastLogonDate,Description,whenCreated
```

Datele din AD se salvează **întotdeauna**, chiar dacă stația este offline. O stație offline
produce o linie NDJSON validă cu `status: "OFFLINE"` și câmpurile AD completate.

### 5.3 Testul de disponibilitate

Test TCP pe portul **445** (nu ICMP — pingul e frecvent blocat, iar 445 confirmă totodată
că stația e utilizabilă și pentru admin share):

```powershell
$c = New-Object Net.Sockets.TcpClient
$ok = $c.ConnectAsync($name,445).Wait($TcpProbeTimeoutMs)
```

Paralelizare cu **RunspacePool** (`$Throughput` fire), nu `Start-Job` (prea lent pentru
sute de stații).

### 5.4 Nivel 1 — CIM peste DCOM

```powershell
$opt = New-CimSessionOption -Protocol Dcom
$s   = New-CimSession -ComputerName $name -SessionOption $opt -OperationTimeoutSec $CimTimeoutSec
```

| Clasă | Namespace | Câmpuri |
|---|---|---|
| `Win32_ComputerSystem` | `root\cimv2` | Manufacturer, Model, TotalPhysicalMemory, UserName, NumberOfLogicalProcessors, Domain |
| `Win32_BIOS` | `root\cimv2` | SerialNumber, SMBIOSBIOSVersion, ReleaseDate |
| `Win32_OperatingSystem` | `root\cimv2` | Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, FreePhysicalMemory |
| `Win32_Processor` | `root\cimv2` | Name (primul procesor) |
| `Win32_LogicalDisk` | `root\cimv2` | filtru `DriveType=3`: DeviceID, VolumeName, Size, FreeSpace |
| `Win32_NetworkAdapterConfiguration` | `root\cimv2` | filtru `IPEnabled=TRUE`: IPAddress[0] IPv4, MACAddress, DHCPEnabled |
| `AntiVirusProduct` | `root\SecurityCenter2` | displayName, productState, timestamp |

**Decodarea `productState`** (best-effort, documentată în cod ca atare): se convertește la
hexazecimal pe 6 cifre; octetul din mijloc indică dacă protecția în timp real este activă,
ultimul octet dacă semnăturile sunt la zi. Rezultatul se salvează în două câmpuri booleene
`av_enabled` / `av_up_to_date`, plus `av_signature_date` din `timestamp`.

> **INTERZIS: `Win32_Product`.** Declanșează reconfigurare MSI pe stația țintă și durează
> minute. Softul instalat se citește exclusiv din registry, la Nivel 2.

Toate interogările Nivel 1 se fac pe **aceeași `CimSession`**, care se închide explicit în
`finally`.

### 5.5 Nivel 2 — Nivel 1 + registry prin StdRegProv

Se refolosește sesiunea CIM deja deschisă. Nu se folosește `Remote Registry` (serviciul e
dezactivat implicit pe Win10/11); `StdRegProv` merge prin WMI.

```powershell
$HKLM = 2147483650
Invoke-CimMethod -CimSession $s -Namespace root\cimv2 -ClassName StdRegProv `
    -MethodName EnumKey -Arguments @{ hDefKey=$HKLM; sSubKeyName=$path }
```

Ce se citește:

**a) Software instalat** — din ambele ramuri:
- `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
- `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`

Pentru fiecare subcheie: `DisplayName`, `DisplayVersion`, `Publisher`, `InstallDate`.
Se **exclud** intrările fără `DisplayName`, cele cu `SystemComponent = 1` și cele cu
`ParentKeyName` prezent (actualizări incluse în alt produs).

**b) Versiunea reală a OS-ului** — `SOFTWARE\Microsoft\Windows NT\CurrentVersion`:
`DisplayVersion` (ex. `24H2`) și `UBR` (revizia). Acestea nu se pot obține din
`Win32_OperatingSystem`.

**c) Ultimul utilizator logat** —
`SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI` → `LastLoggedOnSAMUser`.
(Util pentru stațiile la care nimeni nu e logat în momentul scanării, unde
`Win32_ComputerSystem.UserName` e gol.)

**d) Reboot în așteptare** — `reboot_pending = true` dacă oricare este adevărat:
- există cheia `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`
- există cheia `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`
- există valoarea `PendingFileRenameOperations` în `SYSTEM\CurrentControlSet\Control\Session Manager`

**e) Ultima actualizare Windows reușită** —
`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install` →
`LastSuccessTime`.

Enumerarea softului este partea cea mai costisitoare (zeci de subchei × 4 valori). Se
măsoară **separat** durata blocului registry (`duration_reg_ms`) față de blocul CIM
(`duration_cim_ms`) — exact acesta e numărul care fundamentează decizia Nivel 1 vs. Nivel 2.

### 5.6 Coduri de stare per stație

| Status | Semnificație |
|---|---|
| `OK` | Toate blocurile nivelului cerut au reușit |
| `PARTIAL` | Stația a răspuns, dar cel puțin un bloc a eșuat (se salvează ce s-a obținut) |
| `OFFLINE` | Test TCP 445 eșuat |
| `RPC_DENIED` | Acces refuzat / firewall DCOM (HRESULT 0x80070005, 0x800706BA) |
| `TIMEOUT` | Depășire `CimTimeoutSec` / `RegTimeoutSec` |
| `WMI_ERROR` | Altă eroare CIM |
| `AD_ONLY` | Rulare cu `-WhatIfDiscoveryOnly` |

`error_message` păstrează mesajul original și codul HRESULT, netrunchiat.

### 5.7 Formatul NDJSON

```json
{
  "schema": 1,
  "level": 2,
  "collected_at": "2026-08-26T09:14:03+03:00",
  "status": "OK",
  "error_message": null,
  "duration_cim_ms": 1840,
  "duration_reg_ms": 6120,
  "ad": {
    "name": "GR-CTB-014",
    "dns_name": "gr-ctb-014.domeniu.local",
    "distinguished_name": "CN=GR-CTB-014,OU=Contabilitate,OU=Sediu1,DC=...",
    "ou_path": "Sediu1/Contabilitate",
    "description": "Birou 12 - facturare",
    "os": "Windows 11 Pro",
    "os_version": "10.0 (26100)",
    "last_logon": "2026-08-25T16:42:11+03:00"
  },
  "system": {
    "manufacturer": "HP", "model": "ProDesk 400 G7",
    "serial_number": "CZC1234ABC", "bios_version": "S05 Ver. 02.14.00",
    "cpu_name": "Intel(R) Core(TM) i5-10500",
    "ram_total_mb": 16384,
    "logged_on_user": "DOMENIU\\popescu.ion"
  },
  "os": {
    "caption": "Microsoft Windows 11 Pro", "build": "26100",
    "display_version": "24H2", "ubr": 1742,
    "arch": "64-bit",
    "install_date": "2025-03-11T10:02:00+02:00",
    "last_boot": "2026-08-20T07:55:14+03:00",
    "uptime_days": 6.05
  },
  "network": { "ip_address": "10.20.3.114", "mac_address": "A4:BB:6D:...", "dhcp_enabled": true },
  "disks": [ { "device_id": "C:", "volume_name": "Windows", "size_mb": 476000, "free_mb": 38200 } ],
  "antivirus": { "name": "Windows Defender", "enabled": true, "up_to_date": true,
                 "signature_date": "2026-08-26T04:10:00+03:00" },
  "registry": {
    "last_logged_on_user": "DOMENIU\\popescu.ion",
    "reboot_pending": false,
    "wu_last_success": "2026-08-14T03:12:00+03:00",
    "software": [ { "name": "Zoom Workplace", "version": "6.5.1", "publisher": "Zoom", "install_date": "2026-08-21", "scope": "machine" } ]
  }
}
```

La Nivel 1, obiectul `registry` este `null` — nu absent, ca să fie clar în date că nivelul
a fost 1, nu că citirea a eșuat.

---

## 6. Schema SQLite

```sql
CREATE TABLE runs (
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
    ndjson_path       TEXT
);

CREATE TABLE hosts (
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

CREATE TABLE snapshots (
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
    mac_address         TEXT,
    dhcp_enabled        INTEGER,
    logged_on_user      TEXT,
    last_logged_on_user TEXT,
    av_name             TEXT,
    av_enabled          INTEGER,
    av_up_to_date       INTEGER,
    av_signature_date   TEXT,
    reboot_pending      INTEGER,
    wu_last_success     TEXT,
    UNIQUE(run_id, host_id)
);

CREATE TABLE snapshot_disks (
    id           INTEGER PRIMARY KEY,
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    device_id    TEXT NOT NULL,
    volume_name  TEXT,
    size_mb      INTEGER,
    free_mb      INTEGER,
    free_pct     REAL
);

CREATE TABLE snapshot_software (
    id           INTEGER PRIMARY KEY,
    snapshot_id  INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    version      TEXT,
    publisher    TEXT,
    install_date TEXT,
    scope        TEXT               -- 'machine' | 'machine_x86'
);

CREATE TABLE alerts (
    id           INTEGER PRIMARY KEY,
    run_id       INTEGER NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rule         TEXT NOT NULL,
    severity     TEXT NOT NULL,     -- 'info' | 'warn' | 'crit'
    message      TEXT NOT NULL,
    value        TEXT
);

CREATE INDEX ix_snap_host ON snapshots(host_id, collected_at DESC);
CREATE INDEX ix_snap_run  ON snapshots(run_id);
CREATE INDEX ix_sw_name   ON snapshot_software(name, version);
CREATE INDEX ix_alerts    ON alerts(run_id, severity);
```

Notă de implementare: `PRAGMA foreign_keys = ON` la fiecare conexiune, `PRAGMA journal_mode = WAL`
(scanarea scrie în timp ce interfața citește). Toate datele-timp se stochează ca text ISO 8601
cu offset, exact așa cum vin din colector — **fără** conversii de fus orar.

Ingestia unei rulări se face într-o singură tranzacție per stație, cu `INSERT ... ON CONFLICT`
pe `hosts.name` pentru upsert.

---

## 7. Regulile de alertare

Se evaluează după fiecare rulare, pe snapshot-ul curent, și se scriu în `alerts`. Pragurile
vin din `config.json`.

| Regulă | Condiție | Severitate |
|---|---|---|
| `disk_low` | orice disc cu `free_pct < disk_free_pct_min` | crit sub 5%, altfel warn |
| `uptime_high` | `uptime_days > uptime_days_max` | warn |
| `av_missing` | niciun produs AV raportat | crit |
| `av_disabled` | `av_enabled = 0` | crit |
| `av_stale` | `av_signature_date` mai veche de `av_signature_age_days_max` | warn |
| `reboot_pending` | `reboot_pending = 1` în toate rulările din ultimele `reboot_pending_days_max` zile | warn |
| `os_unsupported` | `os_build` în lista `unsupported_os_builds` | warn |
| `not_seen` | `hosts.last_seen` mai veche de `not_seen_days_max` zile | warn |
| `collect_failed` | status `RPC_DENIED` / `TIMEOUT` / `WMI_ERROR` în ultimele 3 rulări consecutive | info |

Regulile care depind de registry (`reboot_pending`) se evaluează doar la rulările de Nivel 2
și se marchează ca „indisponibil la Nivel 1" în interfață — nu ca „OK".

---

## 8. Aplicația web (Flask)

Legare pe `0.0.0.0:5057` — vizibilă și din alte PC-uri din rețea, ca alte persoane să poată
consulta datele fără să aibă acces la stația de administrare. Fără autentificare (pilot
local, un singur operator care pornește scanări).

Rutele `POST /scan`, `POST /scan/stop` și `GET /ous` sunt restricționate la `127.0.0.1`
(`_restrict_sensitive_routes_to_localhost` din `webapp.py`, verificat prin `before_request`)
— sunt singurele care pot porni/opri o scanare sau primi parola mecanismului de elevare
(§5.1), iar fără HTTPS acea parolă nu trebuie să circule niciodată către alte stații din
rețea. Restul rutelor (dashboard, `/statii`, `/statie/<name>`, `/software`, `/alerte`,
`/rulari`, exporturile CSV, `/scan/status`) rămân accesibile de oriunde din rețea — conțin
doar date de consultare, nicio acțiune și nicio credențială.

Interfața este în **limba română**.

### Rute

| Rută | Conținut |
|---|---|
| `GET /` | Dashboard: numărul de stații, distribuția pe status din ultima rulare, alerte critice, distribuția pe versiuni de OS, top 10 stații cu spațiu redus |
| `GET /statii` | Tabel cu toate stațiile: nume, OU, model, OS + build, IP, ultimul user, spațiu liber C:, uptime, AV, status, ultima vedere. Sortabil pe orice coloană, căutare liberă, filtre pe OU / status / OS |
| `GET /statie/<name>` | Fișa stației: valorile curente, istoricul spațiului liber (grafic simplu), istoricul statusurilor, lista de software (dacă există date de Nivel 2), toate snapshot-urile |
| `GET /software` | Doar cu date de Nivel 2: agregare „produs + versiune → număr de stații", cu drill-down la lista de stații. Aici se vede imediat parcul neomogen (versiuni vechi de Zoom, Java, browsere) |
| `GET /alerte` | Alertele ultimei rulări, grupate pe severitate, cu link la fișa stației; `?rule=` opțional filtrează pe tipul de mesaj (regulă) |
| `GET /rulari` | **Pagina de decizie a pilotului**: pentru fiecare rulare — nivel, durată totală, medie CIM, medie registry, rată de succes pe status. Plus un panou comparativ Nivel 1 vs. Nivel 2 (medii agregate pe fiecare nivel) |
| `POST /scan` | Pornește o scanare: parametri `level` (1 sau 2), `ou_base` opțional și, pentru mecanismul de elevare, `admin_user`/`admin_pass` opționale (dacă `admin_user` e dat, `admin_pass` e obligatoriu) |
| `GET /scan/status` | JSON pentru polling: `{running, done, total, current_host, elapsed_sec, run_id}` |
| `GET /ous` | Selectorul de OU din antet: `?ou_base=` opțional (gol = auto-detecție, ca la scanare); rulează colectorul cu `-ListOusOnly` și întoarce `{ous: [{dn, count}, ...]}` — primul element e mereu OU-ul de bază însuși. Independent de starea de scanare (nu ține lock-ul din `scanner.py`) |
| `GET /export/statii.csv` | Export CSV al vederii curente (cu filtrele aplicate) |
| `GET /export/software.csv` | Export CSV al agregării de software |

### Mecanica scanării (`scanner.py`)

- O singură scanare simultan; un al doilea `POST /scan` primește `409`.
- `subprocess.Popen` cu `powershell.exe -NoProfile -ExecutionPolicy Bypass -File ...`,
  citind stdout (NDJSON) linie cu linie într-un fir separat și ingerând incremental —
  rezultatele apar în interfață pe măsură ce sosesc, nu la final.
- stderr se parsează pentru liniile `PROGRESS` și se scrie integral în `logs\`.
- NDJSON-ul brut se arhivează în `runs\run-<id>-<timestamp>.ndjson` (permite re-ingestia
  fără re-scanare, util la modificarea schemei).
- Rularea se poate opri din interfață (terminarea procesului + marcarea rulării ca
  întreruptă).

### Aspect vizual

Paletă: fundal `#FAF9F5`, suprafețe `#F0EEE6`, text `#141413`, accent `#D97757`.
Font sans-serif de sistem. Fără framework CSS greu — un singur `static/style.css` scris de
mână. Tabele dense, lizibile, cu rânduri compacte; culoarea se folosește **doar** pentru
severitate (verde/chihlimbar/roșu-cărămiziu), nu decorativ.

---

## 9. În afara scopului (explicit)

- Nu se detectează și nu se raportează modificări de configurație hardware.
- Nu se implementează remedieri, comenzi la distanță, repornire sau instalare de software.
- Fără agent, fără scheduled task pe stații, fără GPO, fără WinRM.
- Fără autentificare, roluri sau multi-utilizator.
- Fără notificări prin e-mail (alertele se văd în interfață; se poate adăuga ulterior).
- Fără inventar de imprimante (există deja soluție separată).

---

## 10. Criterii de acceptanță

1. Cu `-WhatIfDiscoveryOnly`, colectorul listează stațiile din OU-ul curent și sub-OU-uri,
   fără să atingă nicio stație, în sub 5 secunde.
2. O rulare de Nivel 1 pe ~200 de stații se încheie în sub 4 minute cu `Throughput = 12`.
3. O stație oprită produce o înregistrare validă cu `status = OFFLINE` și datele din AD
   completate — nu lipsește din raport.
4. O stație care refuză DCOM produce `RPC_DENIED` cu HRESULT-ul în `error_message`,
   iar scanarea continuă neîntrerupt.
5. La Nivel 1, coloana de software este marcată explicit „indisponibil la Nivel 1"
   (nu goală, nu zero).
6. Aceeași stație scanată la Nivel 1 și apoi la Nivel 2 produce două snapshot-uri
   comparabile, iar `/rulari` arată diferența de durată între cele două niveluri.
7. Două rulări consecutive nu duplică stațiile în `hosts`.
8. Baza de date poate fi ștearsă și reconstruită integral din fișierele NDJSON din `runs\`.
9. `Win32_Product` nu apare nicăieri în cod.

---

## 11. Ordinea de dezvoltare

1. `db.py` (schema + inițializare) și `ingest.py`, testate pe un fișier NDJSON scris de mână.
2. `Collect-Inventory.ps1` — descoperire AD + probe TCP + Nivel 1, testat pe 3–5 stații
   prin `-ComputerName`.
3. Ingestie reală + pagina `/statii` și `/statie/<name>`.
4. Nivelul 2 în colector, cu măsurarea separată a duratei.
5. `scanner.py` + butonul de scanare + progres.
6. `alerts.py` + paginile `/alerte` și `/rulari`.
7. Pagina `/software` și exporturile CSV.

Fiecare etapă trebuie să fie funcțională de sine stătător înainte de următoarea.

---

## 12. Stil de cod

Cod comentat consistent, aproape didactic: fiecare funcție cu explicație scurtă a **de ce**
face ce face, nu doar ce face. În PowerShell, comentarii explicite acolo unde se lucrează cu
HRESULT-uri, cu `StdRegProv` (constantele `hDefKey`) și cu decodarea `productState`, pentru
că sunt zonele pe care nu le poți reciti peste șase luni fără context. Fără abstractizări
speculative: pilotul trebuie să rămână ușor de citit și de modificat.
