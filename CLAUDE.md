# CLAUDE.md — Inventar stații AD

Constrângeri obligatorii pentru orice lucru pe acest proiect (detalii complete în
`SPEC_InventarAD.md`):

- **Fără WinRM.** Comunicarea cu stațiile se face exclusiv prin CIM peste **DCOM**
  (`New-CimSessionOption -Protocol Dcom`), niciodată WSMan.
- **Fără GPO / agent / scheduled task / logon script** pe stațiile inventariate.
- **Strict read-only.** Colectorul nu scrie, nu instalează, nu repornește, nu modifică nimic
  pe stațiile interogate. `Win32_Product` este **interzis** (declanșează reconfigurare MSI).
- **PowerShell 5.1** pentru `collector/Collect-Inventory.ps1`, fără dependențe externe
  (native Windows PowerShell, nu PowerShell 7).
- **Python 3 + Flask + `sqlite3` stdlib** pentru aplicația web (fără ORM greu).
- Aplicația leagă pe **`0.0.0.0:5057`** (vizibilă și din alte PC-uri din rețea, pentru
  consultare), fără autentificare — dar rutele care pot porni/opri o scanare sau primi o
  parolă de admin AD (`/scan`, `/scan/stop`, `/ous`) sunt restricționate explicit la
  `127.0.0.1` în `webapp.py` (`_restrict_sensitive_routes_to_localhost`). Nu se relaxează
  această restricție fără să se adauge și HTTPS/autentificare — altfel parola de admin AD
  ar circula necriptat pe rețea.
- Contractul dintre colector și web e **NDJSON pe stdout** (o linie JSON per stație),
  progres/erori pe stderr în format `PROGRESS <done>/<total> <hostname>`.
- Interfața web este în **limba română**.
- Paletă vizuală: fundal `#FAF9F5`, suprafețe `#F0EEE6`, text `#141413`, accent `#D97757`.
  Culoarea se folosește doar pentru severitate (verde/chihlimbar/roșu-cărămiziu).
- Cod comentat didactic, mai ales unde se lucrează cu HRESULT-uri, `StdRegProv` și decodarea
  `productState`. Fără abstractizări speculative.

Scopul real al pilotului: compararea Nivel 1 (CIM/DCOM) vs. Nivel 2 (CIM/DCOM + registry) —
vezi `/rulari` în aplicație și `duration_cim_ms` / `duration_reg_ms` în date.

Environment-ul de dezvoltare curent (`D:\ITInventar`) **nu are modulul `ActiveDirectory`
disponibil** — colectorul nu poate fi testat live împotriva unui domeniu aici; se validează
prin parsare sintactică și prin `-ComputerName` / date simulate unde e posibil (CIM/DCOM și
StdRegProv se pot totuși testa real, direct pe `localhost`, fără AD).

**Important — encoding fișiere `.ps1`:** Windows PowerShell 5.1 citește scripturile fără BOM
folosind codepage-ul ANSI al sistemului, nu UTF-8. Fără BOM, diacriticele din comentarii/string-uri
(ă, â, î, ș, ț, — etc.) sparg parserul cu erori confuze ("Missing ')' in method call" etc., pe
linii care par corecte). `collector\Collect-Inventory.ps1` trebuie salvat mereu cu BOM UTF-8
(`utf-8-sig`) — verifică după orice editare majoră cu:
`python -c "print(open('collector/Collect-Inventory.ps1','rb').read(3)==b'\xef\xbb\xbf')"`.
Editările via Edit tool păstrează BOM-ul existent; doar o rescriere completă (Write) l-ar putea
pierde.
