<#
    Send-StationMessage.ps1 — trimite un mesaj pop-up sesiunii interactive a
    utilizatorului logat pe o stație, apelat de app/messenger.py (POST
    /statie/<nume>/mesaj din webapp.py, pornit doar de pe stația de
    administrare — vezi _restrict_sensitive_routes_to_localhost).

    Comunicarea cu stația se face exclusiv prin CIM peste DCOM
    (New-CimSessionOption -Protocol Dcom), niciodată WSMan — vezi CLAUDE.md.

    De ce un task Scheduler temporar și nu direct Win32_Process::Create +
    msg.exe: Win32_Process::Create pornește *întotdeauna* procesul în Session
    0 (izolată, non-interactivă) — limitare documentată Microsoft, nu o
    problemă de drepturi ale contului. Un msg.exe pornit așa moare aproape
    instant, fără să ajungă niciodată vizibil pe ecranul utilizatorului
    conectat (verificat empiric: procesul pornește, dar dispare la scurt
    timp). Singura cale documentată de a ocoli izolarea de sesiune fără WinRM
    este un task Windows cu declanșator "doar când utilizatorul e logat,
    interactiv" (/IT) — acesta rulează efectiv ÎN sesiunea utilizatorului, nu
    în Session 0. De-aia: cerem prin CIM cine e logat acum (Win32_ComputerSystem),
    creăm un task unic cu /RU <acel user> /IT (fără parolă — /IT folosește
    tokenul sesiunii deja active, nu autentificare nouă), îl rulăm o singură
    dată imediat, apoi îl ștergem după un interval de grație (implicit 20s,
    parametrul -GraceSeconds) — totul rămâne pe firul CIM/DCOM deja deschis,
    fără alt protocol de la distanță, și nu lasă nimic persistent pe stație
    (vezi excepția documentată explicit în CLAUDE.md). Intervalul de grație
    nu e opțional: verificat empiric (2026-09-02) că "schtasks /Delete /F"
    imediat după Run închide fereastra msg.exe încă neconfirmată de
    utilizator, deși mesajul chiar ajunsese pe ecran — utilizatorul vedea
    doar un flash. Task-ul rămas 20s pe stație, neșters, e un cost acceptat
    pentru livrare vizibilă efectiv.

    Această acțiune NU e read-only — e o cerere explicită a operatorului, nu o
    colectare automată; constrângerea "strict read-only" din CLAUDE.md
    privește colectorul de inventariere (Collect-Inventory.ps1), nu asta.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ComputerName,
    [Parameter(Mandatory)] [string] $Message,
    [string] $AdminUser,                    # opțional: cont de admin AD separat, ca la scanare
                                             # (parola vine pe stdin, nu ca argument — vezi mai jos)
    [int] $GraceSeconds = 20                # cât așteptăm după Run înainte să ștergem task-ul —
                                             # timp ca utilizatorul să apuce să vadă/închidă mesajul
                                             # (vezi comentariul din finally de mai jos)
)

$ErrorActionPreference = 'Stop'

$Credential = $null
if ($AdminUser) {
    # Parola pe stdin, o singură citire — la fel ca la Collect-Inventory.ps1,
    # ca să nu rămână vizibilă în linia de comandă a procesului (Task Manager).
    $line = [Console]::In.ReadLine()
    if ([string]::IsNullOrEmpty($line)) {
        Write-Error "Lipsește parola pe stdin pentru -AdminUser."
        exit 1
    }
    $securePassword = ConvertTo-SecureString $line -AsPlainText -Force
    $Credential = New-Object System.Management.Automation.PSCredential($AdminUser, $securePassword)
}

# Rulează o comandă LOCAL pe stația țintă (prin CIM/DCOM deja deschis) și
# așteaptă (interogând Win32_Process) fie ca procesul să dispară, fie
# timeout-ul — util ca pașii create/run ai schtasks să nu se suprapună.
function Invoke-RemoteCommandAndWait {
    param($Session, [string] $CommandLine, [int] $MaxWaitSec = 10)

    $created = Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create `
        -Arguments @{ CommandLine = $CommandLine } -ErrorAction Stop
    if ($created.ReturnValue -ne 0) {
        return [pscustomobject]@{ Started = $false; ReturnValue = $created.ReturnValue; StillRunning = $false }
    }

    $deadline = (Get-Date).AddSeconds($MaxWaitSec)
    $proc = $null
    do {
        Start-Sleep -Milliseconds 300
        $proc = Get-CimInstance -CimSession $Session -ClassName Win32_Process `
            -Filter "ProcessId = $($created.ProcessId)" -ErrorAction SilentlyContinue
    } while ($proc -and (Get-Date) -lt $deadline)

    [pscustomobject]@{ Started = $true; ReturnValue = 0; StillRunning = [bool]$proc; ProcessId = $created.ProcessId }
}

function Get-RemoteTaskLastResult {
    <#
        "Last Result" e semnalul autoritativ al Scheduler-ului despre ce s-a
        întâmplat efectiv la rularea acțiunii (0 = succes; altfel un cod de
        eroare Win32/HRESULT, ca int32 semnat) - mult mai de încredere decât
        o sondare a proceselor, care poate rata un msg.exe scurt-trăitor
        (fără /W, msg.exe trimite mesajul și iese aproape instant).
        schtasks.exe nu își poate întoarce output-ul prin CIM
        (Win32_Process::Create e fire-and-forget, fără stdout), așa că îl
        redirectăm într-un fișier temporar pe stație și îl citim prin
        share-ul administrativ C$ (SMB simplu, NU WinRM - vezi CLAUDE.md) -
        aceleași drepturi de admin ca și sesiunea CIM/DCOM deja deschisă.
        Coloana e citită după POZIȚIE (a 7-a), nu după eticheta header-ului
        din CSV, ca să funcționeze indiferent de limba de interfață a
        stației - eticheta se traduce, ordinea coloanelor nu.
    #>
    param($Session, [string]$ComputerName, [string]$TaskName,
          [System.Management.Automation.PSCredential]$Credential)

    $remoteFile = "C:\Windows\Temp\$TaskName.csv"
    $queryCmd = 'cmd.exe /c schtasks.exe /Query /TN "' + $TaskName + '" /V /FO CSV > "' + $remoteFile + '" 2>&1'
    [void](Invoke-RemoteCommandAndWait -Session $Session -CommandLine $queryCmd -MaxWaitSec 10)

    $driveName = $null
    $readPath = "\\$ComputerName\C$\Windows\Temp\$TaskName.csv"
    try {
        if ($Credential) {
            # UNC direct funcționează doar dacă identitatea Windows curentă a
            # operatorului are deja acces la C$ pe stație; dacă s-a dat un
            # cont de admin separat (-AdminUser), trebuie mapat explicit cu
            # acele credențiale.
            $driveName = "ITInvMsg" + (Get-Random -Maximum 9999)
            New-PSDrive -Name $driveName -PSProvider FileSystem -Root "\\$ComputerName\C$" `
                -Credential $Credential -Scope Script -ErrorAction Stop | Out-Null
            $readPath = "${driveName}:\Windows\Temp\$TaskName.csv"
        }

        $lines = Get-Content -LiteralPath $readPath -ErrorAction Stop
        if ($lines.Count -lt 2) { return $null }

        $headers = 1..28 | ForEach-Object { "c$_" }
        $row = $lines[1] | ConvertFrom-Csv -Header $headers
        return [int64]$row.c7
    } catch {
        return $null
    } finally {
        if ($driveName) { Remove-PSDrive -Name $driveName -ErrorAction SilentlyContinue }
        $deleteFileCmd = 'cmd.exe /c del /f /q "' + $remoteFile + '"'
        try {
            [void](Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create `
                -Arguments @{ CommandLine = $deleteFileCmd } -ErrorAction SilentlyContinue)
        } catch {}
    }
}

function ConvertTo-TaskResultDescription {
    # Doar cele mai frecvente coduri intalnite la actiuni de task Scheduler;
    # orice altceva ramane afisat ca numar brut, cu trimitere la Event Viewer.
    param([int64]$LastResult)
    switch ($LastResult) {
        -2147024894 { return "0x80070002 ERROR_FILE_NOT_FOUND - msg.exe nu a fost gasit in contextul sesiunii" }
        -2147024891 { return "0x80070005 ERROR_ACCESS_DENIED - drepturi insuficiente pentru actiune in acea sesiune" }
        -2147023554 { return "0x8007052E ERROR_LOGON_FAILURE - autentificare esuata pentru contul din /RU" }
        267011      { return "0x41303 SCHED_S_TASK_HAS_NOT_RUN - task-ul inca nu a apucat sa ruleze" }
        267009      { return "0x41301 SCHED_S_TASK_RUNNING - task-ul e inca in executie" }
        default     { return "cod necunoscut - verifica Event Viewer > Applications and Services Logs > Microsoft > Windows > TaskScheduler > Operational pe statie" }
    }
}

$session = $null
try {
    $opt = New-CimSessionOption -Protocol Dcom
    $sessionParams = @{ ComputerName = $ComputerName; SessionOption = $opt; ErrorAction = 'Stop' }
    if ($Credential) { $sessionParams['Credential'] = $Credential }
    $session = New-CimSession @sessionParams

    $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -ErrorAction Stop
    $loggedOnUser = $cs.UserName
    if ([string]::IsNullOrWhiteSpace($loggedOnUser)) {
        Write-Error "Nimeni logat interactiv pe $ComputerName in acest moment - mesajul nu poate fi livrat."
        exit 1
    }

    # Scoatem ghilimelele duble și înlocuim liniile noi cu un separator vizual
    # simplu — mesajul traversează DOUĂ niveluri de linie-de-comandă imbricate
    # (schtasks /TR conține el însuși comanda msg.exe), iar caractere de
    # control embedate cresc mult riscul de parsare greșită la al doilea nivel.
    $safeMessage = ($Message -replace '"', "'") -replace "(\r\n|\r|\n)", ' | '
    $msgCommandLine = 'msg.exe * "' + $safeMessage + '"'
    # Ghilimelele din interiorul comenzii msg.exe trebuie escapate (\") ca să
    # supraviețuiască ca literal quote-uri când schtasks.exe reparsează
    # valoarea /TR ca linie de comandă separată, la rularea task-ului.
    $trValue = $msgCommandLine -replace '"', '\"'

    $taskName = "ITInv-Msg-" + (Get-Random -Maximum 999999)

    try {
        $createCmd = 'schtasks.exe /Create /TN "' + $taskName + '" /TR "' + $trValue + '" ' +
            '/SC ONCE /ST 23:59 /RU "' + $loggedOnUser + '" /IT /RL LIMITED /F'
        $createResult = Invoke-RemoteCommandAndWait -Session $session -CommandLine $createCmd -MaxWaitSec 10
        if (-not $createResult.Started -or $createResult.StillRunning) {
            Write-Error "Crearea task-ului temporar de livrare a mesajului a esuat pe $ComputerName."
            exit 1
        }

        # /ST de mai sus e doar sintactic necesar pentru /SC ONCE — pornim
        # task-ul imediat, nu așteptăm ora programată.
        $runCmd = 'schtasks.exe /Run /TN "' + $taskName + '"'
        [void](Invoke-RemoteCommandAndWait -Session $session -CommandLine $runCmd -MaxWaitSec 10)
        $runStartTime = Get-Date

        # msg.exe pornit de task rulează acum ÎN sesiunea utilizatorului, nu ca
        # sub-proces al lui schtasks.exe. E un proces foarte scurt-trăitor
        # (fără /W, msg.exe trimite mesajul și iese aproape instant, uneori
        # sub 200ms) — o simplă sondare Win32_Process poate rata complet
        # fereastra chiar dacă livrarea a reușit. De-aia sondarea de mai jos
        # e doar un fast-path optimist (dacă prindem procesul, gata, e sigur
        # livrat); dacă nu-l prindem, NU tragem concluzia că a eșuat — cerem
        # semnalul autoritativ, Last Result-ul task-ului din Scheduler.
        $msgProc = $null
        $checkDeadline = (Get-Date).AddMilliseconds(1200)
        do {
            Start-Sleep -Milliseconds 200
            $msgProc = Get-CimInstance -CimSession $session -ClassName Win32_Process `
                -Filter "Name = 'msg.exe'" -ErrorAction SilentlyContinue
        } while (-not $msgProc -and (Get-Date) -lt $checkDeadline)

        if ($msgProc) {
            Write-Output ("OK - mesaj livrat catre $loggedOnUser pe $ComputerName (task interactiv temporar, " +
                "proces msg.exe prins in sondare).")
        } else {
            $lastResult = Get-RemoteTaskLastResult -Session $session -ComputerName $ComputerName `
                -TaskName $taskName -Credential $Credential

            if ($null -eq $lastResult) {
                Write-Error ("Task-ul a rulat pe $ComputerName dar nu s-a putut confirma daca msg.exe a pornit " +
                    "in sesiunea lui $loggedOnUser - nici procesul, nici Last Result-ul task-ului din Scheduler " +
                    "nu au putut fi citite (verifica accesul la share-ul C$ pe statie). Verifica manual ecranul " +
                    "statiei.")
                exit 1
            } elseif ($lastResult -eq 0) {
                Write-Output ("OK - mesaj livrat catre $loggedOnUser pe $ComputerName (task interactiv temporar, " +
                    "confirmat prin Last Result=0 al task-ului din Scheduler).")
            } else {
                $decoded = ConvertTo-TaskResultDescription -LastResult $lastResult
                Write-Error ("Task-ul a rulat pe $ComputerName dar actiunea (msg.exe) a esuat in sesiunea lui " +
                    "$loggedOnUser - Last Result=$lastResult ($decoded).")
                exit 1
            }
        }
    }
    finally {
        # Curățenie best-effort — task-ul nu trebuie să rămână pe stație
        # indiferent ce s-a întâmplat mai sus (vezi excepția din CLAUDE.md:
        # "nu lasă nimic persistent pe stație"). DAR: nu ștergem imediat.
        # Testat empiric (2026-09-02): fereastra msg.exe rămâne vizibilă
        # independent de procesul msg.exe (care oricum iese aproape instant),
        # DAR "schtasks /Delete /F" pe task-ul asociat închide fereastra încă
        # neconfirmată de utilizator, chiar dacă mesajul apucase deja să
        # apară — utilizatorul vede doar un flash. De-aia așteptăm un interval
        # de grație de $GraceSeconds de la Run înainte de Delete, ca mesajul
        # să aibă timp să fie citit; task-ul tot dispare de pe stație, doar
        # mai târziu, nu "imediat".
        if ($runStartTime) {
            $elapsedSec = ((Get-Date) - $runStartTime).TotalSeconds
            $remainingSec = $GraceSeconds - $elapsedSec
            if ($remainingSec -gt 0) { Start-Sleep -Seconds $remainingSec }
        }
        $deleteCmd = 'schtasks.exe /Delete /TN "' + $taskName + '" /F'
        try {
            [void](Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create `
                -Arguments @{ CommandLine = $deleteCmd } -ErrorAction SilentlyContinue)
        } catch {}
    }
}
finally {
    if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
}
