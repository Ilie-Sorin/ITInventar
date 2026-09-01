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
    dată imediat, apoi îl ștergem — totul rămâne pe firul CIM/DCOM deja
    deschis, fără alt protocol de la distanță, și nu lasă nimic persistent pe
    stație (vezi excepția documentată explicit în CLAUDE.md).

    Această acțiune NU e read-only — e o cerere explicită a operatorului, nu o
    colectare automată; constrângerea "strict read-only" din CLAUDE.md
    privește colectorul de inventariere (Collect-Inventory.ps1), nu asta.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ComputerName,
    [Parameter(Mandatory)] [string] $Message,
    [string] $AdminUser                     # opțional: cont de admin AD separat, ca la scanare
                                             # (parola vine pe stdin, nu ca argument — vezi mai jos)
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

        # msg.exe pornit de task rulează acum ÎN sesiunea utilizatorului, nu ca
        # sub-proces al lui schtasks.exe — verificăm separat, ca înainte,
        # dacă a apărut (semn că a ajuns efectiv pe ecran, nu doar că task-ul
        # s-a "rulat" cu succes la nivel de Scheduler). Sondăm de câteva ori
        # în loc de o singură citire la timp fix, ca variații mici de viteză
        # ale stației să nu dea fals-negativ.
        $msgProc = $null
        $checkDeadline = (Get-Date).AddSeconds(3)
        do {
            Start-Sleep -Milliseconds 400
            $msgProc = Get-CimInstance -CimSession $session -ClassName Win32_Process `
                -Filter "Name = 'msg.exe'" -ErrorAction SilentlyContinue
        } while (-not $msgProc -and (Get-Date) -lt $checkDeadline)

        if (-not $msgProc) {
            Write-Error ("Task-ul a rulat pe $ComputerName dar msg.exe nu pare sa fi pornit in sesiunea lui " +
                "$loggedOnUser - verifica daca utilizatorul e intr-adevar logat interactiv acolo chiar acum.")
            exit 1
        }

        Write-Output ("OK - mesaj livrat catre $loggedOnUser pe $ComputerName (task interactiv temporar).")
    }
    finally {
        # Curățenie best-effort — task-ul nu trebuie să rămână pe stație
        # indiferent ce s-a întâmplat mai sus (vezi excepția din CLAUDE.md:
        # "nu lasă nimic persistent pe stație").
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
