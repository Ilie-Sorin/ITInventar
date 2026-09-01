<#
    Send-StationMessage.ps1 — trimite un mesaj pop-up (msg.exe) sesiunilor
    logate pe o stație, apelat de app/messenger.py (POST /statie/<name>/mesaj
    din webapp.py, pornit doar de pe stația de administrare — vezi
    _restrict_sensitive_routes_to_localhost).

    La fel ca Collect-Inventory.ps1: comunicarea cu stația se face exclusiv
    prin CIM peste DCOM (New-CimSessionOption -Protocol Dcom), niciodată
    WSMan — vezi CLAUDE.md. Msg.exe e pornit LOCAL pe stația țintă, prin
    Win32_Process::Create, pentru că doar așa ajunge efectiv pe ecranul
    utilizatorului logat acolo; fără WinRM nu există altă cale de a arăta un
    pop-up de sesiune pe stația țintă. Necesită drepturi de administrator pe
    stația țintă (la fel ca Nivelul 2 al colectorului).

    Spre deosebire de colector, acest script NU e read-only — pornește
    intenționat un proces pe stația țintă; constrângerea "strict read-only"
    din CLAUDE.md privește colectarea automată de inventar, nu o acțiune
    explicită cerută de operator.
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

$session = $null
try {
    $opt = New-CimSessionOption -Protocol Dcom
    $sessionParams = @{ ComputerName = $ComputerName; SessionOption = $opt; ErrorAction = 'Stop' }
    if ($Credential) { $sessionParams['Credential'] = $Credential }
    $session = New-CimSession @sessionParams

    # Scoatem ghilimelele duble din mesaj (nu le escapăm) — un mesaj
    # administrativ scurt nu are nevoie de ele, iar CreateProcess (folosit de
    # Win32_Process::Create pe stația țintă) nu tratează escaping-ul de
    # ghilimele la fel ca cmd.exe, deci evităm ambiguitatea complet.
    $safeMessage = $Message -replace '"', "'"
    $commandLine = 'msg.exe * "' + $safeMessage + '"'

    $result = Invoke-CimMethod -CimSession $session -ClassName Win32_Process -MethodName Create `
        -Arguments @{ CommandLine = $commandLine } -ErrorAction Stop

    if ($result.ReturnValue -ne 0) {
        Write-Error "Win32_Process::Create a eșuat pe $ComputerName cu codul $($result.ReturnValue)."
        exit 1
    }

    Write-Output ("OK pid=" + $result.ProcessId)
}
finally {
    if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
}
