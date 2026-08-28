#Requires -Version 5.1
<#
    Collect-Inventory.ps1 — colectorul de inventar pentru pilotul AD.

    Descoperă stațiile dintr-un OU (și sub-OU-uri) din Active Directory, testează
    disponibilitatea prin TCP 445, apoi citește date prin CIM peste DCOM
    (Nivel 1) și, opțional, prin registry via StdRegProv (Nivel 2).

    Scrie o linie JSON compactă per stație pe STDOUT (NDJSON). Progresul și
    erorile merg pe STDERR, în format "PROGRESS <done>/<total> <hostname>",
    ca să poată fi citite separat de aplicația web (app/scanner.py).

    STRICT READ-ONLY: scriptul nu scrie, nu instalează, nu repornește și nu
    modifică nimic pe stațiile interogate. Win32_Product este interzis explicit
    (declanșează reconfigurare MSI pe stația țintă) — vezi criteriul de
    acceptanță #9 din SPEC_InventarAD.md.

    Fără WinRM: comunicarea se face exclusiv prin CIM peste DCOM
    (New-CimSessionOption -Protocol Dcom), niciodată WSMan.
#>

param(
    [ValidateSet(1, 2)] [int] $Level = 1,
    [string]   $OuBase,                     # gol = auto-detecție din OU-ul stației curente
    [int]      $Throughput = 12,
    [int]      $TcpProbeTimeoutMs = 400,
    [int]      $CimTimeoutSec = 45,
    [int]      $RegTimeoutSec = 60,
    [string[]] $ComputerName,                # opțional: listă explicită (pentru test)
    [switch]   $WhatIfDiscoveryOnly,          # doar interogarea AD, fără contact cu stațiile
    [System.Management.Automation.PSCredential]
               $Credential,                  # opțional: cont de admin AD, dacă diferă de sesiunea curentă
                                              # (folosit atât pentru Get-ADComputer/Get-ADOrganizationalUnit,
                                              # cât și pentru New-CimSession — vezi §5.2/§5.4 din spec)
    [switch]   $ListOusOnly,                  # doar listează OU-urile disponibile (DN + nr. stații), ca
                                               # ajutor la alegerea lui -OuBase; nu atinge nicio stație
    [string]   $AdminUser                     # opțional: alternativă la -Credential pentru apelul din
                                               # app/scanner.py — parola se citește de pe STDIN (o linie),
                                               # NICIODATĂ ca argument de linie de comandă (ar rămâne vizibilă
                                               # oricui vede command-line-ul procesului, ex. Task Manager /
                                               # Get-CimInstance Win32_Process). Vezi construcția $Credential
                                               # mai jos, imediat după deschiderea stdout/stderr.
)

$ErrorActionPreference = 'Stop'
$CollectorVersion = '1.0'

# STDOUT/STDERR trebuie să fie UTF-8 indiferent de codepage-ul consolei/sesiunii.
# [Console]::OutputEncoding nu e de încredere când fluxurile sunt redirecționate
# spre o conductă (cazul nostru: subprocess.Popen din scanner.py) — de-asta
# scriem direct pe handle-urile native printr-un StreamWriter cu encoding explicit,
# altfel diacriticele din mesajele de eroare/progres ies garbled la celălalt capăt.
$stdout = New-Object System.IO.StreamWriter(
    [Console]::OpenStandardOutput(),
    (New-Object System.Text.UTF8Encoding($false))
)
$stdout.AutoFlush = $true

$stderr = New-Object System.IO.StreamWriter(
    [Console]::OpenStandardError(),
    (New-Object System.Text.UTF8Encoding($false))
)
$stderr.AutoFlush = $true

if ($AdminUser -and -not $Credential) {
    # Mecanism de elevare pentru app/scanner.py: operatorul poate porni
    # serverul web cu un cont de domeniu obișnuit și totuși scana cu drepturi
    # de admin AD, dând user+parolă separat doar pentru scanare (§8 — "admin
    # pentru scanare, user pentru consultare"). Parola vine pe STDIN, scrisă
    # de scanner.py imediat după pornirea acestui proces — NU ca argument de
    # linie de comandă, care ar rămâne vizibil oricui inspectează procesul.
    $plainPassword = [Console]::In.ReadLine()
    if ($plainPassword) {
        $securePassword = ConvertTo-SecureString -String $plainPassword -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($AdminUser, $securePassword)
    }
    # Golim variabila cât mai devreme — nu elimină 100% urma din memoria
    # procesului, dar reduce fereastra în care parola în clar mai există undeva.
    $plainPassword = $null
}

function Write-NdjsonLine {
    # O linie JSON compactă per stație — contractul NDJSON cu app/ingest.py.
    param($Record)
    $json = $Record | ConvertTo-Json -Compress -Depth 6
    $stdout.WriteLine($json)
}

function Write-ProgressLine {
    # Format fix "PROGRESS <done>/<total> <hostname>", cerut de scanner.py pentru
    # a separa progresul de restul stderr-ului (care merge integral în logs\).
    param([int]$Done, [int]$Total, [string]$HostName)
    $stderr.WriteLine("PROGRESS $Done/$Total $HostName")
}

function ConvertTo-Iso8601 {
    # Toate timpii se salvează ca text ISO 8601 cu offset, fără conversii de fus —
    # exact ce cere §6 din spec, ca app/db.py să nu mai trebuiască să ghicească.
    param($DateTime)
    if ($null -eq $DateTime) { return $null }
    if ($DateTime -isnot [DateTime]) {
        try { $DateTime = [DateTime]$DateTime } catch { return $null }
    }
    if ($DateTime.Kind -eq [DateTimeKind]::Unspecified) {
        # CIM întoarce DateTime-uri fără fus explicit; le tratăm ca oră locală a
        # stației țintă — cea mai bună aproximare fără o interogare suplimentară.
        $DateTime = [DateTime]::SpecifyKind($DateTime, [DateTimeKind]::Local)
    }
    return $DateTime.ToString('yyyy-MM-ddTHH:mm:sszzz')
}

function ConvertTo-AdInfo {
    # Transformă rezultatul Get-ADComputer în obiectul "ad" din schema NDJSON (§5.7).
    param($Computer)
    $dn = $Computer.DistinguishedName
    $ouPath = $null
    if ($dn) {
        # ou_path derivat din DN: păstrăm doar lanțul de OU-uri (fără CN-ul
        # calculatorului și fără DC-uri), cel mai apropiat de rădăcină primul —
        # ex. "Sediu1/Contabilitate" pentru CN=PC01,OU=Contabilitate,OU=Sediu1,DC=...
        $ouParts = foreach ($seg in ($dn -split ',')) {
            if ($seg -match '^OU=(.+)$') { $Matches[1] }
        }
        if ($ouParts) {
            [array]::Reverse($ouParts)
            $ouPath = $ouParts -join '/'
        }
    }
    return @{
        name               = $Computer.Name
        dns_name           = $Computer.DNSHostName
        distinguished_name = $dn
        ou_path            = $ouPath
        description        = $Computer.Description
        os                 = $Computer.OperatingSystem
        os_version         = $Computer.OperatingSystemVersion
        last_logon         = if ($Computer.LastLogonDate) { ConvertTo-Iso8601 $Computer.LastLogonDate } else { $null }
    }
}

function Resolve-UserDisplayName {
    <#
        Traduce un login de forma "DOMENIU\popescu.ion" (cum vin logged_on_user
        din Win32_ComputerSystem.UserName și last_logged_on_user din registry,
        §5.5c) în numele afișat al persoanei (DisplayName din AD), ca interfața
        web să arate "Popescu Ion", nu contul tehnic.

        Rulează în firul PRINCIPAL (nu în runspace-urile de colectare CIM/DCOM):
        Get-ADUser e o interogare AD separată de contactul cu stația, iar modulul
        ActiveDirectory e deja încărcat aici (folosit și de Get-TargetComputers).
        $Cache evită o interogare AD per stație — de regulă mult mai puțini
        utilizatori unici decât stații într-un OU.
    #>
    param(
        [string] $UserIdentity,
        [System.Management.Automation.PSCredential] $Credential,
        [hashtable] $Cache
    )
    if (-not $UserIdentity) { return $null }

    # Get-ADUser -Identity acceptă sAMAccountName, nu formatul "domeniu\sam" —
    # păstrăm doar ultima bucată după backslash (funcționează și dacă nu există
    # backslash deloc, caz în care întoarce string-ul neschimbat).
    $sam = ($UserIdentity -split '\\')[-1]
    if (-not $sam) { return $null }
    if ($Cache.ContainsKey($sam)) { return $Cache[$sam] }

    $adParams = @{}
    if ($Credential) { $adParams['Credential'] = $Credential }
    try {
        $u = Get-ADUser -Identity $sam -Properties DisplayName @adParams -ErrorAction Stop
        $name = if ($u.DisplayName) { $u.DisplayName } else { $u.Name }
        $Cache[$sam] = $name
        return $name
    } catch {
        # Cont local (nu în AD), cont șters, sau eroare de interogare — nu
        # blocăm nimic, doar rămânem fără nume de afișat pentru acest login.
        $Cache[$sam] = $null
        return $null
    }
}

function Get-TargetComputers {
    # Sursa listei de stații: fie interogarea OU-ului (calea normală), fie
    # lista explicită -ComputerName (test pe 3-5 stații, per §11 pasul 2).
    param([string]$OuBase, [string[]]$ComputerNames, [System.Management.Automation.PSCredential]$Credential)

    $props = 'DNSHostName', 'OperatingSystem', 'OperatingSystemVersion', 'LastLogonDate', 'Description', 'whenCreated'
    # -Credential e opțional: dacă operatorul nu e logat pe stația de administrare
    # cu contul de admin de domeniu, îl poate da explicit aici, fără să schimbe
    # sesiunea Windows curentă. Split în hashtable ca să nu trimitem un parametru
    # $null explicit la cmdlet-urile AD (unele îl resping).
    $adParams = @{}
    if ($Credential) { $adParams['Credential'] = $Credential }

    if ($ComputerNames -and $ComputerNames.Count -gt 0) {
        foreach ($n in $ComputerNames) {
            try {
                $c = Get-ADComputer -Identity $n -Properties $props @adParams -ErrorAction Stop
                ConvertTo-AdInfo -Computer $c
            } catch {
                $stderr.WriteLine("AVERTISMENT: '$n' nu a fost găsit în AD ($($_.Exception.Message)) — se încearcă direct pe nume.")
                @{
                    name = $n; dns_name = $n; distinguished_name = $null; ou_path = $null
                    description = $null; os = $null; os_version = $null; last_logon = $null
                }
            }
        }
        return
    }

    $base = $OuBase
    if (-not $base) {
        # ou_base gol = auto-detecție: folosim OU-ul stației pe care rulează
        # aplicația (exact cum cere §4/§5.2 din spec).
        $me = Get-ADComputer $env:COMPUTERNAME @adParams -ErrorAction Stop
        $base = $me.DistinguishedName -replace '^CN=[^,]+,', ''
    }

    Get-ADComputer -SearchBase $base -SearchScope Subtree -Filter 'Enabled -eq $true' -Properties $props @adParams |
        ForEach-Object { ConvertTo-AdInfo -Computer $_ }
}

function Get-OuInventoryList {
    <#
        Listează OU-urile disponibile sub $Base (implicit rădăcina domeniului),
        cu DistinguishedName și numărul de stații active (Enabled) direct sub
        fiecare — ajutor pentru alegerea lui -OuBase la o rulare reală. Folosește
        doar interogări AD (Get-ADOrganizationalUnit / Get-ADComputer), fără
        niciun contact cu stațiile — la fel de "sigur" ca -WhatIfDiscoveryOnly.
    #>
    param([string]$Base, [System.Management.Automation.PSCredential]$Credential)

    $adParams = @{}
    if ($Credential) { $adParams['Credential'] = $Credential }

    if (-not $Base) {
        # Implicit: OU-ul stației curente, la fel ca auto-detecția din
        # Get-TargetComputers — NU rădăcina domeniului, ca să nu parcurgă tot
        # AD-ul (poate dura mult pe domenii mari). Pentru tot domeniul, se dă
        # explicit -OuBase cu DN-ul rădăcinii.
        $me = Get-ADComputer $env:COMPUTERNAME @adParams -ErrorAction Stop
        $Base = $me.DistinguishedName -replace '^CN=[^,]+,', ''
    }

    $ous = @(Get-ADOrganizationalUnit -SearchBase $Base -SearchScope Subtree -Filter * -Properties DistinguishedName @adParams -ErrorAction Stop)
    # Rădăcina ($Base) nu e ea însăși un obiect organizationalUnit dacă e chiar
    # rădăcina domeniului — o includem manual, ca opțiune "tot domeniul/subarborele".
    $allBases = @([PSCustomObject]@{ DistinguishedName = $Base }) + $ous

    foreach ($ou in $allBases) {
        $count = (Get-ADComputer -SearchBase $ou.DistinguishedName -SearchScope Subtree -Filter 'Enabled -eq $true' @adParams -ErrorAction Stop |
            Measure-Object).Count
        [PSCustomObject]@{
            StatiiActive      = $count
            DistinguishedName = $ou.DistinguishedName
        }
    }
}

function Test-Port445 {
    # Test de disponibilitate prin TCP pe portul 445, NU ICMP: pingul e frecvent
    # blocat de firewall, iar 445 confirmă totodată că stația e utilizabilă și
    # pentru admin share (folosit indirect de DCOM/CIM). Vezi §5.3.
    param([string]$ComputerName, [int]$TimeoutMs)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $connectTask = $client.ConnectAsync($ComputerName, 445)
        $finished = $connectTask.Wait($TimeoutMs)
        return ($finished -and $client.Connected)
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function ConvertFrom-ProductState {
    <#
        Decodare BEST-EFFORT a Win32_SecurityCenter2.AntiVirusProduct.productState.

        Nu există o specificație oficială Microsoft publicată pentru acest câmp;
        schema de mai jos e cea documentată empiric și larg folosită în scripturi
        de administrare (Security Center encodează starea AV-ului în trei octeți
        din valoarea pe 32 de biți). Conversia:
          1. productState -> hex pe 6 cifre (3 octeți relevanți)
          2. octetul din mijloc (poziții 2-3): bitul 0x10 = protecție în timp real activă
          3. octetul din dreapta (poziții 4-5): "00" = semnături la zi, altfel = vechi

        Nu tratați rezultatul ca infailibil — de-asta spec-ul cere să fie
        documentat explicit ca atare, aici și în interfață.
    #>
    param($ProductState)
    if ($null -eq $ProductState) {
        return @{ Enabled = $null; UpToDate = $null }
    }
    $hex = '{0:X6}' -f [int]$ProductState
    $realTimeByte  = $hex.Substring(2, 2)
    $signatureByte = $hex.Substring(4, 2)

    $rtValue = [Convert]::ToInt32($realTimeByte, 16)
    $enabled = (($rtValue -band 0x10) -ne 0)
    $upToDate = ($signatureByte -eq '00')

    return @{ Enabled = $enabled; UpToDate = $upToDate }
}

function Resolve-CollectionStatus {
    <#
        Traduce o excepție CIM/DCOM într-unul din codurile de stare din §5.6.
        0x80070005 (E_ACCESSDENIED) și 0x800706BA (RPC server unavailable) sunt
        cele două HRESULT-uri enumerate explicit în spec pentru refuz de acces
        sau firewall care blochează DCOM.

        Nu se poate conta mereu pe HResult-ul brut: uneori excepția reală
        (COM/DCOM) e împachetată de .NET într-o excepție generică al cărei
        HResult e codul generic COR_E_EXCEPTION (0x80131500), nu HRESULT-ul
        Win32 original — motiv verificat direct în teren (acces refuzat pe o
        stație unde contul care rula colectorul nu era admin local). De-asta
        se verifică ȘI textul mesajului ("Access is denied"), nu doar hex-ul.

        Orice altă eroare merge la WMI_ERROR ca fallback generic — mai bine
        un status vag decât unul greșit.
    #>
    param($Exception)
    # -band cu 0xFFFFFFFF izolează cei mai puțin semnificativi 32 de biți: HResult
    # e un Int32 (adesea negativ ca semn), iar PowerShell îl lărgește la Int64 cu
    # sign-extension înainte de -band, deci masca readuce valoarea pe 32 de biți.
    $hex = '0x{0:X8}' -f ($Exception.HResult -band 0xFFFFFFFF)
    if ($hex -in @('0x80070005', '0x800706BA') -or $Exception.Message -match '(?i)access\s+is\s+denied') {
        return 'RPC_DENIED'
    }
    if ($Exception.Message -match '(?i)time(d)?\s*-?out' -or $hex -eq '0x80338029') { return 'TIMEOUT' }
    return 'WMI_ERROR'
}

function Format-CollectionError {
    # error_message păstrează mesajul original ȘI codul HRESULT, netrunchiat (§5.6).
    param($Exception)
    $hex = '0x{0:X8}' -f ($Exception.HResult -band 0xFFFFFFFF)
    return "$($Exception.Message) (HRESULT: $hex)"
}

# ---------------------------------------------------------------------------
# StdRegProv — acces la registry de la distanță fără serviciul Remote Registry
# (dezactivat implicit pe Win10/11); StdRegProv merge direct prin WMI/DCOM.
# ---------------------------------------------------------------------------

function Get-RegSubKeyNames {
    # hDefKey=2147483650 e HKEY_LOCAL_MACHINE (0x80000002) — StdRegProv cere
    # rădăcina hive-ului ca număr, nu ca literal "HKLM".
    param($CimSession, [uint32]$Hive, [string]$Path, [int]$TimeoutSec)
    $r = Invoke-CimMethod -CimSession $CimSession -Namespace root\cimv2 -ClassName StdRegProv `
        -MethodName EnumKey -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path } `
        -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
    # ReturnValue 2 = cheia nu există; tratăm asta ca listă goală, nu ca eroare.
    if ($r.ReturnValue -ne 0) { return @() }
    return @($r.sNames)
}

function Get-RegStringValue {
    param($CimSession, [uint32]$Hive, [string]$Path, [string]$ValueName, [int]$TimeoutSec)
    $r = Invoke-CimMethod -CimSession $CimSession -Namespace root\cimv2 -ClassName StdRegProv `
        -MethodName GetStringValue -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path; sValueName = $ValueName } `
        -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
    if ($r.ReturnValue -ne 0) { return $null }
    return $r.sValue
}

function Get-RegDwordValue {
    param($CimSession, [uint32]$Hive, [string]$Path, [string]$ValueName, [int]$TimeoutSec)
    $r = Invoke-CimMethod -CimSession $CimSession -Namespace root\cimv2 -ClassName StdRegProv `
        -MethodName GetDWORDValue -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path; sValueName = $ValueName } `
        -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
    if ($r.ReturnValue -ne 0) { return $null }
    return $r.uValue
}

function Test-RegKeyExists {
    # Folosit pentru cheile-marker de reboot pending: existența cheii contează,
    # nu conținutul ei (deseori n-au nici subchei, nici valori).
    param($CimSession, [uint32]$Hive, [string]$Path, [int]$TimeoutSec)
    $r = Invoke-CimMethod -CimSession $CimSession -Namespace root\cimv2 -ClassName StdRegProv `
        -MethodName EnumKey -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path } `
        -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
    return ($r.ReturnValue -eq 0)
}

function Test-RegValueExists {
    # Pentru PendingFileRenameOperations (REG_MULTI_SZ): verificăm prezența
    # numelui în EnumValues, generic și fără să presupunem tipul valorii.
    param($CimSession, [uint32]$Hive, [string]$Path, [string]$ValueName, [int]$TimeoutSec)
    $r = Invoke-CimMethod -CimSession $CimSession -Namespace root\cimv2 -ClassName StdRegProv `
        -MethodName EnumValues -Arguments @{ hDefKey = $Hive; sSubKeyName = $Path } `
        -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
    if ($r.ReturnValue -ne 0) { return $false }
    return (@($r.sNames) -contains $ValueName)
}

function Get-Level1Snapshot {
    <#
        Nivel 1: toate interogările pe ACEEAȘI CimSession (deschisă de apelant),
        fiecare clasă în try/catch propriu — o clasă care eșuează nu oprește
        colectarea celorlalte, ci contribuie la un status PARTIAL în loc de OK.

        INTERZIS: Win32_Product. Declanșează reconfigurare MSI pe stația țintă
        și durează minute — softul instalat se citește exclusiv din registry,
        la Nivel 2 (Get-Level2Snapshot).
    #>
    param($CimSession, [int]$TimeoutSec)

    $result = @{
        System       = $null
        Os           = $null
        Network      = $null
        Disks        = @()
        Antivirus    = $null
        AntivirusAll = @()
        Errors       = New-Object System.Collections.Generic.List[string]
    }

    try {
        $cs = Get-CimInstance -CimSession $CimSession -ClassName Win32_ComputerSystem `
            -Property Manufacturer, Model, TotalPhysicalMemory, UserName, NumberOfLogicalProcessors, Domain `
            -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
        $bios = Get-CimInstance -CimSession $CimSession -ClassName Win32_BIOS `
            -Property SerialNumber, SMBIOSBIOSVersion, ReleaseDate `
            -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
        $cpu = Get-CimInstance -CimSession $CimSession -ClassName Win32_Processor `
            -Property Name -OperationTimeoutSec $TimeoutSec -ErrorAction Stop | Select-Object -First 1

        $result.System = @{
            manufacturer   = $cs.Manufacturer
            model          = $cs.Model
            serial_number  = $bios.SerialNumber
            bios_version   = $bios.SMBIOSBIOSVersion
            cpu_name       = $cpu.Name
            ram_total_mb   = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1MB) } else { $null }
            logged_on_user = $cs.UserName
        }
    } catch {
        $result.Errors.Add("Win32_ComputerSystem/BIOS/Processor: $($_.Exception.Message)")
    }

    try {
        $os = Get-CimInstance -CimSession $CimSession -ClassName Win32_OperatingSystem `
            -Property Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime, FreePhysicalMemory `
            -OperationTimeoutSec $TimeoutSec -ErrorAction Stop
        $uptimeDays = if ($os.LastBootUpTime) { [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 2) } else { $null }
        $result.Os = @{
            caption            = $os.Caption
            build              = $os.BuildNumber
            display_version    = $null   # completat la Nivel 2 din registry — Win32_OperatingSystem nu îl are
            ubr                = $null
            arch               = $os.OSArchitecture
            install_date       = ConvertTo-Iso8601 $os.InstallDate
            last_boot          = ConvertTo-Iso8601 $os.LastBootUpTime
            uptime_days        = $uptimeDays
        }
    } catch {
        $result.Errors.Add("Win32_OperatingSystem: $($_.Exception.Message)")
    }

    try {
        $nic = Get-CimInstance -CimSession $CimSession -ClassName Win32_NetworkAdapterConfiguration `
            -Filter 'IPEnabled = TRUE' -Property IPAddress, MACAddress, DHCPEnabled `
            -OperationTimeoutSec $TimeoutSec -ErrorAction Stop | Select-Object -First 1
        if ($nic) {
            $result.Network = @{
                ip_address   = if ($nic.IPAddress) { $nic.IPAddress[0] } else { $null }
                mac_address  = $nic.MACAddress
                dhcp_enabled = [bool]$nic.DHCPEnabled
            }
        }
    } catch {
        $result.Errors.Add("Win32_NetworkAdapterConfiguration: $($_.Exception.Message)")
    }

    try {
        $disks = @(Get-CimInstance -CimSession $CimSession -ClassName Win32_LogicalDisk `
            -Filter 'DriveType = 3' -Property DeviceID, VolumeName, Size, FreeSpace `
            -OperationTimeoutSec $TimeoutSec -ErrorAction Stop)
        foreach ($d in $disks) {
            $result.Disks += @{
                device_id   = $d.DeviceID
                volume_name = $d.VolumeName
                size_mb     = if ($d.Size) { [math]::Round($d.Size / 1MB) } else { $null }
                free_mb     = if ($d.FreeSpace) { [math]::Round($d.FreeSpace / 1MB) } else { $null }
            }
        }
    } catch {
        $result.Errors.Add("Win32_LogicalDisk: $($_.Exception.Message)")
    }

    try {
        # root\SecurityCenter2 e alt namespace, dar aceeași sesiune CIM/DCOM —
        # nu trebuie deschisă o conexiune separată pentru el.
        #
        # NU luăm doar primul rezultat (cum se făcea inițial): pot fi ÎNREGISTRATE
        # simultan mai multe produse — ex. Windows Defender + un AV terță parte
        # precum Bitdefender Endpoint Security Tools. Windows dezactivează de
        # regulă protecția în timp real a Defender-ului când alt AV preia rolul,
        # dar Defender rămâne înregistrat în Security Center ca produs
        # "dezactivat". Ordinea în care WMI le întoarce nu e garantată — dacă am
        # fi păstrat doar primul, am fi putut raporta exact acel Defender
        # dezactivat drept "singurul AV", declanșând o alertă av_disabled falsă
        # cât timp AV-ul terț chiar protejează stația (vezi alerts._check_av).
        $avProducts = @(Get-CimInstance -CimSession $CimSession -Namespace 'root\SecurityCenter2' `
            -ClassName AntiVirusProduct -Property displayName, productState, timestamp `
            -OperationTimeoutSec $TimeoutSec -ErrorAction Stop)
        foreach ($av in $avProducts) {
            $state = ConvertFrom-ProductState -ProductState $av.productState
            $sigDate = $null
            if ($av.timestamp) {
                try {
                    # AntiVirusProduct.timestamp e în format WMI DATETIME (CIM_DATETIME),
                    # de-asta trece prin ManagementDateTimeConverter și nu prin cast direct.
                    $sigDate = ConvertTo-Iso8601 ([System.Management.ManagementDateTimeConverter]::ToDateTime($av.timestamp))
                } catch { }
            }
            $result.AntivirusAll += @{
                name           = $av.displayName
                enabled        = $state.Enabled
                up_to_date     = $state.UpToDate
                signature_date = $sigDate
            }
        }
        if ($result.AntivirusAll.Count -gt 0) {
            # "Antivirus" (singular) rămâne pentru compatibilitate cu coloanele
            # simple din UI/CSV (av_name/av_enabled/...): alegem produsul cel mai
            # relevant — unul cu protecție activă în locul unuia dezactivat, și
            # între mai multe active, unul cu semnături la zi — ca rezumatul
            # compact să arate AV-ul care chiar protejează stația. Lista completă
            # rămâne în "AntivirusAll" (=> antivirus_all în NDJSON), folosită de
            # alertare și de pagina detaliată a stației.
            $result.Antivirus = $result.AntivirusAll |
                Sort-Object -Property @{Expression = { if ($_.enabled) { 0 } else { 1 } }},
                                       @{Expression = { if ($_.up_to_date) { 0 } else { 1 } }} |
                Select-Object -First 1
        }
    } catch {
        $result.Errors.Add("AntiVirusProduct: $($_.Exception.Message)")
    }

    return $result
}

function Get-Level2Snapshot {
    <#
        Nivel 2: refolosește sesiunea CIM deja deschisă, citește prin StdRegProv.
        Fiecare bloc (a-e din §5.5) e izolat în propriul try/catch, la fel ca la
        Nivel 1 — un bloc eșuat nu oprește restul, doar contribuie la PARTIAL.

        Enumerarea software-ului (bloc a) e partea cea mai costisitoare — zeci
        de subchei × 4 valori fiecare — motiv pentru care apelantul măsoară
        separat durata acestui bloc (duration_reg_ms) față de blocul CIM.
    #>
    param($CimSession, [int]$TimeoutSec)

    $HKLM = [uint32]2147483650   # 0x80000002 — HKEY_LOCAL_MACHINE, cerut de StdRegProv ca număr

    $result = @{
        OsDisplayVersion = $null
        OsUbr            = $null
        LastLoggedOnUser = $null
        RebootPending    = $false
        WuLastSuccess    = $null
        Software         = New-Object System.Collections.Generic.List[hashtable]
        Errors           = New-Object System.Collections.Generic.List[string]
    }

    # b) Versiunea reală a OS-ului — nu se poate obține din Win32_OperatingSystem.
    try {
        $verKey = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $result.OsDisplayVersion = Get-RegStringValue -CimSession $CimSession -Hive $HKLM -Path $verKey -ValueName 'DisplayVersion' -TimeoutSec $TimeoutSec
        $result.OsUbr = Get-RegDwordValue -CimSession $CimSession -Hive $HKLM -Path $verKey -ValueName 'UBR' -TimeoutSec $TimeoutSec
    } catch {
        $result.Errors.Add("CurrentVersion (DisplayVersion/UBR): $($_.Exception.Message)")
    }

    # c) Ultimul utilizator logat — util când nimeni nu e logat la momentul
    # scanării, situație în care Win32_ComputerSystem.UserName e gol.
    try {
        $result.LastLoggedOnUser = Get-RegStringValue -CimSession $CimSession -Hive $HKLM `
            -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI' `
            -ValueName 'LastLoggedOnSAMUser' -TimeoutSec $TimeoutSec
    } catch {
        $result.Errors.Add("LogonUI LastLoggedOnSAMUser: $($_.Exception.Message)")
    }

    # d) Reboot în așteptare — adevărat dacă oricare din cele trei semnale există.
    try {
        $rp1 = Test-RegKeyExists -CimSession $CimSession -Hive $HKLM -TimeoutSec $TimeoutSec `
            -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        $rp2 = Test-RegKeyExists -CimSession $CimSession -Hive $HKLM -TimeoutSec $TimeoutSec `
            -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
        $rp3 = Test-RegValueExists -CimSession $CimSession -Hive $HKLM -TimeoutSec $TimeoutSec `
            -Path 'SYSTEM\CurrentControlSet\Control\Session Manager' -ValueName 'PendingFileRenameOperations'
        $result.RebootPending = [bool]($rp1 -or $rp2 -or $rp3)
    } catch {
        $result.Errors.Add("RebootPending: $($_.Exception.Message)")
    }

    # e) Ultima actualizare Windows reușită.
    try {
        $wuValue = Get-RegStringValue -CimSession $CimSession -Hive $HKLM -TimeoutSec $TimeoutSec `
            -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install' `
            -ValueName 'LastSuccessTime'
        if ($wuValue) {
            try { $result.WuLastSuccess = ConvertTo-Iso8601 ([DateTime]::Parse($wuValue)) }
            catch { $result.WuLastSuccess = $wuValue }   # format neașteptat — păstrăm textul brut mai bine decât nimic
        }
    } catch {
        $result.Errors.Add("WindowsUpdate LastSuccessTime: $($_.Exception.Message)")
    }

    # a) Software instalat — din ambele ramuri (64-bit nativ + Wow6432Node pentru 32-bit).
    $branches = @(
        @{ Path = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'machine' }
        @{ Path = 'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'machine_x86' }
    )
    foreach ($branch in $branches) {
        try {
            $subKeys = Get-RegSubKeyNames -CimSession $CimSession -Hive $HKLM -Path $branch.Path -TimeoutSec $TimeoutSec
            foreach ($sk in $subKeys) {
                $subPath = "$($branch.Path)\$sk"
                $displayName = Get-RegStringValue -CimSession $CimSession -Hive $HKLM -Path $subPath -ValueName 'DisplayName' -TimeoutSec $TimeoutSec
                if (-not $displayName) { continue }   # exclus: fără DisplayName (§5.5a)

                $systemComponent = Get-RegDwordValue -CimSession $CimSession -Hive $HKLM -Path $subPath -ValueName 'SystemComponent' -TimeoutSec $TimeoutSec
                if ($systemComponent -eq 1) { continue }   # exclus: componentă de sistem, nu produs instalat

                $parentKeyName = Get-RegStringValue -CimSession $CimSession -Hive $HKLM -Path $subPath -ValueName 'ParentKeyName' -TimeoutSec $TimeoutSec
                if ($parentKeyName) { continue }   # exclus: update inclus în alt produs

                $result.Software.Add(@{
                    name         = $displayName
                    version      = Get-RegStringValue -CimSession $CimSession -Hive $HKLM -Path $subPath -ValueName 'DisplayVersion' -TimeoutSec $TimeoutSec
                    publisher    = Get-RegStringValue -CimSession $CimSession -Hive $HKLM -Path $subPath -ValueName 'Publisher' -TimeoutSec $TimeoutSec
                    install_date = Get-RegStringValue -CimSession $CimSession -Hive $HKLM -Path $subPath -ValueName 'InstallDate' -TimeoutSec $TimeoutSec
                    scope        = $branch.Scope
                    user         = $null
                })
            }
        } catch {
            $result.Errors.Add("Uninstall ($($branch.Path)): $($_.Exception.Message)")
        }
    }

    # f) Software instalat PER UTILIZATOR — instalări care scriu doar în hive-ul
    # utilizatorului (HKEY_CURRENT_USER), nu în HKLM, deci invizibile la blocul (a)
    # de mai sus. StdRegProv nu are un HKEY_CURRENT_USER separat de conceptul de
    # sesiune curentă a apelantului (n-are sens la distanță) — dar fiecare profil
    # logat își montează hive-ul (NTUSER.DAT) sub HKEY_USERS\<SID> cât timp
    # utilizatorul e logat, iar StdRegProv POATE adresa HKEY_USERS direct
    # (hDefKey = 2147483651 / 0x80000003). De-asta citim de acolo, nu din HKCU.
    #
    # LIMITARE CUNOSCUTĂ (best-effort, ca și decodarea productState mai sus):
    # un profil offline (utilizator delogat) nu are hive-ul montat și NU apare
    # aici — nu există o cale read-only de a-l citi fără WinRM/agent (montarea
    # manuală a NTUSER.DAT ar însemna o scriere pe stația țintă, interzisă de
    # regula strict read-only). În practică se văd userii logați la momentul
    # scanării — suficient pentru pilot, dar de documentat explicit în UI.
    $HKU = [uint32]2147483651   # 0x80000003 — HKEY_USERS

    try {
        # Numele de utilizator nu se poate citi din HKEY_USERS (hive-ul unui SID
        # nu-și cunoaște propriul nume) — se rezolvă separat din ProfileList,
        # care mapează SID -> ProfileImagePath (ex. "C:\Users\popescu.ion") încă
        # din HKLM, deci disponibil indiferent dacă hive-ul e încărcat sau nu.
        $profileMap = @{}
        $profileListPath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        $profileSids = Get-RegSubKeyNames -CimSession $CimSession -Hive $HKLM -Path $profileListPath -TimeoutSec $TimeoutSec
        foreach ($psid in $profileSids) {
            $imagePath = Get-RegStringValue -CimSession $CimSession -Hive $HKLM `
                -Path "$profileListPath\$psid" -ValueName 'ProfileImagePath' -TimeoutSec $TimeoutSec
            if ($imagePath) {
                $profileMap[$psid] = ($imagePath -split '\\')[-1]
            }
        }

        # sSubKeyName = '' enumeră rădăcina hive-ului (aici HKEY_USERS), la fel
        # cum am enumera rădăcina HKLM — StdRegProv tratează hDefKey ca hive-ul
        # de pornit, nu ca o cheie anume.
        $loadedSids = Get-RegSubKeyNames -CimSession $CimSession -Hive $HKU -Path '' -TimeoutSec $TimeoutSec
        foreach ($sid in $loadedSids) {
            # Excludem: hive-urile "..._Classes" (doar cache de asociere de
            # fișiere per utilizator, nu un profil separat), ".DEFAULT" și
            # conturile de serviciu S-1-5-18/19/20 (SYSTEM/LOCAL/NETWORK
            # SERVICE) — niciunul dintre acestea nu e un "utilizator" în
            # sensul cerut aici. Păstrăm doar SID-uri de cont normal
            # (S-1-5-21-...), fie de domeniu, fie local.
            if ($sid -match '_Classes$') { continue }
            if ($sid -in @('.DEFAULT', 'S-1-5-18', 'S-1-5-19', 'S-1-5-20')) { continue }
            if ($sid -notmatch '^S-1-5-21-') { continue }

            $userName = if ($profileMap.ContainsKey($sid)) { $profileMap[$sid] } else { $sid }
            $uninstallPath = "$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall"
            try {
                $subKeys = Get-RegSubKeyNames -CimSession $CimSession -Hive $HKU -Path $uninstallPath -TimeoutSec $TimeoutSec
                foreach ($sk in $subKeys) {
                    $subPath = "$uninstallPath\$sk"
                    $displayName = Get-RegStringValue -CimSession $CimSession -Hive $HKU -Path $subPath -ValueName 'DisplayName' -TimeoutSec $TimeoutSec
                    if (-not $displayName) { continue }

                    $systemComponent = Get-RegDwordValue -CimSession $CimSession -Hive $HKU -Path $subPath -ValueName 'SystemComponent' -TimeoutSec $TimeoutSec
                    if ($systemComponent -eq 1) { continue }

                    $parentKeyName = Get-RegStringValue -CimSession $CimSession -Hive $HKU -Path $subPath -ValueName 'ParentKeyName' -TimeoutSec $TimeoutSec
                    if ($parentKeyName) { continue }

                    $result.Software.Add(@{
                        name         = $displayName
                        version      = Get-RegStringValue -CimSession $CimSession -Hive $HKU -Path $subPath -ValueName 'DisplayVersion' -TimeoutSec $TimeoutSec
                        publisher    = Get-RegStringValue -CimSession $CimSession -Hive $HKU -Path $subPath -ValueName 'Publisher' -TimeoutSec $TimeoutSec
                        install_date = Get-RegStringValue -CimSession $CimSession -Hive $HKU -Path $subPath -ValueName 'InstallDate' -TimeoutSec $TimeoutSec
                        scope        = 'user'
                        user         = $userName
                    })
                }
            } catch {
                $result.Errors.Add("Uninstall per utilizator ($sid): $($_.Exception.Message)")
            }
        }
    } catch {
        $result.Errors.Add("Software per utilizator (HKEY_USERS/ProfileList): $($_.Exception.Message)")
    }

    return $result
}

function Invoke-StationCollection {
    <#
        Orchestrează colectarea pentru o singură stație: probă TCP, sesiune
        CIM/DCOM, Nivel 1, opțional Nivel 2. Întoarce hashtable-ul gata de
        serializat ca o linie NDJSON (schema §5.7).

        Statusul rezultă din combinarea a două surse posibile de eșec:
          - eșec la deschiderea sesiunii CIM sau la prima interogare (probă de
            conectivitate reală) => RPC_DENIED / TIMEOUT / WMI_ERROR, fără date
          - una sau mai multe clase/chei individuale eșuează, dar sesiunea a
            funcționat => PARTIAL, cu datele obținute salvate
    #>
    param(
        [hashtable] $AdInfo,
        [int]       $Level,
        [int]       $TcpProbeTimeoutMs,
        [int]       $CimTimeoutSec,
        [int]       $RegTimeoutSec,
        [System.Management.Automation.PSCredential] $Credential
    )

    $record = @{
        schema          = 1
        level           = $Level
        collected_at    = $null
        status          = $null
        error_message   = $null
        duration_cim_ms = $null
        duration_reg_ms = $null
        ad              = $AdInfo
        system          = $null
        os              = $null
        network         = $null
        disks           = @()
        antivirus       = $null
        antivirus_all   = @()
        registry        = $null
    }

    $name = $AdInfo.dns_name
    if (-not $name) { $name = $AdInfo.name }

    if (-not (Test-Port445 -ComputerName $name -TimeoutMs $TcpProbeTimeoutMs)) {
        $record.status = 'OFFLINE'
        $record.collected_at = ConvertTo-Iso8601 (Get-Date)
        return $record
    }

    $session = $null
    $cimSw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $opt = New-CimSessionOption -Protocol Dcom
        $sessionParams = @{
            ComputerName        = $name
            SessionOption       = $opt
            OperationTimeoutSec = $CimTimeoutSec
            ErrorAction         = 'Stop'
        }
        # -Credential opțional: contul de admin AD dat la linia de comandă, dacă
        # diferă de sesiunea Windows curentă (vezi -Credential la nivelul scriptului).
        if ($Credential) { $sessionParams['Credential'] = $Credential }
        $session = New-CimSession @sessionParams

        # Probă de conectivitate reală: New-CimSession peste DCOM nu garantează
        # mereu validarea imediată a canalului — primul query efectiv e cel care
        # scoate la iveală RPC_DENIED/TIMEOUT dacă stația refuză conexiunea.
        # O lăsăm în afara Get-Level1Snapshot ca eșecul ei să însemne "stația
        # nu răspunde deloc", nu doar "o clasă WMI a eșuat" (=> PARTIAL greșit).
        [void](Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem -Property Name -OperationTimeoutSec $CimTimeoutSec -ErrorAction Stop)

        $l1 = Get-Level1Snapshot -CimSession $session -TimeoutSec $CimTimeoutSec
        $cimSw.Stop()
        $record.duration_cim_ms = [int]$cimSw.Elapsed.TotalMilliseconds

        $record.system = $l1.System
        $record.os = $l1.Os
        $record.network = $l1.Network
        $record.disks = $l1.Disks
        $record.antivirus = $l1.Antivirus
        $record.antivirus_all = $l1.AntivirusAll

        $errs = New-Object System.Collections.Generic.List[string]
        $errs.AddRange($l1.Errors)

        if ($Level -eq 2) {
            $regSw = [System.Diagnostics.Stopwatch]::StartNew()
            $l2 = Get-Level2Snapshot -CimSession $session -TimeoutSec $RegTimeoutSec
            $regSw.Stop()
            $record.duration_reg_ms = [int]$regSw.Elapsed.TotalMilliseconds

            if ($record.os) {
                $record.os.display_version = $l2.OsDisplayVersion
                $record.os.ubr = $l2.OsUbr
            }
            $record.registry = @{
                last_logged_on_user = $l2.LastLoggedOnUser
                reboot_pending      = $l2.RebootPending
                wu_last_success     = $l2.WuLastSuccess
                software            = @($l2.Software)
            }
            $errs.AddRange($l2.Errors)
        }

        $record.status = if ($errs.Count -gt 0) { 'PARTIAL' } else { 'OK' }
        if ($errs.Count -gt 0) { $record.error_message = ($errs -join ' | ') }
    } catch {
        if ($cimSw.IsRunning) { $cimSw.Stop() }
        $record.duration_cim_ms = [int]$cimSw.Elapsed.TotalMilliseconds
        $record.status = Resolve-CollectionStatus -Exception $_.Exception
        $record.error_message = Format-CollectionError -Exception $_.Exception
    } finally {
        if ($session) { Remove-CimSession -CimSession $session -ErrorAction SilentlyContinue }
    }

    $record.collected_at = ConvertTo-Iso8601 (Get-Date)
    return $record
}

# ---------------------------------------------------------------------------
# Corpul principal al scriptului
# ---------------------------------------------------------------------------

try {
    if ($ListOusOnly) {
        # Mod separat de descoperire, pentru operator SAU pentru aplicația web
        # (ruta /ous, folosită de selectorul de OU din antet): listează
        # OU-ul de bază + sub-OU-urile lui, cu DN și nr. de stații active,
        # ca să se aleagă -OuBase la rularea reală. O linie JSON compactă
        # per OU pe stdout — schemă proprie (distinguished_name/station_count),
        # DISTINCTĂ de NDJSON-ul de stații; nu face parte din contractul cu
        # app/ingest.py, dar e tot JSON ca să poată fi parsată programatic.
        Get-OuInventoryList -Base $OuBase -Credential $Credential |
            Sort-Object DistinguishedName |
            ForEach-Object {
                $line = [ordered]@{
                    distinguished_name = $_.DistinguishedName
                    station_count      = $_.StatiiActive
                } | ConvertTo-Json -Compress
                $stdout.WriteLine($line)
            }
        exit 0
    }

    $computers = @(Get-TargetComputers -OuBase $OuBase -ComputerNames $ComputerName -Credential $Credential)
    $total = $computers.Count

    if ($WhatIfDiscoveryOnly) {
        # Doar descoperirea AD, fără niciun contact cu stațiile — criteriul de
        # acceptanță #1 cere sub 5 secunde pentru asta.
        $done = 0
        foreach ($ad in $computers) {
            $rec = @{
                schema = 1; level = $Level; collected_at = (ConvertTo-Iso8601 (Get-Date)); status = 'AD_ONLY'
                error_message = $null; duration_cim_ms = $null; duration_reg_ms = $null
                ad = $ad; system = $null; os = $null; network = $null; disks = @()
                antivirus = $null; antivirus_all = @(); registry = $null
            }
            Write-NdjsonLine $rec
            $done++
            Write-ProgressLine -Done $done -Total $total -HostName $ad.name
        }
        exit 0
    }

    if ($total -eq 0) {
        Write-ProgressLine -Done 0 -Total 0 -HostName '(nicio stație găsită)'
        exit 0
    }

    # Funcțiile folosite în interiorul fiecărui runspace trebuie înregistrate
    # explicit în InitialSessionState — runspace-urile nu moștenesc scope-ul
    # scriptului părinte. RunspacePool în loc de Start-Job: mult mai rapid
    # pentru sute de stații (fără overhead-ul unui proces nou per job).
    $workerFunctions = @(
        'ConvertTo-Iso8601', 'Test-Port445', 'ConvertFrom-ProductState',
        'Resolve-CollectionStatus', 'Format-CollectionError',
        'Get-RegSubKeyNames', 'Get-RegStringValue', 'Get-RegDwordValue',
        'Test-RegKeyExists', 'Test-RegValueExists',
        'Get-Level1Snapshot', 'Get-Level2Snapshot', 'Invoke-StationCollection'
    )
    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($fn in $workerFunctions) {
        $body = (Get-Item "function:$fn").ScriptBlock
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn, $body)))
    }

    $maxThreads = [Math]::Max(1, $Throughput)
    $pool = [runspacefactory]::CreateRunspacePool(1, $maxThreads, $iss, $Host)
    $pool.Open()

    try {
        $jobs = New-Object System.Collections.Generic.List[object]
        foreach ($ad in $computers) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $pool
            [void]$ps.AddScript({
                param($AdInfo, $Level, $TcpMs, $CimSec, $RegSec, $Cred)
                Invoke-StationCollection -AdInfo $AdInfo -Level $Level `
                    -TcpProbeTimeoutMs $TcpMs -CimTimeoutSec $CimSec -RegTimeoutSec $RegSec -Credential $Cred
            }).AddArgument($ad).AddArgument($Level).AddArgument($TcpProbeTimeoutMs).AddArgument($CimTimeoutSec).AddArgument($RegTimeoutSec).AddArgument($Credential)

            $jobs.Add([PSCustomObject]@{
                Pipeline = $ps
                Handle   = $ps.BeginInvoke()
                Name     = $ad.name
            })
        }

        # Interogăm periodic care runspace-uri s-au terminat, în loc să așteptăm
        # în ordinea în care au fost pornite — altfel o stație lentă ar bloca
        # afișarea rezultatelor deja gata, contrazicând cerința de progres live.
        $pending = New-Object System.Collections.Generic.List[object]
        $pending.AddRange($jobs)
        $done = 0
        # Cache SAM -> DisplayName pentru Resolve-UserDisplayName, populat pe
        # măsură ce vin rezultatele — vezi comentariul funcției pentru de ce
        # rulează aici (fir principal), nu în runspace-urile de colectare.
        $userDisplayNameCache = @{}
        while ($pending.Count -gt 0) {
            $finished = @($pending | Where-Object { $_.Handle.IsCompleted })
            if ($finished.Count -eq 0) {
                Start-Sleep -Milliseconds 100
                continue
            }
            foreach ($job in $finished) {
                try {
                    $results = $job.Pipeline.EndInvoke($job.Handle)
                    foreach ($rec in $results) {
                        if ($rec.system -and $rec.system.logged_on_user) {
                            $rec.system.logged_on_user_display_name = Resolve-UserDisplayName `
                                -UserIdentity $rec.system.logged_on_user -Credential $Credential -Cache $userDisplayNameCache
                        }
                        if ($rec.registry -and $rec.registry.last_logged_on_user) {
                            $rec.registry.last_logged_on_user_display_name = Resolve-UserDisplayName `
                                -UserIdentity $rec.registry.last_logged_on_user -Credential $Credential -Cache $userDisplayNameCache
                        }
                        Write-NdjsonLine $rec
                    }
                } catch {
                    # Excepție nemanevrată în runspace (neașteptat) — nu blocăm restul scanării.
                    $errRec = @{
                        schema = 1; level = $Level; collected_at = (ConvertTo-Iso8601 (Get-Date)); status = 'WMI_ERROR'
                        error_message = $_.Exception.Message; duration_cim_ms = $null; duration_reg_ms = $null
                        ad = @{ name = $job.Name }; system = $null; os = $null; network = $null
                        disks = @(); antivirus = $null; antivirus_all = @(); registry = $null
                    }
                    Write-NdjsonLine $errRec
                } finally {
                    $job.Pipeline.Dispose()
                }
                $done++
                Write-ProgressLine -Done $done -Total $total -HostName $job.Name
                [void]$pending.Remove($job)
            }
        }
    } finally {
        $pool.Close()
        $pool.Dispose()
    }
} finally {
    $stdout.Flush()
    $stdout.Dispose()
    $stderr.Flush()
    $stderr.Dispose()
}
