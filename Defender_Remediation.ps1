#requires -Version 5.1
# Defender / Windows Security Center race-condition detector and remediation
# Run elevated or as SYSTEM.

[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$DefenderGuid = '{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}'
$WscRegPath   = "HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av\$DefenderGuid"

# Exact productState values observed during this issue.
$BrokenState  = [uint32]0x060100
$HealthyState = [uint32]0x061100

$LogRoot = 'C:\ProgramData\DefenderWscRace'
$LogFile = Join-Path -Path $LogRoot -ChildPath 'DefenderWscRace.log'

try {
    New-Item -Path $LogRoot -ItemType Directory -Force -ErrorAction Stop |
        Out-Null
}
catch {
    Write-Output "Unable to create log directory '$LogRoot': $($_.Exception.Message)"
    exit 1
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $Line = '{0}  {1}' -f $Timestamp, $Message

    Write-Output $Line

    try {
        Add-Content `
            -LiteralPath $LogFile `
            -Value $Line `
            -Encoding UTF8 `
            -ErrorAction Stop
    }
    catch {
        Write-Output "Unable to write to log file '$LogFile': $($_.Exception.Message)"
    }
}

function Convert-ToHexState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return 'N/A'
    }

    try {
        $NumericValue = [uint32]$Value
        return ('0x{0:X6}' -f $NumericValue)
    }
    catch {
        return 'INVALID'
    }
}

function Get-DefenderWscState {
    [CmdletBinding()]
    param()

    $Mp            = $null
    $Wmi           = $null
    $RegistryState = $null
    $WscStatus     = $null

    try {
        $Mp = Get-MpComputerStatus -ErrorAction Stop
    }
    catch {
        Write-Log "Get-MpComputerStatus failed: $($_.Exception.Message)"
    }

    try {
        $WmiProducts = Get-CimInstance `
            -Namespace 'root\SecurityCenter2' `
            -ClassName 'AntiVirusProduct' `
            -ErrorAction Stop

        $Wmi = $WmiProducts |
            Where-Object {
                $_.instanceGuid -ieq $DefenderGuid -or
                $_.displayName -match 'Microsoft Defender|Windows Defender'
            } |
            Select-Object -First 1
    }
    catch {
        Write-Log "SecurityCenter2 query failed: $($_.Exception.Message)"
    }

    try {
        if (Test-Path -LiteralPath $WscRegPath) {
            $RegistryProperties = Get-ItemProperty `
                -LiteralPath $WscRegPath `
                -Name 'STATE' `
                -ErrorAction Stop

            $RegistryState = $RegistryProperties.STATE
        }
    }
    catch {
        Write-Log "Security Center registry query failed: $($_.Exception.Message)"
    }

    try {
        $WscService = Get-Service -Name 'wscsvc' -ErrorAction Stop
        $WscStatus = $WscService.Status
    }
    catch {
        Write-Log "Unable to query wscsvc: $($_.Exception.Message)"
    }

    $AMRunningMode             = $null
    $AMServiceEnabled          = $null
    $AntivirusEnabled          = $null
    $RealTimeProtectionEnabled = $null
    $PlatformVersion           = $null
    $SignatureVersion          = $null

    if ($null -ne $Mp) {
        $AMRunningMode             = $Mp.AMRunningMode
        $AMServiceEnabled          = $Mp.AMServiceEnabled
        $AntivirusEnabled          = $Mp.AntivirusEnabled
        $RealTimeProtectionEnabled = $Mp.RealTimeProtectionEnabled
        $PlatformVersion           = $Mp.AMProductVersion
        $SignatureVersion          = $Mp.AntivirusSignatureVersion
    }

    $WmiDisplayName  = $null
    $WmiProductState = $null

    if ($null -ne $Wmi) {
        $WmiDisplayName  = $Wmi.displayName
        $WmiProductState = $Wmi.productState
    }

    [PSCustomObject]@{
        AMRunningMode             = $AMRunningMode
        AMServiceEnabled          = $AMServiceEnabled
        AntivirusEnabled          = $AntivirusEnabled
        RealTimeProtectionEnabled = $RealTimeProtectionEnabled
        PlatformVersion           = $PlatformVersion
        SignatureVersion          = $SignatureVersion

        WmiDisplayName            = $WmiDisplayName
        WmiProductState           = $WmiProductState
        WmiProductStateHex        = Convert-ToHexState -Value $WmiProductState

        RegistryState             = $RegistryState
        RegistryStateHex          = Convert-ToHexState -Value $RegistryState

        WscServiceStatus          = $WscStatus
    }
}

function Test-DefenderReallyOn {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    return (
        $State.AMServiceEnabled -eq $true -and
        $State.AntivirusEnabled -eq $true -and
        $State.RealTimeProtectionEnabled -eq $true -and
        $State.AMRunningMode -eq 'Normal'
    )
}

function Test-WscBroken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    $WmiBroken      = $false
    $RegistryBroken = $false

    if ($null -ne $State.WmiProductState) {
        try {
            $WmiBroken = (
                [uint32]$State.WmiProductState -eq $BrokenState
            )
        }
        catch {
            $WmiBroken = $false
        }
    }

    if ($null -ne $State.RegistryState) {
        try {
            $RegistryBroken = (
                [uint32]$State.RegistryState -eq $BrokenState
            )
        }
        catch {
            $RegistryBroken = $false
        }
    }

    return ($WmiBroken -or $RegistryBroken)
}

function Test-WscHealthy {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$State
    )

    $WmiHealthy      = $false
    $RegistryHealthy = $false

    if ($null -ne $State.WmiProductState) {
        try {
            $WmiHealthy = (
                [uint32]$State.WmiProductState -eq $HealthyState
            )
        }
        catch {
            $WmiHealthy = $false
        }
    }

    if ($null -ne $State.RegistryState) {
        try {
            $RegistryHealthy = (
                [uint32]$State.RegistryState -eq $HealthyState
            )
        }
        catch {
            $RegistryHealthy = $false
        }
    }

    return ($WmiHealthy -and $RegistryHealthy)
}

function Get-MpCmdRunPath {
    [CmdletBinding()]
    param()

    $PlatformRoot = Join-Path `
        -Path $env:ProgramData `
        -ChildPath 'Microsoft\Windows Defender\Platform'

    if (Test-Path -LiteralPath $PlatformRoot) {
        try {
            $PlatformDirectories = Get-ChildItem `
                -LiteralPath $PlatformRoot `
                -Directory `
                -ErrorAction Stop |
                Sort-Object -Property Name -Descending

            foreach ($PlatformDirectory in $PlatformDirectories) {
                $Candidate = Join-Path `
                    -Path $PlatformDirectory.FullName `
                    -ChildPath 'MpCmdRun.exe'

                if (Test-Path -LiteralPath $Candidate) {
                    return $Candidate
                }
            }
        }
        catch {
            Write-Log "Unable to inspect Defender platform directory: $($_.Exception.Message)"
        }
    }

    $FallbackPath = Join-Path `
        -Path $env:ProgramFiles `
        -ChildPath 'Windows Defender\MpCmdRun.exe'

    if (Test-Path -LiteralPath $FallbackPath) {
        return $FallbackPath
    }

    return $null
}

Write-Log '============================================================'
Write-Log 'Starting Defender / Windows Security Center health check'

$Before = Get-DefenderWscState

Write-Log "Defender platform       : $($Before.PlatformVersion)"
Write-Log "Signature version       : $($Before.SignatureVersion)"
Write-Log "AM running mode         : $($Before.AMRunningMode)"
Write-Log "AM service enabled      : $($Before.AMServiceEnabled)"
Write-Log "Antivirus enabled       : $($Before.AntivirusEnabled)"
Write-Log "Real-time protection    : $($Before.RealTimeProtectionEnabled)"
Write-Log "WSC service             : $($Before.WscServiceStatus)"
Write-Log "WMI productState        : $($Before.WmiProductState) [$($Before.WmiProductStateHex)]"
Write-Log "Registry STATE          : $($Before.RegistryState) [$($Before.RegistryStateHex)]"

$DefenderReallyOn = Test-DefenderReallyOn -State $Before
$WscBroken        = Test-WscBroken -State $Before

if (-not $DefenderReallyOn) {
    Write-Log 'Defender is not reporting a normal active state.'
    Write-Log 'This does not match the known WSC race condition.'
    Write-Log 'No remediation was performed.'
    exit 1
}

if (-not $WscBroken) {
    Write-Log 'Defender is active and the known broken WSC state was not detected.'
    Write-Log 'No remediation is required.'
    exit 0
}

Write-Log '*** RACE CONDITION DETECTED ***'
Write-Log 'Defender reports itself active, but Windows Security Center reports 0x060100.'

# Ensure Windows Security Center is running before resetting Defender.
try {
    $WscSvc = Get-Service -Name 'wscsvc' -ErrorAction Stop

    if ($WscSvc.Status -ne 'Running') {
        Write-Log 'Windows Security Center is not running. Starting wscsvc.'

        Start-Service -Name 'wscsvc' -ErrorAction Stop
        Start-Sleep -Seconds 15

        $AfterWscStart = Get-DefenderWscState

        Write-Log "After starting wscsvc, WMI      : $($AfterWscStart.WmiProductStateHex)"
        Write-Log "After starting wscsvc, Registry : $($AfterWscStart.RegistryStateHex)"

        $DefenderStillOn = Test-DefenderReallyOn -State $AfterWscStart
        $WscNowHealthy   = Test-WscHealthy -State $AfterWscStart

        if ($DefenderStillOn -and $WscNowHealthy) {
            Write-Log 'Windows Security Center recovered without resetting Defender.'
            exit 0
        }
    }
}
catch {
    Write-Log "Could not start or check wscsvc: $($_.Exception.Message)"
}

# Confirm that the mismatch still exists before ResetPlatform.
$Confirm = Get-DefenderWscState

if (-not (Test-DefenderReallyOn -State $Confirm)) {
    Write-Log 'Defender runtime state changed before remediation.'
    Write-Log 'ResetPlatform was cancelled.'
    exit 1
}

if (-not (Test-WscBroken -State $Confirm)) {
    Write-Log 'The Windows Security Center state recovered before remediation.'
    exit 0
}

$MpCmdRun = Get-MpCmdRunPath

if (-not $MpCmdRun) {
    Write-Log 'MpCmdRun.exe was not found in the Defender platform or Program Files locations.'
    exit 1
}

Write-Log "Using MpCmdRun.exe: $MpCmdRun"
Write-Log 'Running MpCmdRun.exe -ResetPlatform'
Write-Log "Platform before reset: $($Confirm.PlatformVersion)"

try {
    $Process = Start-Process `
        -FilePath $MpCmdRun `
        -ArgumentList '-ResetPlatform' `
        -Wait `
        -PassThru `
        -NoNewWindow `
        -ErrorAction Stop

    $ResetExitCode = $Process.ExitCode
    Write-Log "ResetPlatform exit code: $ResetExitCode"

    if ($ResetExitCode -ne 0) {
        Write-Log 'ResetPlatform returned a non-zero exit code.'
        exit 1
    }
}
catch {
    Write-Log "ResetPlatform failed: $($_.Exception.Message)"
    exit 1
}

Write-Log 'Waiting for Defender and Windows Security Center to republish state.'

$Recovered = $false
$After     = $null

for ($Attempt = 1; $Attempt -le 18; $Attempt++) {
    Start-Sleep -Seconds 5

    try {
        $After = Get-DefenderWscState

        $StatusLine = (
            'Check {0} | WMI={1} Registry={2} Platform={3}' -f
            $Attempt,
            $After.WmiProductStateHex,
            $After.RegistryStateHex,
            $After.PlatformVersion
        )

        Write-Log $StatusLine

        $DefenderRecovered = Test-DefenderReallyOn -State $After
        $WscRecovered      = Test-WscHealthy -State $After

        if ($DefenderRecovered -and $WscRecovered) {
            $Recovered = $true
            break
        }
    }
    catch {
        Write-Log "Post-remediation check $Attempt failed: $($_.Exception.Message)"
    }
}

if ($Recovered) {
    Write-Log '*** REMEDIATION SUCCESSFUL ***'
    Write-Log "Platform after reset : $($After.PlatformVersion)"
    Write-Log "WMI productState      : $($After.WmiProductStateHex)"
    Write-Log "Registry STATE        : $($After.RegistryStateHex)"
    exit 0
}

Write-Log '*** REMEDIATION FAILED ***'

if ($null -ne $After) {
    Write-Log "Defender platform : $($After.PlatformVersion)"
    Write-Log "WMI productState  : $($After.WmiProductStateHex)"
    Write-Log "Registry STATE    : $($After.RegistryStateHex)"
}

exit 1
