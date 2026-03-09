[CmdletBinding()]
param(
    [ValidateSet("start", "stop", "status", "test")]
    [string]$Action = "status"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path -Parent $PSScriptRoot
$StateRoot = Join-Path $env:TEMP "S5Core-VPN"
$LogsRoot = Join-Path $StateRoot "logs"
$StatePath = Join-Path $StateRoot "state.clixml"

# =========================
# Edit this block only.
# =========================
$Config = [ordered]@{
    ServerHost        = "YOUR_SERVER_IP"
    ServerPort        = 1443
    ObfsPsk           = "YOUR_32_BYTE_PSK_REPLACE_ME_1234"
    ObfsMaxPadding    = 256
    ObfsMtu           = 1400
    ProxyUser         = "YOUR_PROXY_USERNAME"
    ProxyPass         = "YOUR_PROXY_PASSWORD"
    ClientListenAddr  = "127.0.0.1:1080"
    TunName           = "wintun"
    TunIp             = "198.18.0.1"
    TunPrefixLength   = 15
    DnsServers        = @("1.1.1.1", "1.0.0.1")
    DisableIPv6       = $true
    RouteLanRanges    = $true
    AutoBuildS5Client = $true
    S5ClientExe       = (Join-Path $RepoRoot "build\s5client.exe")
    # Optional: leave empty to auto-detect tun2socks from winget/common paths.
    Tun2SocksExe      = ""
    # Optional: leave empty if wintun.dll is already next to tun2socks.exe.
    WintunDll         = ""
}

function Write-Info([string]$Message) {
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "[ OK ] $Message" -ForegroundColor Green
}

function Write-WarnMsg([string]$Message) {
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail([string]$Message) {
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

function Format-Optional($Value) {
    if ($null -eq $Value -or [string]::IsNullOrWhiteSpace([string]$Value)) {
        return "n/a"
    }
    return [string]$Value
}

function New-DirectoryIfMissing([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script from an elevated PowerShell session."
    }
}

function ConvertTo-SubnetMask([int]$PrefixLength) {
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) {
        throw "Invalid prefix length: $PrefixLength"
    }

    $mask = [uint32]0
    for ($i = 0; $i -lt $PrefixLength; $i++) {
        $mask = $mask -bor (1 -shl (31 - $i))
    }

    return [string]([System.Net.IPAddress]::new([byte[]](
        ($mask -shr 24) -band 0xff,
        ($mask -shr 16) -band 0xff,
        ($mask -shr 8) -band 0xff,
        $mask -band 0xff
    )))
}

function Join-ArgumentString([string[]]$Arguments) {
    return ($Arguments | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + ($_ -replace '"', '\"') + '"'
        } else {
            $_
        }
    }) -join " "
}

function Export-State($State) {
    New-DirectoryIfMissing $StateRoot
    $State | Export-Clixml -Path $StatePath
}

function Import-State {
    if (-not (Test-Path -LiteralPath $StatePath)) {
        return $null
    }
    return Import-Clixml -Path $StatePath
}

function Remove-State {
    if (Test-Path -LiteralPath $StatePath) {
        Remove-Item -LiteralPath $StatePath -Force
    }
}

function Test-ProcessAlive([int]$ProcessId) {
    try {
        $null = Get-Process -Id $ProcessId -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

function Resolve-ServerIPv4([string]$HostOrIp) {
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($HostOrIp, [ref]$ip)) {
        if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "IPv6 server addresses are not supported by this script. Use an IPv4 server IP."
        }
        return $ip.IPAddressToString
    }

    $addresses = [System.Net.Dns]::GetHostAddresses($HostOrIp) |
        Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
    if (-not $addresses -or $addresses.Count -eq 0) {
        throw "Failed to resolve an IPv4 address for server host '$HostOrIp'."
    }
    return $addresses[0].IPAddressToString
}

function Get-PrimaryRoute {
    $route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" |
        Where-Object { $_.NextHop -and $_.NextHop -ne "0.0.0.0" } |
        Sort-Object @{ Expression = { $_.RouteMetric + $_.InterfaceMetric } }, RouteMetric |
        Select-Object -First 1

    if (-not $route) {
        throw "Could not determine the current default route."
    }

    $adapter = Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction Stop
    $ipIf = Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction Stop

    return [pscustomobject]@{
        InterfaceAlias   = $adapter.Name
        InterfaceIndex   = $route.InterfaceIndex
        Gateway          = $route.NextHop
        AutomaticMetric  = $ipIf.AutomaticMetric
        InterfaceMetric  = $ipIf.InterfaceMetric
    }
}

function Get-DefaultRoutes {
    return Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" |
        Where-Object { $_.NextHop -and $_.NextHop -ne "0.0.0.0" -and $_.InterfaceAlias -ne $Config.TunName }
}

function Get-ListenEndpoint([string]$ListenAddr) {
    $parts = $ListenAddr.Split(":")
    if ($parts.Count -lt 2) {
        throw "Invalid ClientListenAddr: $ListenAddr"
    }

    return [pscustomobject]@{
        Host = ($parts[0..($parts.Count - 2)] -join ":")
        Port = [int]$parts[-1]
    }
}

function Wait-TcpPort([string]$TargetHost, [int]$Port, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $client = New-Object Net.Sockets.TcpClient
            $iar = $client.BeginConnect($TargetHost, $Port, $null, $null)
            if ($iar.AsyncWaitHandle.WaitOne(250)) {
                $client.EndConnect($iar)
                $client.Dispose()
                return
            }
            $client.Dispose()
        } catch {
        }
        Start-Sleep -Milliseconds 250
    }

    throw "Timed out waiting for TCP $TargetHost`:$Port."
}

function Assert-CommandAvailable([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        throw "Required command not found: $Name"
    }
}

function Initialize-S5ClientBinary {
    New-DirectoryIfMissing (Split-Path -Parent $Config.S5ClientExe)

    if ($Config.AutoBuildS5Client -or -not (Test-Path -LiteralPath $Config.S5ClientExe)) {
        Assert-CommandAvailable "go"
        Write-Info "Building s5client from local source..."
        Push-Location $RepoRoot
        try {
            & go build -o $Config.S5ClientExe .\cmd\s5client
        } finally {
            Pop-Location
        }
    }

    if (-not (Test-Path -LiteralPath $Config.S5ClientExe)) {
        throw "s5client binary not found: $($Config.S5ClientExe)"
    }
}

function Resolve-Tun2SocksExePath {
    if (-not [string]::IsNullOrWhiteSpace($Config.Tun2SocksExe) -and (Test-Path -LiteralPath $Config.Tun2SocksExe)) {
        return $Config.Tun2SocksExe
    }

    $candidates = New-Object System.Collections.Generic.List[string]

    $wingetRoot = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
    if (Test-Path -LiteralPath $wingetRoot) {
        Get-ChildItem -Path $wingetRoot -Directory -Filter "xjasonlyu.tun2socks*" -ErrorAction SilentlyContinue |
            ForEach-Object {
                $candidate = Join-Path $_.FullName "tun2socks-windows-amd64.exe"
                if (Test-Path -LiteralPath $candidate) {
                    $candidates.Add($candidate) | Out-Null
                }
            }
    }

    foreach ($fallback in @(
        "C:\Tools\tun2socks.exe",
        "C:\Tools\tun2socks-windows-amd64.exe"
    )) {
        if (Test-Path -LiteralPath $fallback) {
            $candidates.Add($fallback) | Out-Null
        }
    }

    $cmd = Get-Command "tun2socks*" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd -and $cmd.Source -and (Test-Path -LiteralPath $cmd.Source)) {
        $candidates.Add($cmd.Source) | Out-Null
    }

    return $candidates | Select-Object -First 1
}

function Resolve-WintunDllPath([string]$Tun2SocksExe) {
    $tunDir = Split-Path -Parent $Tun2SocksExe
    $localWintunDll = Join-Path $tunDir "wintun.dll"
    if (Test-Path -LiteralPath $localWintunDll) {
        return $localWintunDll
    }

    if (-not [string]::IsNullOrWhiteSpace($Config.WintunDll) -and (Test-Path -LiteralPath $Config.WintunDll)) {
        return $Config.WintunDll
    }

    foreach ($fallback in @(
        "C:\Program Files\WireGuard\wintun.dll",
        "C:\Program Files\Tailscale\wintun.dll",
        "C:\Tools\wintun.dll"
    )) {
        if (Test-Path -LiteralPath $fallback) {
            return $fallback
        }
    }

    return $null
}

function Initialize-Tun2SocksDependencies {
    $resolvedTun2SocksExe = Resolve-Tun2SocksExePath
    if ([string]::IsNullOrWhiteSpace($resolvedTun2SocksExe)) {
        throw "tun2socks binary not found. Set Tun2SocksExe in this script or install tun2socks via winget."
    }
    $Config.Tun2SocksExe = $resolvedTun2SocksExe

    $tunDir = Split-Path -Parent $Config.Tun2SocksExe
    $localWintunDll = Join-Path $tunDir "wintun.dll"

    if (Test-Path -LiteralPath $localWintunDll) {
        return
    }

    $resolvedWintunDll = Resolve-WintunDllPath -Tun2SocksExe $Config.Tun2SocksExe
    if ([string]::IsNullOrWhiteSpace($resolvedWintunDll)) {
        throw "wintun.dll not found. Put wintun.dll next to $($Config.Tun2SocksExe) or set WintunDll in this script."
    }
    $Config.WintunDll = $resolvedWintunDll

    Copy-Item -LiteralPath $Config.WintunDll -Destination $localWintunDll -Force
}

function Start-ProcessWithEnvironment {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $false)]
        [string[]]$Arguments = @(),

        [Parameter(Mandatory = $false)]
        [hashtable]$Environment = @{},

        [Parameter(Mandatory = $true)]
        [string]$StdOutPath,

        [Parameter(Mandatory = $true)]
        [string]$StdErrPath,

        [Parameter(Mandatory = $true)]
        [string]$WorkingDirectory
    )

    $previousEnv = @{}
    try {
        foreach ($key in $Environment.Keys) {
            $previousEnv[$key] = [Environment]::GetEnvironmentVariable($key, "Process")
            [Environment]::SetEnvironmentVariable($key, [string]$Environment[$key], "Process")
        }

        $argumentString = Join-ArgumentString $Arguments
        if ([string]::IsNullOrWhiteSpace($argumentString)) {
            return Start-Process -FilePath $FilePath `
                -WorkingDirectory $WorkingDirectory `
                -RedirectStandardOutput $StdOutPath `
                -RedirectStandardError $StdErrPath `
                -PassThru
        }

        return Start-Process -FilePath $FilePath `
            -ArgumentList $argumentString `
            -WorkingDirectory $WorkingDirectory `
            -RedirectStandardOutput $StdOutPath `
            -RedirectStandardError $StdErrPath `
            -PassThru
    } finally {
        foreach ($key in $Environment.Keys) {
            [Environment]::SetEnvironmentVariable($key, $previousEnv[$key], "Process")
        }
    }
}

function Wait-ForTunInterface([string]$Name, [int]$TimeoutSeconds) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $adapter = Get-NetAdapter -Name $Name -ErrorAction SilentlyContinue
        if ($adapter) {
            return $adapter
        }
        Start-Sleep -Milliseconds 300
    }

    throw "Timed out waiting for TUN adapter '$Name'."
}

function Set-TunInterface {
    param(
        [Parameter(Mandatory = $true)]
        [string]$TunName
    )

    $existingV4 = Get-NetIPAddress -InterfaceAlias $TunName -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($existingV4) {
        $existingV4 | Remove-NetIPAddress -Confirm:$false | Out-Null
    }

    New-NetIPAddress -InterfaceAlias $TunName `
        -AddressFamily IPv4 `
        -IPAddress $Config.TunIp `
        -PrefixLength $Config.TunPrefixLength | Out-Null

    Set-DnsClientServerAddress -InterfaceAlias $TunName -ServerAddresses $Config.DnsServers
    Set-NetIPInterface -InterfaceAlias $TunName -AddressFamily IPv4 -AutomaticMetric Disabled -InterfaceMetric 1 | Out-Null
}

function Set-PrimaryMetricForTunnel {
    param(
        [Parameter(Mandatory = $true)]
        $PrimaryRoute,

        [Parameter(Mandatory = $true)]
        $State
    )

    $State.PrimaryInterfaceMetric = $PrimaryRoute.InterfaceMetric
    $State.PrimaryAutomaticMetric = $PrimaryRoute.AutomaticMetric

    Set-NetIPInterface -InterfaceAlias $PrimaryRoute.InterfaceAlias `
        -AddressFamily IPv4 `
        -AutomaticMetric Disabled `
        -InterfaceMetric 50 | Out-Null
}

function Restore-PrimaryMetric {
    param([Parameter(Mandatory = $true)]$State)

    if (-not $State.PrimaryInterfaceAlias -or $null -eq $State.PrimaryAutomaticMetric -or $null -eq $State.PrimaryInterfaceMetric) {
        return
    }

    try {
        Set-NetIPInterface -InterfaceAlias $State.PrimaryInterfaceAlias `
            -AddressFamily IPv4 `
            -AutomaticMetric $State.PrimaryAutomaticMetric `
            -InterfaceMetric ([int]$State.PrimaryInterfaceMetric) | Out-Null
    } catch {
        Write-WarnMsg "Failed to restore interface metric on $($State.PrimaryInterfaceAlias): $($_.Exception.Message)"
    }
}

function Add-ManagedRoute {
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPrefix,

        [Parameter(Mandatory = $true)]
        [int]$InterfaceIndex,

        [Parameter(Mandatory = $true)]
        [string]$NextHop,

        [Parameter(Mandatory = $true)]
        [int]$RouteMetric
    )

    $existing = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix $DestinationPrefix -InterfaceIndex $InterfaceIndex -ErrorAction SilentlyContinue |
        Where-Object { $_.NextHop -eq $NextHop }

    if (-not $existing) {
        New-NetRoute -AddressFamily IPv4 `
            -DestinationPrefix $DestinationPrefix `
            -InterfaceIndex $InterfaceIndex `
            -NextHop $NextHop `
            -RouteMetric $RouteMetric `
            -PolicyStore ActiveStore | Out-Null
    }

    $State.AddedRoutes.Add([pscustomobject]@{
        DestinationPrefix = $DestinationPrefix
        InterfaceIndex    = $InterfaceIndex
        NextHop           = $NextHop
    }) | Out-Null
}

function Remove-ManagedRoutes {
    param([Parameter(Mandatory = $true)]$State)

    foreach ($route in @($State.AddedRoutes) | Sort-Object DestinationPrefix -Descending) {
        try {
            Get-NetRoute -AddressFamily IPv4 `
                -DestinationPrefix $route.DestinationPrefix `
                -InterfaceIndex ([int]$route.InterfaceIndex) `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -eq $route.NextHop } |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            Write-WarnMsg "Failed to remove route $($route.DestinationPrefix): $($_.Exception.Message)"
        }
    }
}

function Export-DefaultRoutes {
    param([Parameter(Mandatory = $true)]$State)

    $State.SavedDefaultRoutes = @()
    foreach ($route in Get-DefaultRoutes) {
        $State.SavedDefaultRoutes += [pscustomobject]@{
            InterfaceIndex = $route.InterfaceIndex
            NextHop        = $route.NextHop
            RouteMetric    = $route.RouteMetric
        }
    }
}

function Remove-DefaultRoutes {
    param([Parameter(Mandatory = $true)]$State)

    foreach ($route in @($State.SavedDefaultRoutes)) {
        try {
            Get-NetRoute -AddressFamily IPv4 `
                -DestinationPrefix "0.0.0.0/0" `
                -InterfaceIndex ([int]$route.InterfaceIndex) `
                -ErrorAction SilentlyContinue |
                Where-Object { $_.NextHop -eq $route.NextHop } |
                Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
        } catch {
            Write-WarnMsg "Failed to remove default route via $($route.NextHop): $($_.Exception.Message)"
        }
    }
}

function Restore-DefaultRoutes {
    param([Parameter(Mandatory = $true)]$State)

    foreach ($route in @($State.SavedDefaultRoutes)) {
        $existing = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" -InterfaceIndex ([int]$route.InterfaceIndex) -ErrorAction SilentlyContinue |
            Where-Object { $_.NextHop -eq $route.NextHop }

        if (-not $existing) {
            try {
                New-NetRoute -AddressFamily IPv4 `
                    -DestinationPrefix "0.0.0.0/0" `
                    -InterfaceIndex ([int]$route.InterfaceIndex) `
                    -NextHop $route.NextHop `
                    -RouteMetric ([int]$route.RouteMetric) `
                    -PolicyStore ActiveStore | Out-Null
            } catch {
                Write-WarnMsg "Failed to restore default route via $($route.NextHop): $($_.Exception.Message)"
            }
        }
    }
}

function Disable-PhysicalIPv6 {
    param([Parameter(Mandatory = $true)]$State)

    $State.DisabledIpv6Adapters = New-Object System.Collections.Generic.List[string]
    if (-not $Config.DisableIPv6) {
        return
    }

    $adapters = Get-NetAdapter |
        Where-Object {
            $_.Status -eq "Up" -and
            $_.Name -ne $Config.TunName
        }

    foreach ($adapter in $adapters) {
        try {
            $binding = Get-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -ErrorAction Stop
            if ($binding.Enabled) {
                Disable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6 -PassThru:$false | Out-Null
                $State.DisabledIpv6Adapters.Add($adapter.Name) | Out-Null
            }
        } catch {
            Write-WarnMsg "Failed to disable IPv6 on $($adapter.Name): $($_.Exception.Message)"
        }
    }
}

function Restore-PhysicalIPv6 {
    param([Parameter(Mandatory = $true)]$State)

    foreach ($adapterName in @($State.DisabledIpv6Adapters)) {
        try {
            Enable-NetAdapterBinding -Name $adapterName -ComponentID ms_tcpip6 -PassThru:$false | Out-Null
        } catch {
            Write-WarnMsg "Failed to re-enable IPv6 on $($adapterName): $($_.Exception.Message)"
        }
    }
}

function Start-S5Client {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerIp,

        [Parameter(Mandatory = $true)]
        $State
    )

    $endpoint = Get-ListenEndpoint $Config.ClientListenAddr
    $stdout = Join-Path $LogsRoot "s5client.stdout.log"
    $stderr = Join-Path $LogsRoot "s5client.stderr.log"

    $envMap = @{
        CLIENT_LISTEN_ADDR = $Config.ClientListenAddr
        SERVER_ADDR        = "$ServerIp`:$($Config.ServerPort)"
        OBFS_PSK           = $Config.ObfsPsk
        OBFS_MAX_PADDING   = [string]$Config.ObfsMaxPadding
        OBFS_MTU           = [string]$Config.ObfsMtu
        PROXY_USER         = [string]$Config.ProxyUser
        PROXY_PASS         = [string]$Config.ProxyPass
        ROUTE_DOMAINS      = ""
    }

    $proc = Start-ProcessWithEnvironment `
        -FilePath $Config.S5ClientExe `
        -Arguments @() `
        -Environment $envMap `
        -StdOutPath $stdout `
        -StdErrPath $stderr `
        -WorkingDirectory (Split-Path -Parent $Config.S5ClientExe)

    $State.S5ClientPid = $proc.Id
    $State.S5ClientStdout = $stdout
    $State.S5ClientStderr = $stderr

    Wait-TcpPort -TargetHost $endpoint.Host -Port $endpoint.Port -TimeoutSeconds 12
}

function Start-Tun2Socks {
    param(
        [Parameter(Mandatory = $true)]
        $PrimaryRoute,

        [Parameter(Mandatory = $true)]
        $State
    )

    $stdout = Join-Path $LogsRoot "tun2socks.stdout.log"
    $stderr = Join-Path $LogsRoot "tun2socks.stderr.log"
    # tun2socks only talks to the local s5client SOCKS endpoint.
    # The obfuscated hop stays between s5client and the remote server.
    $tunArgs = @(
        "-device", $Config.TunName,
        "-proxy", ("socks5://{0}" -f $Config.ClientListenAddr),
        "-interface", $PrimaryRoute.InterfaceAlias
    )

    $proc = Start-Process -FilePath $Config.Tun2SocksExe `
        -ArgumentList (Join-ArgumentString $tunArgs) `
        -WorkingDirectory (Split-Path -Parent $Config.Tun2SocksExe) `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -PassThru

    $State.Tun2SocksPid = $proc.Id
    $State.Tun2SocksStdout = $stdout
    $State.Tun2SocksStderr = $stderr

    $adapter = Wait-ForTunInterface -Name $Config.TunName -TimeoutSeconds 12
    $State.TunInterfaceIndex = $adapter.ifIndex
}

function Stop-ManagedProcesses {
    param([Parameter(Mandatory = $true)]$State)

    foreach ($pidName in @("Tun2SocksPid", "S5ClientPid")) {
        $pidValue = $State.$pidName
        if ($pidValue -and (Test-ProcessAlive -ProcessId ([int]$pidValue))) {
            try {
                Stop-Process -Id ([int]$pidValue) -Force
            } catch {
                Write-WarnMsg "Failed to stop PID $($pidValue): $($_.Exception.Message)"
            }
        }
    }
}

function Test-Config {
    if ([string]::IsNullOrWhiteSpace($Config.ServerHost)) {
        throw "ServerHost is required."
    }
    if ($Config.ServerPort -lt 1 -or $Config.ServerPort -gt 65535) {
        throw "ServerPort must be between 1 and 65535."
    }
    if ([string]::IsNullOrWhiteSpace($Config.ObfsPsk) -or $Config.ObfsPsk.Length -ne 32) {
        throw "ObfsPsk must be exactly 32 bytes."
    }
    if ([string]::IsNullOrWhiteSpace($Config.ClientListenAddr)) {
        throw "ClientListenAddr is required."
    }
    if ([string]::IsNullOrWhiteSpace($Config.TunName)) {
        throw "TunName is required."
    }
    if ([string]::IsNullOrWhiteSpace($Config.TunIp)) {
        throw "TunIp is required."
    }
    if (-not $Config.DnsServers -or $Config.DnsServers.Count -eq 0) {
        throw "At least one DNS server is required."
    }
}

function Stop-TunnelInternal {
    param(
        [Parameter(Mandatory = $true)]
        $State,

        [switch]$KeepState
    )

    Restore-DefaultRoutes -State $State
    Remove-ManagedRoutes -State $State
    Restore-PrimaryMetric -State $State
    Restore-PhysicalIPv6 -State $State
    Stop-ManagedProcesses -State $State

    try {
        if ($State.TunInterfaceIndex) {
            Set-DnsClientServerAddress -InterfaceIndex ([int]$State.TunInterfaceIndex) -ResetServerAddresses -ErrorAction SilentlyContinue
        }
    } catch {
    }

    if (-not $KeepState) {
        Remove-State
    }
}

function Start-Tunnel {
    Assert-Administrator
    Test-Config
    New-DirectoryIfMissing $LogsRoot
    Initialize-S5ClientBinary
    Initialize-Tun2SocksDependencies

    $existingState = Import-State
    if ($existingState -and (($existingState.S5ClientPid -and (Test-ProcessAlive -ProcessId ([int]$existingState.S5ClientPid))) -or
        ($existingState.Tun2SocksPid -and (Test-ProcessAlive -ProcessId ([int]$existingState.Tun2SocksPid))))) {
        throw "Tunnel already appears to be active. Run '.\scripts\s5vpn-win.ps1 stop' first."
    }

    $primary = Get-PrimaryRoute
    $serverIp = Resolve-ServerIPv4 $Config.ServerHost

    $state = [pscustomobject]@{
        StartedAt            = Get-Date
        ServerIp             = $serverIp
        ServerPort           = $Config.ServerPort
        LocalProxyUri        = ("socks5://{0}" -f $Config.ClientListenAddr)
        PrimaryInterfaceAlias = $primary.InterfaceAlias
        PrimaryInterfaceIndex = $primary.InterfaceIndex
        PrimaryGateway       = $primary.Gateway
        PrimaryAutomaticMetric = $null
        PrimaryInterfaceMetric = $null
        TunInterfaceIndex    = $null
        S5ClientPid          = $null
        Tun2SocksPid         = $null
        S5ClientStdout       = $null
        S5ClientStderr       = $null
        Tun2SocksStdout      = $null
        Tun2SocksStderr      = $null
        DisabledIpv6Adapters = @()
        SavedDefaultRoutes   = @()
        AddedRoutes          = (New-Object System.Collections.ArrayList)
    }

    Export-State $state

    try {
        Write-Info "Default uplink: $($primary.InterfaceAlias) via $($primary.Gateway)"
        Write-Info "Server route pin: $serverIp`:$($Config.ServerPort)"

        Start-S5Client -ServerIp $serverIp -State $state
        Write-Ok "s5client is running on $($Config.ClientListenAddr)"

        Start-Tun2Socks -PrimaryRoute $primary -State $state
        Set-TunInterface -TunName $Config.TunName
        Write-Ok "tun2socks created adapter '$($Config.TunName)'"

        Set-PrimaryMetricForTunnel -PrimaryRoute $primary -State $state
        Disable-PhysicalIPv6 -State $state
        Export-DefaultRoutes -State $state

        Add-ManagedRoute -State $state -DestinationPrefix "$serverIp/32" -InterfaceIndex $primary.InterfaceIndex -NextHop $primary.Gateway -RouteMetric 1

        if ($Config.RouteLanRanges) {
            Add-ManagedRoute -State $state -DestinationPrefix "10.0.0.0/8" -InterfaceIndex $primary.InterfaceIndex -NextHop $primary.Gateway -RouteMetric 5
            Add-ManagedRoute -State $state -DestinationPrefix "172.16.0.0/12" -InterfaceIndex $primary.InterfaceIndex -NextHop $primary.Gateway -RouteMetric 5
            Add-ManagedRoute -State $state -DestinationPrefix "192.168.0.0/16" -InterfaceIndex $primary.InterfaceIndex -NextHop $primary.Gateway -RouteMetric 5
        }

        Add-ManagedRoute -State $state -DestinationPrefix "0.0.0.0/1" -InterfaceIndex ([int]$state.TunInterfaceIndex) -NextHop $Config.TunIp -RouteMetric 1
        Add-ManagedRoute -State $state -DestinationPrefix "128.0.0.0/1" -InterfaceIndex ([int]$state.TunInterfaceIndex) -NextHop $Config.TunIp -RouteMetric 1
        Remove-DefaultRoutes -State $state

        Export-State $state
        Write-Ok "Full-tunnel mode is active."
        Write-Host ""
        Write-Host ("Server obfs endpoint : {0}:{1}" -f $serverIp, $Config.ServerPort)
        Write-Host ("Local SOCKS endpoint : {0}" -f $Config.ClientListenAddr)
        Write-Host ("Chain                : tun2socks -> {0} -> obfs -> {1}:{2}" -f $state.LocalProxyUri, $serverIp, $Config.ServerPort)
        Write-Host ("TUN adapter          : {0} ({1}/{2})" -f $Config.TunName, $Config.TunIp, $Config.TunPrefixLength)
        Write-Host ("Logs                 : {0}" -f $LogsRoot)
    } catch {
        Write-Fail $_.Exception.Message
        Stop-TunnelInternal -State $state
        throw
    }
}

function Stop-Tunnel {
    Assert-Administrator

    $state = Import-State
    if (-not $state) {
        Write-WarnMsg "No saved tunnel state was found."
        return
    }

    Stop-TunnelInternal -State $state
    Write-Ok "Direct connection restored."
}

function Show-Status {
    $state = Import-State
    $adapter = Get-NetAdapter -Name $Config.TunName -ErrorAction SilentlyContinue

    Write-Host "=== S5Core Windows VPN status ==="
    if ($state) {
        Write-Host ("State file           : {0}" -f $StatePath)
        Write-Host ("Started at           : {0}" -f $state.StartedAt)
        Write-Host ("Server pin           : {0}:{1}" -f $state.ServerIp, $state.ServerPort)
        Write-Host ("Chain                : tun2socks -> {0} -> obfs -> {1}:{2}" -f (Format-Optional $state.LocalProxyUri), $state.ServerIp, $state.ServerPort)
        Write-Host ("Uplink               : {0}" -f $state.PrimaryInterfaceAlias)
        Write-Host ("s5client PID         : {0}" -f (Format-Optional $state.S5ClientPid))
        Write-Host ("tun2socks PID        : {0}" -f (Format-Optional $state.Tun2SocksPid))
        Write-Host ("Saved default routes : {0}" -f (@($state.SavedDefaultRoutes).Count))
    } else {
        Write-Host "State file           : not found"
    }

    if ($adapter) {
        Write-Host ("TUN adapter          : present ({0})" -f $adapter.Status)
    } else {
        Write-Host "TUN adapter          : not present"
    }

    $splitRoutes = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/1" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq $Config.TunName }
    if ($splitRoutes) {
        Write-Host "Split routes         : installed"
    } else {
        Write-Host "Split routes         : not installed"
    }
}

function Test-Tunnel {
    $state = Import-State
    if (-not $state) {
        throw "Tunnel is not active."
    }

    Write-Info ("Configured chain: tun2socks -> {0} -> obfs -> {1}:{2}" -f (Format-Optional $state.LocalProxyUri), $state.ServerIp, $state.ServerPort)

    Write-Info "External IPv4:"
    try {
        $ip = & curl.exe --max-time 10 --silent https://ifconfig.me/ip
        Write-Host $ip
    } catch {
        Write-WarnMsg "Failed to fetch external IP: $($_.Exception.Message)"
    }

    Write-Info "Route to 1.1.1.1:"
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/1" -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceAlias -eq $Config.TunName } |
        Format-Table DestinationPrefix, NextHop, InterfaceAlias, InterfaceIndex, RouteMetric -AutoSize
}

try {
    switch ($Action) {
        "start"  { Start-Tunnel }
        "stop"   { Stop-Tunnel }
        "status" { Show-Status }
        "test"   { Test-Tunnel }
    }
} catch {
    Write-Fail $_.Exception.Message
    exit 1
}
