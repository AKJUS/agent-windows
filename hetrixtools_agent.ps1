#
#	HetrixTools Server Monitoring Agent
#	Copyright 2015 - 2025 @  HetrixTools
#	For support, please open a ticket on our website https://hetrixtools.com
#
#
#		DISCLAIMER OF WARRANTY
#
#	The Software is provided "AS IS" and "WITH ALL FAULTS," without warranty of any kind, 
#	including without limitation the warranties of merchantability, fitness for a particular purpose and non-infringement. 
#	HetrixTools makes no warranty that the Software is free of defects or is suitable for any particular purpose. 
#	In no event shall HetrixTools be responsible for loss or damages arising from the installation or use of the Software, 
#	including but not limited to any indirect, punitive, special, incidental or consequential damages of any character including, 
#	without limitation, damages for loss of goodwill, work stoppage, computer failure or malfunction, or any and all other commercial damages or losses. 
#	The entire risk as to the quality and performance of the Software is borne by you, the user.
#
#		END OF DISCLAIMER OF WARRANTY

# Script path
$ScriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$ScriptFile = $MyInvocation.MyCommand.Path

# Agent Version (do not change)
$Version = "2.1.2"

# Load configuration file
$ConfigFile = "$ScriptPath\hetrixtools.cfg"

# Debug log
$debugLog = "$ScriptPath\debug.log"

# Script start time
$ScriptStartTime = Get-Date -Format '[yyyy-MM-dd HH:mm:ss]'

# Function to parse the configuration file
function Get-ConfigValue {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Key,
        [string]$DefaultValue = $null,
        [switch]$Required
    )
    
    # Match the key at the start of the line while allowing optional whitespace around '='
    $line = Get-Content $ConfigFile | Where-Object { $_ -match "^\s*$Key\s*=" }
    if ($line) {
        $parts = $line.Split('=', 2)
        if ($parts.Count -gt 1) {
            return $parts[1].Trim().Trim('"', "'")
        }
    }
    if ($Required.IsPresent) {
        Write-Error "Required config key '$Key' not found in $ConfigFile"
        exit 1
    }
    return $DefaultValue
}

# Function to encode a string to base64
function Encode-Base64 {
    param (
        [string]$InputString
    )
    
    # Return an empty string if the input is null or empty
    if ([string]::IsNullOrEmpty($InputString)) {
        return ""
    }
    
    # Convert the string to bytes
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($InputString)
    
    # Convert the bytes to a base64 string
    $base64String = [Convert]::ToBase64String($bytes)
    
    return $base64String
}

function Check-ProcessOrService {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Name
    )
	
	$Name = $Name -replace '\.exe$', ''
    
    # Check if the given name is a running process
    if (Get-Process -Name $Name -ErrorAction SilentlyContinue) {
        return 1
    }
    # If not a running process, check if it is a running service
    elseif (Get-Service -Name $Name -ErrorAction SilentlyContinue) {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service.Status -eq 'Running') {
            return 1
        } else {
            return 0
        }
    } 
    # If neither a running process nor a running service
    else {
        return 0
    }
}

function Get-PerflibCounterNames {
    param (
        [int[]]$Ids
    )

    $perflibBase = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib'
    $allKeys = Get-ChildItem -Path $perflibBase |
        Where-Object { $_.PSChildName -match '^(?:[0-9a-fA-F]{3,4}|CurrentLanguage)$' } |
        Select-Object -ExpandProperty PSChildName

    $preferred = @($allKeys | Where-Object { $_ -ne '009' })

    if ($preferred.Count -gt 1 -and $preferred -contains 'CurrentLanguage') {
        $activeLcid = 'CurrentLanguage'
    } elseif ($preferred.Count -gt 0) {
        $activeLcid = $preferred[0]
    } elseif ($allKeys -contains '009') {
        $activeLcid = '009'
    } else {
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') No valid Perflib subkeys found."}
        Write-Warning "No valid Perflib subkeys found."
        return @{}
    }

    $counterPath = Join-Path $perflibBase $activeLcid
    try {
        $counters = (Get-ItemProperty -Path $counterPath -Name Counter).Counter
    } catch {
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Could not read Counter from $counterPath"}
        Write-Warning "Could not read Counter from $counterPath"
        return @{}
    }

    $result = @{}

    foreach ($id in $Ids) {
        for ($i = 0; $i -lt $counters.Length; $i += 2) {
            if ($counters[$i] -eq $id.ToString()) {
                $result[$id] = $counters[$i + 1]
                break
            }
        }

        if (-not $result.ContainsKey($id)) {
            $result[$id] = $null
        }
    }

    return $result
}

function Wait-ForJobOutput {
    param(
        [System.Management.Automation.Job]$Job,
        [int]$TimeoutSeconds = 10
    )

    $elapsed = 0
    while ($elapsed -lt $TimeoutSeconds) {
        $result = Receive-Job -Job $Job
        if ($result) {
            return ,$result
        }
        Start-Sleep -Milliseconds 200
        $elapsed += 0.2
    }

    return $null
}

# Retrieve current byte counters for a network adapter, trying multiple
# providers when Get-NetAdapterStatistics is unavailable.
function Get-NicBytes {
    param(
        [Parameter(Mandatory)][string]$Name
    )

    try {
        $stat = Get-NetAdapterStatistics -Name $Name -ErrorAction Stop
        return [pscustomobject]@{ RX = [int64]$stat.ReceivedBytes; TX = [int64]$stat.SentBytes }
    } catch {
        try {
            $nic = Get-NetAdapter -Name $Name -ErrorAction Stop
            $normTarget = ($nic.InterfaceDescription -replace '[^A-Za-z0-9]', '').ToUpper()
            $raw = Get-CimInstance -ClassName Win32_PerfRawData_Tcpip_NetworkInterface |
                Where-Object {
                    $curr = ($_.Name -replace '[^A-Za-z0-9]', '').ToUpper()
                    $curr -eq $normTarget -or $_.Name -like "*$($nic.InterfaceDescription)*" -or $_.Name -like "*$Name*"
                } | Select-Object -First 1
            if ($raw) {
                $rx = $raw.PSObject.Properties['BytesReceivedPerSec'].Value
                if ($rx -eq $null) { $rx = $raw.PSObject.Properties['BytesReceivedPersec'].Value }
                $tx = $raw.PSObject.Properties['BytesSentPerSec'].Value
                if ($tx -eq $null) { $tx = $raw.PSObject.Properties['BytesSentPersec'].Value }
                if ($rx -ne $null -and $tx -ne $null) {
                    return [pscustomobject]@{ RX = [int64]$rx; TX = [int64]$tx }
                }
            }
        } catch {
            try {
                $counterBase = "\\Network Interface($Name)"
                $c = Get-Counter -Counter @("$counterBase\\Bytes Received/sec", "$counterBase\\Bytes Sent/sec") -ErrorAction Stop
                $rx = ($c.CounterSamples | Where-Object { $_.Path -like '*Bytes Received/sec' }).RawValue
                $tx = ($c.CounterSamples | Where-Object { $_.Path -like '*Bytes Sent/sec' }).RawValue
                if ($rx -ne $null -and $tx -ne $null) {
                    return [pscustomobject]@{ RX = [int64]$rx; TX = [int64]$tx }
                }
            } catch {
            }
        }
    }

    return [pscustomobject]@{ RX = $null; TX = $null }
}

function Test-IsNonLoopbackAddress {
    param(
        [string]$Address
    )

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return $false
    }

    $normalized = $Address.Trim().Trim('[', ']')

    if ($normalized -match '^(127\.)') {
        return $false
    }
    if ($normalized -match '^(::1|::ffff:127\.|0:0:0:0:0:0:0:1)$') {
        return $false
    }
    if ($normalized -match '^fe80:') {
        return $false
    }

    return $true
}

function Get-ListeningPorts {
    param(
        [int]$MaxPorts = 30
    )

    $ports = [System.Collections.Generic.HashSet[int]]::new()

    try {
        $listeners = Get-NetTCPConnection -State Listen -WarningAction SilentlyContinue
        foreach ($listener in $listeners) {
            if ($listener.LocalPort -eq $null) { continue }
            if (-not (Test-IsNonLoopbackAddress -Address $listener.LocalAddress)) { continue }
            [void]$ports.Add([int]$listener.LocalPort)
        }
    } catch {
        try {
            $netstatOutput = netstat -an | Select-String -Pattern 'LISTENING'
            foreach ($line in $netstatOutput) {
                if ($line.Line -match '^\s*TCP\s+(\S+):(\d+)\s+\S+\s+LISTENING') {
                    $address = $matches[1]
                    $port = [int]$matches[2]
                    if (-not (Test-IsNonLoopbackAddress -Address $address)) { continue }
                    [void]$ports.Add($port)
                }
            }
        } catch {
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Failed to auto-detect listening ports: $($_.Exception.Message)"}
        }
    }

    $sorted = @()
    foreach ($port in $ports) {
        $sorted += $port
    }
    if ($sorted.Count -gt 0) {
        $sorted = $sorted | Sort-Object
        $sorted = @($sorted)
    }
    if ($sorted.Count -gt $MaxPorts) {
        $sorted = $sorted[0..($MaxPorts - 1)]
    }

    return $sorted
}

function Get-PortConnectionSample {
    param(
        [int[]]$Ports
    )

    $result = @{}
    if (-not $Ports -or $Ports.Count -eq 0) {
        return $result
    }

    foreach ($port in $Ports) {
        $result["$port"] = 0
    }

    $targetSet = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($port in $Ports) {
        [void]$targetSet.Add($port)
    }

    try {
        $connections = Get-NetTCPConnection -State Established -WarningAction SilentlyContinue
        foreach ($conn in $connections) {
            if ($conn.LocalPort -eq $null) { continue }
            $localPort = [int]$conn.LocalPort
            if (-not $targetSet.Contains($localPort)) { continue }
            if (-not (Test-IsNonLoopbackAddress -Address $conn.LocalAddress)) { continue }
            $key = "$localPort"
            $result[$key]++
        }
    } catch {
        try {
            $netstatLines = netstat -an | Select-String -Pattern 'ESTABLISHED'
            foreach ($line in $netstatLines) {
                if ($line.Line -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+ESTABLISHED') {
                    $address = $matches[1]
                    $port = [int]$matches[2]
                    if (-not $targetSet.Contains($port)) { continue }
                    if (-not (Test-IsNonLoopbackAddress -Address $address)) { continue }
                    $key = "$port"
                    $result[$key]++
                }
            }
        } catch {
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Failed to sample port connections: $($_.Exception.Message)"}
        }
    }

    return $result
}

# Configs
$SID = Get-ConfigValue -Key "SID" -Required
$CollectEveryXSeconds = Get-ConfigValue -Key "CollectEveryXSeconds" -DefaultValue "3"
$NetworkInterfaces = Get-ConfigValue -Key "NetworkInterfaces" -DefaultValue ""
$CheckServices = Get-ConfigValue -Key "CheckServices" -DefaultValue ""
$ConnectionPorts = Get-ConfigValue -Key "ConnectionPorts" -DefaultValue ""
$CheckDriveHealth = Get-ConfigValue -Key "CheckDriveHealth" -DefaultValue "0"
$OutgoingPings = Get-ConfigValue -Key "OutgoingPings" -DefaultValue ""
$OutgoingPingsCount = Get-ConfigValue -Key "OutgoingPingsCount" -DefaultValue "20"
$DEBUG = Get-ConfigValue -Key "DEBUG" -DefaultValue "0"
$PingJobs = @()

if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Starting HetrixTools Agent v$Version"}

# If SID is empty, exit
if ([string]::IsNullOrEmpty($SID)) {
    Write-Host "SID is empty. Exiting..."
    if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') SID is empty"}
    exit 1
}

# Start timers
$START = [datetime]::UtcNow
$tTIMEDIFF = 0

# Get current minute
$M = [int](Get-Date -Format 'mm')

# If minute is empty, set it to 0
if (-not $M) {
    $M = 0
}

# Clear debug log every day at midnight
if ((Get-Date).Hour -eq 0 -and (Get-Date).Minute -eq 0) {
    if (Test-Path $debugLog) {
        Remove-Item -Path $debugLog -Force
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Debug log cleared."}
    }
}

# Outgoing PING
if (-not [string]::IsNullOrEmpty($OutgoingPings)) {
    if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') OutgoingPings: $OutgoingPings"}

    $pingJobScript = {
        param(
            [string]$TargetName,
            [string]$PingTarget,
            [string]$OutgoingPingsCount,
            [string]$ScriptPath,
            [string]$Debug,
            [string]$DebugLog,
            [string]$ScriptStartTime
        )

        function Write-PingDebug {
            param([string]$Message)
            if ($Debug -eq "1") {
                Add-Content -Path $DebugLog -Value "$ScriptStartTime-$((Get-Date -Format '[yyyy-MM-dd HH:mm:ss]')) $Message"
            }
        }

        if ($TargetName -notmatch '^[A-Za-z0-9._-]+$') { Write-PingDebug "Invalid PING target name value"; return }
        if ($PingTarget -notmatch '^[A-Za-z0-9.:_-]+$') { Write-PingDebug "Invalid PING target value"; return }
        if ($OutgoingPingsCount -notmatch '^\d+$') { Write-PingDebug "Invalid PING count value"; return }
        $count = [int]$OutgoingPingsCount
        if ($count -lt 10 -or $count -gt 40) { Write-PingDebug "Invalid PING count value"; return }

        $pingExe = Join-Path $env:SystemRoot 'System32\ping.exe'
        if (-not (Test-Path $pingExe)) { $pingExe = 'ping.exe' }
        Write-PingDebug "PING_CMD: $pingExe $PingTarget -n $count -w 1000"
        $pingOutput = & $pingExe $PingTarget -n $count -w 1000 2>&1
        $pingExitCode = $LASTEXITCODE
        Write-PingDebug "PING_EXIT: $pingExitCode"

        if ($Debug -eq "1") {
            $pingOutputText = if ($pingOutput) { $pingOutput -join "`n" } else { "" }
            Add-Content -Path $DebugLog -Value "$ScriptStartTime-$((Get-Date -Format '[yyyy-MM-dd HH:mm:ss]')) PING_OUTPUT:`n$pingOutputText"
        }

        $packetLoss = $null
        if ($pingOutput) {
            foreach ($line in $pingOutput) {
                if ($line -match '\((\d+)%') {
                    $packetLoss = $matches[1]
                    break
                }
            }
        }
        if ([string]::IsNullOrEmpty($packetLoss)) { Write-PingDebug "Unable to extract packet loss"; return }

        $avgRtt = 0
        if ($pingOutput) {
            foreach ($line in $pingOutput) {
                if ($line -match 'Average\s*=\s*(\d+)ms') {
                    $avgRtt = [int]$matches[1] * 1000
                    break
                }
            }
        }

        Write-PingDebug "PACKET_LOSS: $packetLoss"
        Write-PingDebug "AVG_RTT: $avgRtt"

        $pingLine = "$TargetName,$PingTarget,$packetLoss,$avgRtt;"
        $pingFile = Join-Path $ScriptPath 'ping.txt'
        $written = $false
        for ($i = 0; $i -lt 5 -and -not $written; $i++) {
            try {
                Add-Content -Path $pingFile -Value $pingLine
                $written = $true
            } catch {
                Start-Sleep -Milliseconds 100
            }
        }
        if (-not $written) { Write-PingDebug "Failed to append ping result to ping.txt" }
    }

    $OutgoingPingsArray = $OutgoingPings -split '\|'
    foreach ($entry in $OutgoingPingsArray) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }
        $parts = $entry -split ',', 2
        if ($parts.Count -lt 2) { continue }
        $targetName = $parts[0].Trim()
        $pingTarget = $parts[1].Trim()
        if ([string]::IsNullOrWhiteSpace($targetName) -or [string]::IsNullOrWhiteSpace($pingTarget)) { continue }
        try {
            $job = Start-Job -ScriptBlock $pingJobScript -ArgumentList $targetName, $pingTarget, $OutgoingPingsCount, $ScriptPath, $DEBUG, $debugLog, $ScriptStartTime
            $PingJobs += $job
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Started PING job ID $($job.Id) for $targetName ($pingTarget)"}
        } catch {
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Failed to start PING job for $targetName ($pingTarget): $($_.Exception.Message)"}
        }
    }
}

# Get CounterNames
$CounterNames = Get-PerflibCounterNames -Ids @(238, 6, 234, 200)
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CounterName: $($CounterNames[238])"}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CounterName: $($CounterNames[6])"}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CounterName: $($CounterNames[234])"}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CounterName: $($CounterNames[200])"}

# Network interfaces
if (-not [string]::IsNullOrEmpty($NetworkInterfaces)) {
    # Use the network interfaces specified in settings
    $NetworkInterfacesArray = $NetworkInterfaces -split ','
} else {
    # Automatically detect the network interfaces
    $NetworkInterfacesArray = @()
    $activeInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    foreach ($interface in $activeInterfaces) {
        $NetworkInterfacesArray += $interface.Name
    }
}

if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Network Interfaces: $($NetworkInterfacesArray -join ', ')"}

# Connection ports
$ConnectionPortsArray = @()
[int[]]$ConnectionPortsInt = @()
$Connections = @{}
$PortSampleCount = 0

if (-not [string]::IsNullOrWhiteSpace($ConnectionPorts)) {
    $ConnectionPortsArray = $ConnectionPorts -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\d+$' }
    if ($ConnectionPortsArray.Count -gt 0) {
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Using configured connection ports: $($ConnectionPortsArray -join ', ')"} 
    } elseif ($DEBUG -eq "1") {
        Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') No valid ports found in ConnectionPorts setting"
    }
} else {
    $autoPorts = Get-ListeningPorts
    if ($autoPorts.Count -gt 0) {
        $ConnectionPortsArray = $autoPorts | ForEach-Object { "$_" }
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Auto detected connection ports: $($ConnectionPortsArray -join ', ')"}
    } elseif ($DEBUG -eq "1") {
        Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') No external connection ports detected"
    }
}

if ($ConnectionPortsArray.Count -gt 0) {
    $ConnectionPortsInt = $ConnectionPortsArray | ForEach-Object { [int]$_ }
    foreach ($port in $ConnectionPortsArray) {
        $Connections[$port] = 0
    }
} elseif ($DEBUG -eq "1") {
    Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Port connection monitoring disabled (no ports configured or detected)"
}

# Initial network usage
$aRX = @{}
$aTX = @{}

# Loop through network interfaces
foreach ($NIC in $NetworkInterfacesArray) {
    try {
        $stats = Get-NicBytes -Name $NIC
        if ($stats.RX -ne $null) {
            $aRX[$NIC] = $stats.RX
            $aTX[$NIC] = $stats.TX
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Network Stats: $NIC - RX: $($aRX[$NIC]) - TX: $($aTX[$NIC])"}
        }
    } catch {
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Network Error: $NIC"}
    }
}

if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Network Stats: $($aRX -join ', ') - $($aTX -join ', ')"}

# Check processes/services
if (-not [string]::IsNullOrEmpty($CheckServices)) {
    $SRVCSR = @{}
    $CheckServicesArray = $CheckServices -split ','
    foreach ($serviceName in $CheckServicesArray) {
        $serviceStatus = Check-ProcessOrService -Name $serviceName
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Service: $serviceName - Status: $serviceStatus"}
        if ($SRVCSR.ContainsKey($serviceName)) {
            $SRVCSR[$serviceName] += $serviceStatus
        } else {
            $SRVCSR[$serviceName] = $serviceStatus
        }
    }
}

# Calculate how many data sample loops
$RunTimes = [math]::Floor(60 / $CollectEveryXSeconds)

if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') RunTimes: $RunTimes"}

# Initialise values
$total_cpuUsage = 0
$total_diskTime = 0

# Start persistent CPU job
$cpuJob = Start-Job -ScriptBlock {
    param($CounterNames, $SampleCount)
    while ($true) {
        $cpuCounter = Get-Counter "\$($CounterNames[238])(_Total)\$($CounterNames[6])" -SampleInterval 1 -MaxSamples $SampleCount
        $cpuAvg = ($cpuCounter.CounterSamples | Select-Object -ExpandProperty CookedValue | Measure-Object -Average).Average
        Write-Output $cpuAvg
    }
} -ArgumentList $CounterNames, $CollectEveryXSeconds

# Start persistent Disk job
$diskJob = Start-Job -ScriptBlock {
    param($CounterNames, $SampleCount)
    while ($true) {
        $diskCounter = Get-Counter "\$($CounterNames[234])(_Total)\$($CounterNames[200])" -SampleInterval 1 -MaxSamples $SampleCount
        $diskAvg = ($diskCounter.CounterSamples | Select-Object -ExpandProperty CookedValue | Measure-Object -Average).Average
        Write-Output $diskAvg
    }
} -ArgumentList $CounterNames, $CollectEveryXSeconds

# Collect data loop
for ($X = 1; $X -le $RunTimes; $X++) {
    if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Start Loop: $X"}

    # Retrieve CPU and Disk usage
    $cpuUsage = Wait-ForJobOutput -Job $cpuJob
    $diskTime = Wait-ForJobOutput -Job $diskJob

    if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CPU Usage: $cpuUsage - Disk Time: $diskTime"}

    # Add up the results
    $total_cpuUsage += [math]::Round($cpuUsage, 2)
    $total_diskTime += [math]::Round($diskTime, 2)

    if ($ConnectionPortsInt.Count -gt 0) {
        $connectionSample = Get-PortConnectionSample -Ports $ConnectionPortsInt
        foreach ($port in $ConnectionPortsArray) {
            if ($connectionSample.ContainsKey($port)) {
                $Connections[$port] += $connectionSample[$port]
            }
        }
        $PortSampleCount++
        if ($DEBUG -eq "1") {
            $sampleDebug = ($ConnectionPortsArray | ForEach-Object {
                $value = if ($connectionSample.ContainsKey($_)) { $connectionSample[$_] } else { 0 }
                "$_,$value"
            }) -join ';'
            Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Port sample: $sampleDebug"
        }
    }

    # Check if the minute has changed, so we can end the loop
    $MM = [int](Get-Date -Format 'mm')

    # If minute is empty or zero, set it to 0
    if (-not $MM) {
        $MM = 0
    }

    # Compare the current minute with the initial minute ($M)
    if ($MM -ne $M) {
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Break Loop: $X"}
        break
    }
    if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') End Loop: $X"}
}

# Stop and remove the jobs
Stop-Job $cpuJob, $diskJob
Remove-Job $cpuJob, $diskJob

# Get Win32_OperatingSystem
$Win32_OperatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem

# Get the OS name
$osName = $Win32_OperatingSystem.Caption
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') OS Name: $osName"}
$osName = Encode-Base64 -InputString $osName

# Get the OS version
$osVersion = $Win32_OperatingSystem.Version
$buildLabEx = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").BuildLabEx
if ($buildLabEx) {
    $osVersion += ",$buildLabEx"
}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') OS Version: $osVersion"}
$osVersion = Encode-Base64 -InputString $osVersion

# Get the hostname
$hostname = $env:COMPUTERNAME
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Hostname: $hostname"}
$hostname = Encode-Base64 -InputString $hostname

# Get current time
$time = Get-Date -Format "yyyy-MM-dd HH:mm:ss zzz"
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Time: $time"}
$time = Encode-Base64 -InputString $time

# Get Reboot Required
$needsRestart = "0"
if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
    $needsRestart = "1"
}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Reboot Required: $needsRestart"}

# Get the system uptime
$uptime = $Win32_OperatingSystem.LastBootUpTime
$uptime = [math]::Round((New-TimeSpan -Start $uptime -End (Get-Date)).TotalSeconds, 0)
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Uptime: $uptime"}

# Get the CPU information
$sysInfo = Get-CimInstance -ClassName Win32_Processor

# Get the CPU model
$cpuModel = $sysInfo[0].Name
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CPU Model: $cpuModel"}
$cpuModel = Encode-Base64 -InputString $cpuModel

# Get the CPU sockets
$cpuSockets = ($sysInfo | Measure-Object).Count
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CPU Sockets: $cpuSockets"}

# Get the number of CPU cores
$cpuCores = $sysInfo.NumberOfCores
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CPU Cores: $cpuCores"}

# Get the number of CPU threads
$cpuThreads = $sysInfo.NumberOfLogicalProcessors
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CPU Threads: $cpuThreads"}

# Get the CPU Frequency
$cpuFreq = [math]::Round(($sysInfo | Measure-Object -Property CurrentClockSpeed -Average).Average)
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CPU Frequency: $cpuFreq"}

# Calculate CPU Usage
$cpuUsage = [math]::Round($total_cpuUsage / $X, 2)
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') CPU Usage: $cpuUsage"}

# Get the disk I/O wait time
$diskTime = [math]::Round($total_diskTime / $X, 2)
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Disk Time: $diskTime"}

# Get the total RAM
$totalMemory = $Win32_OperatingSystem.TotalVisibleMemorySize * 1024
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Total Memory: $totalMemory"}

# Get the free RAM
$freeMemory = $Win32_OperatingSystem.FreePhysicalMemory * 1024
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Free Memory: $freeMemory"}

# Calculate used memory
$usedMemory = $totalMemory - $freeMemory
$usedMemory = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Used Memory: $usedMemory"}

# Get swap (paging file) information
$swapInfo = Get-CimInstance -ClassName Win32_PageFileUsage

# Get the total swap size
$totalSwapSize = ($swapInfo | Measure-Object -Property AllocatedBaseSize -Sum).Sum * 1024 * 1024
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Total Swap Size: $totalSwapSize"}

# Get the used swap size
$usedSwapSize = ($swapInfo | Measure-Object -Property CurrentUsage -Sum).Sum * 1024 * 1024
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Used Swap Size: $usedSwapSize"}

# Calculate swap usage percentage
if($totalSwapSize -and $usedSwapSize -and ($totalSwapSize -is [int] -or $totalSwapSize -is [double]) -and ($usedSwapSize -is [int] -or $usedSwapSize -is [double])) {
    $swapUsage = [math]::Round(($usedSwapSize / $totalSwapSize) * 100, 2)
} else {
    $swapUsage = 0
}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Swap Usage: $swapUsage"}

# Get disk information and usage details
$disksInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 }
$allDiskData = @()
foreach ($disk in $disksInfo) {
    try {
        $diskUsage = Get-PSDrive -Name $disk.DeviceID.Substring(0,1)
        $totalSize = $disk.Size
        $usedSize = $disk.Size - $disk.FreeSpace

        # Format and add the disk data
        $diskData = "$($disk.DeviceID),$($totalSize),$($usedSize),$($disk.FreeSpace)"
        $allDiskData += $diskData
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Disk Data: $diskData"}
    } catch {
        # Ignore any errors for unavailable disks
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Disk Error: $disk"}
    }
}

# Join all disk data into a single string
$disks = ($allDiskData -join ';') + ';'
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Disks: $disks"}
$disks = Encode-Base64 -InputString $disks

# Disk Health
$DH = ""
if ($CheckDriveHealth -eq "1") {
    $CheckDriveHealth = Get-PhysicalDisk
    foreach ($disk in $CheckDriveHealth) {
        $wearLevel = 0
        $powerCycleCount = 0
        $powerOnHours = 0
        $unsafeShutdownCount = 0
        $writeErrorsTotal = 0
        $writeErrorsCorrected = 0
        $writeErrorsUncorrected = 0
        $temperature = 0
        try {
            $reliabilityData = Get-StorageReliabilityCounter -PhysicalDisk $disk
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Disk Health: $($disk.DeviceID) - $($reliabilityData.Wear) - $($reliabilityData.PowerCycleCount) - $($reliabilityData.PowerOnHours) - $($reliabilityData.StartStopCycleCount) - $($reliabilityData.WriteErrorsTotal) - $($reliabilityData.WriteErrorsCorrected) - $($reliabilityData.WriteErrorsUncorrected) - $($reliabilityData.Temperature)"}
            if ($reliabilityData) {
                $wearLevel = $reliabilityData.Wear
                $powerCycleCount = $reliabilityData.PowerCycleCount
                $powerOnHours = $reliabilityData.PowerOnHours
                $unsafeShutdownCount = $reliabilityData.StartStopCycleCount
                $writeErrorsTotal = $reliabilityData.WriteErrorsTotal
                $writeErrorsCorrected = $reliabilityData.WriteErrorsCorrected
                $writeErrorsUncorrected = $reliabilityData.WriteErrorsUncorrected
                $temperature = $reliabilityData.Temperature
            }
        } catch {
            # Ignore any errors for unavailable disks
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Disk Health Error: $disk"}
        }
        $DH += "$($disk.DeviceID),$($disk.MediaType),$($disk.FriendlyName),$($disk.SerialNumber),$($disk.OperationalStatus),$($disk.HealthStatus),$wearLevel,$powerCycleCount,$powerOnHours,$unsafeShutdownCount,$writeErrorsTotal,$writeErrorsCorrected,$writeErrorsUncorrected,$temperature;"
    }
    $DH = Encode-Base64 -InputString $DH
}

# Total network usage and IP addresses
$RX = 0
$TX = 0
$NICS = ""
$IPv4 = ""
$IPv6 = ""
$tTIMEDIFF = ([datetime]::UtcNow - $START).TotalSeconds
# Loop through network interfaces
foreach ($NIC in $NetworkInterfacesArray) {
    try {
        $adapterStats = Get-NicBytes -Name $NIC

        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Network Stats: $NIC - RX: $($adapterStats.RX) - TX: $($adapterStats.TX)"}

        if ($adapterStats.RX -ne $null) {
            $rxDiff = $adapterStats.RX - $aRX[$NIC]
            $RX = [math]::Round($rxDiff / $tTIMEDIFF, 0)

            $txDiff = $adapterStats.TX - $aTX[$NIC]
            $TX = [math]::Round($txDiff / $tTIMEDIFF, 0)

            # Add the RX and TX values to the string
            $NICS += "$NIC,$RX,$TX;"

            # Individual NIC IP addresses
            $ipv4Addresses = (Get-NetIPAddress -InterfaceAlias $NIC -AddressFamily IPv4 | Where-Object {
                ($_ -ne $null) -and ($_ -match '^(?!10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)')
            }).IPAddress -join ","
            if (Get-NetAdapter -Name $NIC -ErrorAction SilentlyContinue) {
                $ipv6Addresses = (Get-NetIPAddress -InterfaceAlias $NIC -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object {
                    ($_ -ne $null) -and ($_.IPAddress -notmatch '^(fe80::|fd00::|fc00::)')
                }).IPAddress -join ","
                if (!$ipv6Addresses) {
                    $ipv6Addresses = ""
                }
            } else {
                $ipv6Addresses = ""
            }
            $IPv4 += "$NIC,$ipv4Addresses;"
            $IPv6 += "$NIC,$ipv6Addresses;"
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Network Stats: $NIC - RX: $RX - TX: $TX - IPv4: $ipv4Addresses - IPv6: $ipv6Addresses"}
        }
    } catch {
        # Ignore any errors for unavailable NICs
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Network Error: $NIC"}
    }
}
$NICS = Encode-Base64 -InputString $NICS
$IPv4 = Encode-Base64 -InputString $IPv4
$IPv6 = Encode-Base64 -InputString $IPv6

$CONN = ""
if ($ConnectionPortsArray.Count -gt 0) {
    foreach ($port in $ConnectionPortsArray) {
        $average = if ($PortSampleCount -gt 0) {
            [math]::Round($Connections[$port] / $PortSampleCount, 0)
        } else {
            0
        }
        $CONN += "$port,$average;"
    }
    if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Port connections: $CONN"}
    $CONN = Encode-Base64 -InputString $CONN
}

# Check processes/services
$SRVCS = ""
if (-not [string]::IsNullOrEmpty($CheckServices)) {
    foreach ($serviceName in $CheckServicesArray) {
        $serviceStatus = Check-ProcessOrService -Name $serviceName
        if ($SRVCSR.ContainsKey($serviceName)) {
            $SRVCSR[$serviceName] += $serviceStatus
        } else {
            $SRVCSR[$serviceName] = $serviceStatus
        }
        # Append to the SRVCS string based on the status
        if ($SRVCSR[$serviceName] -eq 0) {
            $SRVCS += "$serviceName,0;"
        } else {
            $SRVCS += "$serviceName,1;"
        }
    }
}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Services: $SRVCS"}
$SRVCS = Encode-Base64 -InputString $SRVCS

# Wait for Outgoing PING jobs to complete (best effort)
if ($PingJobs.Count -gt 0) {
    $pingTimeout = 30
    if ($OutgoingPingsCount -match '^\d+$') {
        $countForTimeout = [int]$OutgoingPingsCount
        if ($countForTimeout -gt 0) {
            $pingTimeout = [math]::Min(60, $countForTimeout + 10)
        }
    }
    if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Waiting for PING jobs (timeout ${pingTimeout}s)"}
    Wait-Job -Job $PingJobs -Timeout $pingTimeout | Out-Null
    foreach ($job in $PingJobs) {
        if ($job.State -eq 'Running') {
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') PING job $($job.Id) timed out"}
            Stop-Job -Job $job -Force -ErrorAction SilentlyContinue
        }
        Receive-Job -Job $job -ErrorAction SilentlyContinue | Out-Null
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
    }
}

# Outgoing PING
$OPING = ""
if (-not [string]::IsNullOrEmpty($OutgoingPings)) {
    $pingFile = Join-Path $ScriptPath 'ping.txt'
    if (Test-Path $pingFile) {
        try {
            $pingLines = Get-Content -Path $pingFile -ErrorAction Stop | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            if ($pingLines.Count -gt 0) {
                $pingJoined = $pingLines -join ''
                $OPING = Encode-Base64 -InputString $pingJoined
            }
        } catch {
            if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Failed to read ping.txt: $($_.Exception.Message)"}
        } finally {
            Remove-Item -Path $pingFile -Force -ErrorAction SilentlyContinue
        }
    } elseif ($DEBUG -eq "1") {
        Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') ping.txt not found"
    }
}
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') OPING: $OPING"}

# Create a custom object with all the data
$Data = [PSCustomObject]@{
    version = $Version
    SID = $SID
    os = $osName
    kernel = $osVersion
    hostname = $hostname
    time = $time
    reqreboot = $needsRestart
    uptime = $uptime
    cpumodel = $cpuModel
    cpusockets = $cpuSockets
    cpucores = $cpuCores
    cputhreads = $cpuThreads
    cpuspeed = $cpuFreq
    cpu = $cpuUsage
    wa = $diskTime
    ramsize = $totalMemory
    ram = $usedMemory
    ramswapsize = $totalSwapSize
    ramswap = $swapUsage
    disks = $disks
    nics = $NICS
    ipv4 = $IPv4
    ipv6 = $IPv6
    conn = $CONN
    serv = $SRVCS
    oping = $OPING
    dh = $DH
}

# Convert the custom object to JSON
$Data = $Data | ConvertTo-Json
if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Data: $Data"}

# Send the data
$APIURL = "https://sm.hetrixtools.net/win/"
$Headers = @{}
$ContentType = 'application/json; charset=utf-8'
$MaxRetries = 3
$Timeout = 15
$RetryCount = 0
$Success = $false
while ($RetryCount -lt $MaxRetries -and -not $Success) {
    try {
        $startTime = Get-Date
        $Response = Invoke-RestMethod -Uri $APIURL -Method Post -Headers $Headers -ContentType $ContentType -Body $Data -TimeoutSec $Timeout -ErrorAction Stop
        $endTime = Get-Date
        $responseTime = [math]::Round(($endTime - $startTime).TotalMilliseconds, 0)
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Response: $Response | Status: 200 | Time: ${responseTime}ms"}
        $Success = $true
    } catch {
        $errorMessage = "Exception: $($_.Exception.Message)"
        $statusCode = $null
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            $errorMessage += " | Status Code: $statusCode"
        }
        if ($_.Exception.InnerException) {
            $errorMessage += " | Inner Exception: $($_.Exception.InnerException.Message)"
        }
        if ($DEBUG -eq "1") {Add-Content -Path $debugLog -Value "$ScriptStartTime-$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') Error: $errorMessage | Attempt: $($RetryCount + 1) of $MaxRetries"}
        $RetryCount++
        if ($RetryCount -ne $MaxRetries) {
            Start-Sleep -Seconds 1
        }
    }
}
