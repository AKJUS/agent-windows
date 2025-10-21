#
#	HetrixTools Server Monitoring Agent - Install Script
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

# Branch
$BRANCH = "main"

# Check if the operating system is 64-bit
$is64BitOS = ([Environment]::Is64BitOperatingSystem)
# Check if the current PowerShell process is 32-bit
$is32BitProcess = -not ([Environment]::Is64BitProcess)
if ($is64BitOS -and $is32BitProcess) {
    Write-Host "Error: Please run this script in a 64-bit PowerShell session."
    exit
}

# Check if the script is running with elevated privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "Error: Please run this script as an Administrator."
    exit
}

# Make sure older versions of PowerShell are configured to allow TLS 1.2
# OSVersion needs to be considered to prevent downgrading stronger SystemDefault on newer versions of Windows Server
$commonSecurityProtocols = [Net.SecurityProtocolType]::Tls12
if ([System.Environment]::OSVersion.Version.Build -lt 17763 -and [Net.ServicePointManager]::SecurityProtocol -lt $commonSecurityProtocols) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $commonSecurityProtocols
}

# Find and uninstall v1 agent
Write-Host "Checking for old agent..."
$processName = "HetrixToolsAgent.exe"
$processes = Get-CimInstance Win32_Process | Where-Object { $_.Name -eq $processName }
$paths = @()
if ($processes) {
    foreach ($process in $processes) {
        $processPath = $process.ExecutablePath
        if ($processPath) {
            Write-Host "Found process $($process.ProcessId) running from path $processPath"
            $paths += $processPath.Trim()
        } else {
            Write-Host "Unable to retrieve the path for the process $($process.ProcessId)."
        }
    }
    $uniquePaths = $paths | Select-Object -Unique
    if ($uniquePaths.Count -eq 1) {
        $finalPath = $uniquePaths
        Write-Host "The unique path for all instances is $finalPath"
        Write-Host "Uninstalling the old agent..."
        & "$finalPath" stop
        & "$finalPath" remove
        & taskkill /IM "HetrixToolsAgent.exe" /F
    } else {
        Write-Host "Error: Cannot uninstall the old agent because there are multiple instances running from different paths."
        Write-Host "Please manually uninstall the old agent and then re-run this install script again."
        exit 1
    }
}
Write-Host "... done."

# Determine the branch/version and parse installation arguments
$argIndex = 0
if ($args.Count -eq 0) {
    Write-Host "Error: No installation arguments provided."
    exit
}

$potentialBranch = $args[$argIndex]
$potentialBranchTrimmed = if ($null -ne $potentialBranch) { $potentialBranch.Trim() } else { "" }
if (-not [string]::IsNullOrWhiteSpace($potentialBranchTrimmed) -and $potentialBranchTrimmed.Length -ne 32) {
    $BRANCH = $potentialBranchTrimmed
    $argIndex++
    Write-Host "Installing from $BRANCH branch..."
}

# Check if the selected branch exists
Write-Host "Checking if the selected branch exists..."
$branchCheckUrl = "https://raw.githubusercontent.com/hetrixtools/agent-windows/$BRANCH/hetrixtools_agent.ps1"
try {
    $branchRequest = [System.Net.WebRequest]::Create($branchCheckUrl)
    $branchRequest.Method = "HEAD"
    $branchRequest.Timeout = 15000
    $branchResponse = $branchRequest.GetResponse()
    $branchResponse.Close()
    Write-Host "... done."
} catch {
    Write-Host "Error: Branch '$BRANCH' does not exist in the remote repository. Please specify a valid branch name."
    exit 1
}

if ($args.Count -le $argIndex) {
    Write-Host "Error: Server ID is missing."
    exit
}

$SID = $args[$argIndex].Trim()
$argIndex++

$servicesArgument = "0"
if ($args.Count -gt $argIndex) {
    $servicesValue = $args[$argIndex]
    if ($null -ne $servicesValue) {
        $servicesArgument = $servicesValue.Trim()
    } else {
        $servicesArgument = ""
    }
    $argIndex++
}

$driveHealthArgument = "0"
if ($args.Count -gt $argIndex) {
    $driveValue = $args[$argIndex]
    if ($null -ne $driveValue) {
        $driveHealthArgument = $driveValue.Trim()
    } else {
        $driveHealthArgument = ""
    }
    $argIndex++
}

$portsArgument = "0"
if ($args.Count -gt $argIndex) {
    $portsValue = $args[$argIndex]
    if ($null -ne $portsValue) {
        $portsArgument = $portsValue.Trim()
    } else {
        $portsArgument = ""
    }
    $argIndex++
}

Write-Host "Checking Server ID (SID)..."
if ([string]::IsNullOrWhiteSpace($SID)) {
    Write-Host "Error: Server ID is empty."
    exit
}
Write-Host "... done."

# Installation folder
$folderPath = "C:\Program Files\HetrixTools"

# Check if the folder exists
Write-Host "Checking installation folder..."
if (-Not (Test-Path -Path $folderPath)) {
    # Create the folder if it does not exist
    New-Item -Path $folderPath -ItemType Directory
} else {
    Write-Host "Folder already exists: $folderPath"
    # Delete the old agent
    Write-Host "Deleting the old agent..."
    Remove-Item -Path $folderPath -Recurse
    Write-Host "... done."
    # Create the folder
    Write-Host "Creating the folder..."
    New-Item -Path $folderPath -ItemType Directory
}
Write-Host "... done."

# Download the agent
Write-Host "Downloading the agent..."
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("https://raw.githubusercontent.com/hetrixtools/agent-windows/$BRANCH/hetrixtools_agent.ps1", "$folderPath\hetrixtools_agent.ps1")
Write-Host "... done."
Write-Host "Downloading the config file..."
$wc.DownloadFile("https://raw.githubusercontent.com/hetrixtools/agent-windows/$BRANCH/hetrixtools.cfg", "$folderPath\hetrixtools.cfg")
Write-Host "... done."

# Insert the Server ID into the config file
Write-Host "Inserting the Server ID into the config file..."
(Get-Content "$folderPath\hetrixtools.cfg") | ForEach-Object { $_ -replace "SID=", "SID=$SID" } | Set-Content "$folderPath\hetrixtools.cfg"

# Check if any processes/services need to be monitored
Write-Host "Checking if any processes/services need to be monitored..."
if (-not [string]::IsNullOrWhiteSpace($servicesArgument) -and $servicesArgument -ne "0") {
    # Insert the processes/services into the config file
    Write-Host "Inserting the processes/services into the config file..."
    # Split the string into an array and filter out empty elements
    $processesString = ($servicesArgument.Split(",") | Where-Object { $_.Trim() -ne "" }) -join ","
    (Get-Content "$folderPath\hetrixtools.cfg") | ForEach-Object { $_ -replace "CheckServices=", "CheckServices=$processesString" } | Set-Content "$folderPath\hetrixtools.cfg"
}
Write-Host "... done."

# Check if Drive Health Monitoring is enabled
Write-Host "Checking if Drive Health Monitoring is enabled..."
if ($driveHealthArgument -eq "1") {
    # Insert the Drive Health Monitoring into the config file
    Write-Host "Inserting the Drive Health Monitoring into the config file..."
    (Get-Content "$folderPath\hetrixtools.cfg") | ForEach-Object { $_ -replace "CheckDriveHealth=0", "CheckDriveHealth=1" } | Set-Content "$folderPath\hetrixtools.cfg"
}
Write-Host "... done."

# Check if any port connections need to be monitored
Write-Host "Checking if any connection ports need to be monitored..."
if (-not [string]::IsNullOrWhiteSpace($portsArgument) -and $portsArgument -ne "0") {
    Write-Host "Inserting the connection ports into the config file..."
    $portsString = ($portsArgument.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }) -join ","
    if ($portsString) {
        (Get-Content "$folderPath\hetrixtools.cfg") | ForEach-Object { $_ -replace "ConnectionPorts=", "ConnectionPorts=$portsString" } | Set-Content "$folderPath\hetrixtools.cfg"
    }
}
Write-Host "... done."

# Create the scheduled task
Write-Host "Checking the scheduled task..."
$taskName = "HetrixTools Server Monitoring Agent"
$processName = "powershell.exe"
$scriptName = "hetrixtools_agent.ps1"
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "The scheduled task already exists..."
    # Find the processes matching the script being executed by the scheduled task
    Write-Host "Finding any running processes executed by the existing scheduled task..."
    $processes = Get-Process | Where-Object {
        $_.ProcessName -like "powershell*" -or $_.ProcessName -like "pwsh*"
    }
    foreach ($process in $processes) {
        try {
            $cmdLine = (Get-CimInstance Win32_Process -Filter "ProcessId = $($process.Id)").CommandLine
            if ($cmdLine -like "*$scriptName*") {
                Write-Host "Found process $($process.Id)"
                try {
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    Write-Host "Terminated process $($process.Id)"
                } catch {
                    Write-Host "Failed to terminate process $($process.Id)"
                }
            }
        } catch {
            Write-Host "Unable to access command line for process $($process.Id)."
        }
    }
    Write-Host "Deleting the existing scheduled task..."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}
Write-Host "... done."
Write-Host "Creating the new scheduled task..."
# Calculate the next full minute
$currentTime = Get-Date
$nextFullMinute = $currentTime.AddMinutes(1).Date.AddHours($currentTime.Hour).AddMinutes($currentTime.Minute)
# Define task action
$taskAction = New-ScheduledTaskAction -Execute $processName -Argument "-ExecutionPolicy Bypass -File `"$folderPath\hetrixtools_agent.ps1`""
# Define task trigger to start at the next full minute and repeat every minute
$taskTrigger = New-ScheduledTaskTrigger -Once -At $nextFullMinute -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration (New-TimeSpan -Days 9999)
# Define task principal
$taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
# Define task settings with parallel execution and execution time limit
$taskSettings = New-ScheduledTaskSettingsSet -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances Parallel
# Register the scheduled task
Register-ScheduledTask -TaskName $taskName -Action $taskAction -Trigger $taskTrigger -Settings $taskSettings -Principal $taskPrincipal
# Set the execution time limit explicitly using Set-ScheduledTask
$task = Get-ScheduledTask -TaskName $taskName
$task.Settings.ExecutionTimeLimit = "PT2M"
Set-ScheduledTask -TaskName $taskName -TaskPath "\" -Settings $task.Settings
Write-Host "... done."

# Start the scheduled task
$currentSecond = (Get-Date).Second
if ($currentSecond -ge 2 -and $currentSecond -le 50) {
    Write-Host "Starting the scheduled task..."
    Start-ScheduledTask -TaskName $taskName
    Write-Host "... done."
}

# Confirm installation
Write-Host "Letting HetrixTools know the installation has been completed..."
# Create a custom object with all the data
$Data = [PSCustomObject]@{
    version = 'install'
    SID = $SID
}
# Convert the object to JSON
$Data = $Data | ConvertTo-Json
# Send the data
$APIURL = "https://sm.hetrixtools.net/win/"
$Headers = @{
    'Content-Type' = 'application/json'
}
$MaxRetries = 3
$Timeout = 15
$RetryCount = 0
$Success = $false
while ($RetryCount -lt $MaxRetries -and -not $Success) {
    try {
        $Response = Invoke-RestMethod -Uri $APIURL -Method Post -Headers $Headers -Body $Data -TimeoutSec $Timeout
        $Success = $true
    } catch {
        $RetryCount++
        if ($RetryCount -ne $MaxRetries) {
            Start-Sleep -Seconds 1
        }
    }
}
Write-Host "... done."

Write-Host "Installation completed successfully."
