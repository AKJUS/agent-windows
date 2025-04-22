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

# Branch
if ($args.Count -ge 1 -and $args[0]) {
    $BRANCH = $args[0]
} else {
    $BRANCH = "main"
}

# Check if the branch exists in the remote repository
$branchCheckUrl = "https://raw.githubusercontent.com/hetrixtools/agent-windows/$BRANCH/hetrixtools_agent.ps1"
try {
    $request = Invoke-WebRequest -Uri $branchCheckUrl -Method Head -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Host "Branch '$BRANCH' does not exist in the remote repository. Please specify a valid branch name."
    exit 1
}

# Check if the operating system is 64-bit
$is64BitOS = ([Environment]::Is64BitOperatingSystem)
# Check if the current PowerShell process is 32-bit
$is32BitProcess = -not ([Environment]::Is64BitProcess)
if ($is64BitOS -and $is32BitProcess) {
    Write-Host "Please run this script in a 64-bit PowerShell session."
    exit 1
}

# Check if the script is running with elevated privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if (-not $isAdmin) {
    Write-Host "Please run this script as an Administrator."
    exit 1
}

# Make sure older versions of PowerShell are configured to allow TLS 1.2
# OSVersion needs to be considered to prevent downgrading stronger SystemDefault on newer versions of Windows Server
$commonSecurityProtocols = [Net.SecurityProtocolType]::Tls12
if ([System.Environment]::OSVersion.Version.Build -lt 17763 -and [Net.ServicePointManager]::SecurityProtocol -lt $commonSecurityProtocols) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor $commonSecurityProtocols
}

# Installation folder
$folderPath = "C:\Program Files\HetrixTools"
# Check if the folder exists
if (-not (Test-Path $folderPath)) {
    Write-Host "Installation folder not found. Please run the installation script first."
    exit 1
}

# Load configuration file
$ConfigFile = "$folderPath\hetrixtools.cfg"
if (-not (Test-Path $ConfigFile)) {
    Write-Host "Configuration file not found. Please run the installation script first."
    exit 1
}

# Function to parse the configuration file
function Get-ConfigValue {
    param (
        [string]$Key
    )
    
    # Read the file and find the line containing the key
    $line = Get-Content $ConfigFile | Where-Object { $_ -match "^$Key=" }
    if ($line) {
        return $line.Split('=')[1].Trim().Trim('"', "'")
    } else {
        exit 1
    }
}

# Helper function to update a config line
function Update-ConfigLine {
    param (
        [string[]]$lines,
        [string]$key,
        [string]$value,
        [bool]$quoteValue = $false
    )
    $pattern = "^$key="
    $replacement = if ($quoteValue) { "$key=`"$value`"" } else { "$key=$value" }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match $pattern) {
            $lines[$i] = $replacement
        }
    }
    return $lines
}

# Configs
$SID = Get-ConfigValue -Key "SID"
$CollectEveryXSeconds = Get-ConfigValue -Key "CollectEveryXSeconds"
$NetworkInterfaces = Get-ConfigValue -Key "NetworkInterfaces"
$CheckServices = Get-ConfigValue -Key "CheckServices"
$CheckDriveHealth = Get-ConfigValue -Key "CheckDriveHealth"
$DEBUG = Get-ConfigValue -Key "DEBUG"

# Download the agent
$wc = New-Object System.Net.WebClient
Write-Host "Downloading the agent..."
try {
    $wc.DownloadFile("https://raw.githubusercontent.com/hetrixtools/agent-windows/$BRANCH/hetrixtools_agent.ps1", "$folderPath\hetrixtools_agent.ps1")
    Write-Host "... done."
    if ((Get-Item "$folderPath\hetrixtools_agent.ps1").Length -eq 0) {
        Write-Host "Downloaded agent script is empty. Please check your network connection and branch name."
        $wc.Dispose()
        exit 1
    }
} catch {
    Write-Host "Failed to download the agent script. Please check your network connection and branch name."
    $wc.Dispose()
    exit 1
}
Write-Host "Downloading the config file..."
try {
    $wc.DownloadFile("https://raw.githubusercontent.com/hetrixtools/agent-windows/$BRANCH/hetrixtools.cfg", "$folderPath\hetrixtools.cfg")
    Write-Host "... done."
    if ((Get-Item "$folderPath\hetrixtools.cfg").Length -eq 0) {
        Write-Host "Downloaded config file is empty. Please check your network connection and branch name."
        $wc.Dispose()
        exit 1
    }
} catch {
    Write-Host "Failed to download the config file. Please check your network connection and branch name."
    $wc.Dispose()
    exit 1
}
$wc.Dispose()

# Read config file into memory
$configLines = Get-Content "$folderPath\hetrixtools.cfg"

# Update all config values in memory
$configLines = Update-ConfigLine -lines $configLines -key "SID" -value $SID
$configLines = Update-ConfigLine -lines $configLines -key "CollectEveryXSeconds" -value $CollectEveryXSeconds
$configLines = Update-ConfigLine -lines $configLines -key "NetworkInterfaces" -value $NetworkInterfaces -quoteValue $true
$configLines = Update-ConfigLine -lines $configLines -key "CheckServices" -value $CheckServices -quoteValue $true
$configLines = Update-ConfigLine -lines $configLines -key "CheckDriveHealth" -value $CheckDriveHealth
$configLines = Update-ConfigLine -lines $configLines -key "DEBUG" -value $DEBUG

# Write back to file once
Set-Content "$folderPath\hetrixtools.cfg" $configLines

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
            Write-Host "Error accessing command line for process $($process.Id)."
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

Write-Host "Update completed successfully."