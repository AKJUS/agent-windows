#
#	HetrixTools Server Monitoring Agent - Uninstall Script
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

# Get the Server ID
$SID = $args[0]

# Make sure the SID is not empty
Write-Host "Checking Server ID (SID)..."
if ($SID -eq "") {
    Write-Host "No Server ID provided."
}
Write-Host "... done."

# Installation folder
$folderPath = "C:\Program Files\HetrixTools"

# Check if the folder exists
Write-Host "Checking installation folder..."
if (-Not (Test-Path -Path $folderPath)) {
    Write-Host "Folder does not exist: $folderPath"
} else {
    Write-Host "Folder already exists: $folderPath"
    # Delete the old agent
    Write-Host "Deleting the old agent..."
    Remove-Item -Path $folderPath -Recurse
}
Write-Host "... done."

# Delete the scheduled task
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

# If SID not empty, send the uninstallation notice to HetrixTools
if ($SID -ne "") {
    # Confirm uninstallation
    Write-Host "Letting HetrixTools know the uninstallation has been completed..."
    # Create a custom object with all the data
    $Data = [PSCustomObject]@{
        version = 'uninstall'
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
}

Write-Host "Uninstallation completed successfully."