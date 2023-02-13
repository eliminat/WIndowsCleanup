##### Windows Cleanup PowerShell Script #####
##### Targeted at Windows 10 and later #####
##### Written By: eliminat #####



### Check for Admin
function CheckAdmin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((CheckAdmin) -eq $false) {
    if ($elevated) {
        # could not elevate, quit
    }
    else {
        # Detecting Powershell (powershell.exe) or Powershell Core (pwsh), will return true if Powershell Core (pwsh)
        if ($IsCoreCLR) { $PowerShellCmdLine = "pwsh.exe" } else { $PowerShellCmdLine = "powershell.exe" }
        $CommandLine = "-noprofile -ExecutionPolicy Bypass -File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments + ' -Elevated'
        Start-Process "$PSHOME\$PowerShellCmdLine" -Verb RunAs -ArgumentList $CommandLine
    }
    Exit
}

### Write to Console and Log File
function Out-Log {
    param([string]$logstring)

        # Set Date for Log
    $LogDate = Get-Date -Format "MM-d-yy-HHmm"

    $logfile = Join-Path $PWD.Path "disk_cleanup_log.txt"
    Add-Content -Path $logfile -Value $logstring
    Write-Host $logstring
}


### Clean DISM
function Clean-DISM {
  $dismOutput = dism.exe /Online /Cleanup-Image /StartComponentCleanup
  Out-Log("DISM cleanup completed.")
}

### Clean Additional Windows Files/Logs
function Clean-AdditionalFiles {
  $additionalFiles = @(
    "$env:windir\logs\CBS\CBS.log",
    "$env:windir\memory.dmp",
    "$env:windir\minidump*.dmp"
    

  )
    foreach ($file in $additionalFiles) {
    if (Test-Path $file) {
      Remove-Item $file -Force
      Out-Log("$file cleaned.")
    }
  }
    
    Remove-Item "$env:SYSTEMROOT\SoftwareDistribution\Download\*" -Force -Recurse
    Out-Log("SoftwareDistribution\Download\ cleaned")
    # Clear Windows log files
    wevtutil.exe cl Application
    wevtutil.exe cl System
    wevtutil.exe cl Security

    Out-Log("Cleaned Windows Event Logs")
}

### Clean Windows Temp Files
function Clean-WindowsTempFiles {
  $tempDirectory = "$env:windir\temp"
  Remove-Item $tempDirectory\* -Force -Recurse
  Out-Log("Windows temp files cleaned.") | Out-Log
}

### Clean User Temp Files
function Clean-UserTempFiles {
    # Clear all user temp files
    # These files can safely be deleted, as they are only used temporarily
    # by applications and can be safely removed at any time
    Get-ChildItem -Path "C:\Users" -Directory | ForEach-Object {
        $usertemp = Join-Path $_.FullName "AppData\Local\Temp\*"
        $items = Get-ChildItem -Path $usertemp -Force -Recurse -ErrorAction SilentlyContinue
        if ($items) {
            $items | Remove-Item -Force -Recurse -Verbose
            Out-Log("Cleaned $usertemp")
        }
        $wer = Join-Path $_.FullName "AppData\Local\Microsoft\Windows\WER\*"
        $items = Get-ChildItem -Path $wer -Force -Recurse -ErrorAction SilentlyContinue
        if ($items) {
            $items | Remove-Item -Force -Recurse -Verbose
            Out-Log("Cleaned $wer")
        }
        $thumbnail = Join-Path $_.FullName "AppData\Local\Windows\Explorer\*"
        $items = Get-ChildItem -Path $thumbnail -Force -Recurse -ErrorAction SilentlyContinue
        if ($items) {
            $items | Remove-Item -Force -Recurse -Verbose
            Out-Log("Cleaned $thumbnail")
        }
    }
}

### Clean Browser Caches for all users
function Clean-BrowserCacheFiles {
    # Clean up browser cache files for all users
    $Browsers = @(
        @{ Name = 'Edge'; Path = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge_*\AC\MicrosoftEdge\Cache\*"; },
        @{ Name = 'Firefox'; Path = "$env:ProgramFiles\Mozilla Firefox\cache2\entries\*"; },
        @{ Name = 'Chrome'; Path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*"; },
        @{ Name = 'Brave'; Path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Cache\*"; },
        @{ Name = 'Vivaldi'; Path = "$env:LOCALAPPDATA\Vivaldi\User Data\Default\Cache\*"; }
    )

    foreach ($Browser in $Browsers) {
        $BrowserPath = Get-ChildItem -Path $Browser.Path -Recurse -Force -ErrorAction SilentlyContinue
        if ($BrowserPath) {
            Remove-Item -Path $BrowserPath.FullName -Force -Recurse
            Out-Log("Removed items from $($Browser.Name) cache")
        }
    }
}

### Run Disk Cleanup
function Clean-DiskCleanup{
    # Clean up other temporary files
    # These files are used by various Windows components
    Start-Process -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1"
    Out-Log("Started Disk Cleanup Utility")
}

##### MAIN #####

# Get the free disk space before cleanup
$before = (Get-PSDrive C).Free


Clean-WindowsTempFiles

Clean-UserTempFiles

Clean-BrowserCacheFiles

Clean-DiskCleanup

Clean-DISM

Clean-AdditionalFiles

# Get the free disk space after cleanup
$after = (Get-PSDrive C).Free

# Calculate the amount of disk space that was freed up
$freed = $after - $before

# Output the amount of free disk space freed by the cleanup
Out-Log("Free disk space before cleanup: $($before / 1GB) GB")
Out-Log("Free disk space after cleanup: $($after / 1GB) GB")
Out-Log("Freed disk space: $($freed / 1GB) GB")
