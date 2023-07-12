param(
    [parameter(Mandatory=$False)]
    [String]$LogPath
)

if($PSBoundParameters.ContainsKey('LogPath') -eq $false){
    $LogPath = "C:\Temp"
}

$timeStr = get-date -f 'yyyy-MM-dd-HHmmss' 
$LogFile = $LogPath + "\" + $timeStr + ".log"


Start-Transcript -Path $LogFile -NoClobber

Write-Host "Stopping Wavesor Processes"
Get-Process wavebrowser -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process SWUpdater -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep 2

$user_list = Get-Item C:\users\* | Select-Object Name -ExpandProperty Name
foreach ($User in $user_list) {
    if ($User -notlike "*Public*") {
        $exists = test-path -path "C:\users\$user\Wavesor Software"
        if ($exists -eq $True) {
            Write-Host "Found C:\users\$user\Wavesor Software. Removing..."
            Remove-Item "C:\users\$user\Wavesor Software" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$user\Wavesor Software"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$user\Wavesor Software"
            }
        }
        $exists = test-path -path "C:\users\$user\WebNavigatorBrowser"
        if ($exists -eq $True) {
            Write-Host "Found C:\users\$user\WebNavigatorBrowser. Removing..."
            Remove-Item "C:\users\$user\WebNavigatorBrowser" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$user\WebNavigatorBrowser"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$user\WebNavigatorBrowser"
            }
        }
        $exists = test-path -path "C:\users\$user\appdata\local\WaveBrowser"
        if ($exists -eq $True) {
            Write-Host "Found C:\users\$user\appdata\local\WaveBrowser. Removing..."
            Remove-Item "C:\users\$user\appdata\local\WaveBrowser" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$user\appdata\local\WaveBrowser"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$user\appdata\local\WaveBrowser"
            }
        }
        $exists = test-path -path "C:\users\$user\appdata\local\WebNavigatorBrowser"
        if ($exists -eq $True) {
            Write-Host "Found C:\users\$user\appdata\local\WebNavigatorBrowser. Removing..."
            Remove-Item "C:\users\$user\appdata\local\WebNavigatorBrowser" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$user\appdata\local\WebNavigatorBrowser"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$user\appdata\local\WebNavigatorBrowser"
            }
        }
        Remove-Item "C:\users\$user\downloads\Wave Browser*.exe" -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\users\$user\appdata\roaming\microsoft\windows\start menu\programs\WaveBrowser.lnk" -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\USERS\$user\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\WAVEBROWSER.LNK" -ErrorAction SilentlyContinue
        Remove-Item "C:\USERS\$user\DESKTOP\WAVEBROWSER.LNK" -ErrorAction SilentlyContinue
    }
}

$tasks = Get-ScheduledTask -TaskName *Wave* | Select-Object -ExpandProperty TaskName
$taskCount=0
foreach ($task in $tasks) {
	Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    $taskCount++
}

Write-Host $taskCount + " scheduled tasks removed."

Write-Host "Cleaning Registry..."

Remove-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\Wave*' -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\system32\tasks\Wavesor*" -Recurse -Confirm:$false -ErrorAction SilentlyContinue

$sid_list = Get-Item -Path "Registry::HKU\*" | Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+"
foreach ($sid in $sid_list) {
    if ($sid -notlike "*_Classes*") {
        $keyexists = test-path -path "Registry::$sid\Software\WaveBrowser"
        if ($keyexists -eq $True) {
            Write-Host "Key Registry::$sid\Software\WaveBrowser Exists. Removing Key"
            Remove-Item -Path "Registry::$sid\Software\WaveBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$sid\Software\WaveBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$sid\Software\WaveBrowser"
            }
        }
        $keyexists = test-path -path "Registry::$sid\Software\Wavesor"
        if ($keyexists -eq $True) {
            Write-Host "Key Registry::$sid\Software\Wavesor Exists. Removing Key"
            Remove-Item -Path "Registry::$sid\Software\Wavesor" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$sid\Software\Wavesor"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$sid\Software\Wavesor"
            }
        }
        $keyexists = test-path -path "Registry::$sid\Software\WebNavigatorBrowser"
        if ($keyexists -eq $True) {
            Write-Host "Key Registry::$sid\Software\WebNavigatorBrowser Exists. Removing Key."
            Remove-Item -Path "Registry::$sid\Software\WebNavigatorBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$sid\Software\WebNavigatorBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$sid\Software\WebNavigatorBrowser"
            }
        }
        $keyexists = test-path -path "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
        if ($keyexists -eq $True) {
            Write-Host "Key Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser Exists. Removing Key."
            Remove-Item -Path "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            }
        }
        $keyexists = test-path -path "Registry::$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
        if ($keyexists -eq $True) {
            Write-Host "Key Registry::$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser Exists. Removing Key"
            Remove-Item -Path "Registry::$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$sid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            }
        }
        $keypath = "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run"
        $keyexists = (Get-Item $keypath).Property -contains "Wavesor SWUpdater"
        if ($keyexists -eq $True) {
            Write-Host "Wavesor Updater Found in Registry. Removing Registry Key."
            Remove-ItemProperty -Path "Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Wavesor SWUpdater" -ErrorAction SilentlyContinue
            $keyexists = (Get-Item $keypath).Property -contains "Wavesor SWUpdater"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$sid\Software\Microsoft\Windows\CurrentVersion\Run.Wavesor SWUpdater"
            }
        }
    }
    if ($sid -like "*_Classes*") {
        Write-Host  "Removing Wavesor Entries for " + $sid 
        remove-item "Registry::$sid\WaveBrwsHTM*" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.CredentialDialogUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.CredentialDialogUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.OnDemandCOMClassUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.OnDemandCOMClassUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.PolicyStatusUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.PolicyStatusUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.Update3COMClassUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.Update3COMClassUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.Update3WebUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$sid\WavesorSWUpdater.Update3WebUser.1.0" -Recurse -ErrorAction SilentlyContinue
    }
}

Stop-Transcript