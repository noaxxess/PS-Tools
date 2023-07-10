param(
    [parameter(Mandatory=$False)]
    [String]$LogFile
)

if($PSBoundParameters.ContainsKey('LogFile') -eq $false){
    $LogFile = "C:\Temp\RemoveWaveSor.log"
}

Start-Transcript -Path $LogFile -NoClobber

Get-Process wavebrowser -ErrorAction SilentlyContinue | Stop-Process -Force
Get-Process SWUpdater -ErrorAction SilentlyContinue | Stop-Process -Force
sleep 2

$user_list = Get-Item C:\users\* | Select-Object Name -ExpandProperty Name
foreach ($i in $user_list) {
    if ($i -notlike "*Public*") {
        $exists = test-path -path "C:\users\$i\Wavesor Software"
        if ($exists -eq $True) {
            rm "C:\users\$i\Wavesor Software" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$i\Wavesor Software"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$i\Wavesor Software"
            }
        }
        $exists = test-path -path "C:\users\$i\WebNavigatorBrowser"
        if ($exists -eq $True) {
            rm "C:\users\$i\WebNavigatorBrowser" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$i\WebNavigatorBrowser"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$i\WebNavigatorBrowser"
            }
        }
        $exists = test-path -path "C:\users\$i\appdata\local\WaveBrowser"
        if ($exists -eq $True) {
            rm "C:\users\$i\appdata\local\WaveBrowser" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$i\appdata\local\WaveBrowser"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$i\appdata\local\WaveBrowser"
            }
        }
        $exists = test-path -path "C:\users\$i\appdata\local\WebNavigatorBrowser"
        if ($exists -eq $True) {
            rm "C:\users\$i\appdata\local\WebNavigatorBrowser" -Force -Recurse -ErrorAction SilentlyContinue
            $exists = test-path -path "C:\users\$i\appdata\local\WebNavigatorBrowser"
            if ($exists -eq $True) {
                "WaveBrowser Removal Unsuccessful => C:\users\$i\appdata\local\WebNavigatorBrowser"
            }
        }
        rm "C:\users\$i\downloads\Wave Browser*.exe" -Force -ErrorAction SilentlyContinue
        rm "C:\users\$i\appdata\roaming\microsoft\windows\start menu\programs\WaveBrowser.lnk" -Force -ErrorAction SilentlyContinue
        rm "C:\USERS\$i\APPDATA\ROAMING\MICROSOFT\INTERNET EXPLORER\QUICK LAUNCH\WAVEBROWSER.LNK" -ErrorAction SilentlyContinue
        rm "C:\USERS\$i\DESKTOP\WAVEBROWSER.LNK" -ErrorAction SilentlyContinue
    }
}

$tasks = Get-ScheduledTask -TaskName *Wave* | Select-Object -ExpandProperty TaskName
foreach ($i in $tasks) {
	Unregister-ScheduledTask -TaskName $i -Confirm:$false -ErrorAction SilentlyContinue
}

Remove-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\TREE\Wave*' -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "C:\windows\system32\tasks\Wavesor*" -Recurse -Confirm:$false -ErrorAction SilentlyContinue

$sid_list = Get-Item -Path "Registry::HKU\*" | Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+"
foreach ($i in $sid_list) {
    if ($i -notlike "*_Classes*") {
        $keyexists = test-path -path "Registry::$i\Software\WaveBrowser"
        if ($keyexists -eq $True) {
            Remove-Item -Path "Registry::$i\Software\WaveBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$i\Software\WaveBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$i\Software\WaveBrowser"
            }
        }
        $keyexists = test-path -path "Registry::$i\Software\Wavesor"
        if ($keyexists -eq $True) {
            Remove-Item -Path "Registry::$i\Software\Wavesor" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$i\Software\Wavesor"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$i\Software\Wavesor"
            }
        }
        $keyexists = test-path -path "Registry::$i\Software\WebNavigatorBrowser"
        if ($keyexists -eq $True) {
            Remove-Item -Path "Registry::$i\Software\WebNavigatorBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$i\Software\WebNavigatorBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$i\Software\WebNavigatorBrowser"
            }
        }
        $keyexists = test-path -path "Registry::$i\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
        if ($keyexists -eq $True) {
            Remove-Item -Path "Registry::$i\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$i\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$i\Software\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            }
        }
        $keyexists = test-path -path "Registry::$i\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
        if ($keyexists -eq $True) {
            Remove-Item -Path "Registry::$i\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser" -Recurse -ErrorAction SilentlyContinue
            $keyexists = test-path -path "Registry::$i\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$i\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\WaveBrowser"
            }
        }
        $keypath = "Registry::$i\Software\Microsoft\Windows\CurrentVersion\Run"
        $keyexists = (Get-Item $keypath).Property -contains "Wavesor SWUpdater"
        if ($keyexists -eq $True) {
            Remove-ItemProperty -Path "Registry::$i\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Wavesor SWUpdater" -ErrorAction SilentlyContinue
            $keyexists = (Get-Item $keypath).Property -contains "Wavesor SWUpdater"
            if ($keyexists -eq $True) {
                "WaveBrowser Removal Unsuccessful => Registry::$i\Software\Microsoft\Windows\CurrentVersion\Run.Wavesor SWUpdater"
            }
        }
    }
}

$sid_list = Get-Item -Path "Registry::HKU\*" | Select-String -Pattern "S-\d-(?:\d+-){5,14}\d+"
foreach ($i in $sid_list) {
    if ($i -like "*_Classes*") {
        remove-item "Registry::$i\WaveBrwsHTM*" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.CredentialDialogUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.CredentialDialogUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.OnDemandCOMClassUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.OnDemandCOMClassUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.PolicyStatusUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.PolicyStatusUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.Update3COMClassUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.Update3COMClassUser.1.0" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.Update3WebUser" -Recurse -ErrorAction SilentlyContinue
        remove-item "Registry::$i\WavesorSWUpdater.Update3WebUser.1.0" -Recurse -ErrorAction SilentlyContinue
    }
}

Stop-Transcript