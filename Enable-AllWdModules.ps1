# Requires admin rights

#Set today's date variable
$todayTime = (Get-Date).toString("MMddyyHHmm")

#CreateLogFile
$logFile = "C:\Temp\WdModuleCheck-$todayTime.log"

#Logging Function
function WriteLog {
	Param ([string]$LogString)
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$LogMessage = "$Stamp : $LogString"
	Add-content $logFile -value $LogMessage
}

# Function to check and enable Defender protection modules
function Enable-WindowsDefenderModules {
    $mpPrefs = Get-MpPreference

    WriteLog "Checking Windows Defender modules..." 

    if ($mpPrefs.DisableRealtimeMonitoring) {
        WriteLog "Enabling Real-Time Protection..."
        Set-MpPreference -DisableRealtimeMonitoring $false
    }

    if ($mpPrefs.DisableBehaviorMonitoring) {
        WriteLog "Enabling Behavior Monitoring..."
        Set-MpPreference -DisableBehaviorMonitoring $false
    }

    if ($mpPrefs.DisableIOAVProtection) {
        WriteLog "Enabling IOAV Protection..."
        Set-MpPreference -DisableIOAVProtection $false
    }

    if ($mpPrefs.DisableScriptScanning) {
        WriteLog "Enabling Script Scanning..."
        Set-MpPreference -DisableScriptScanning $false
    }

    if ($mpPrefs.DisableIntrusionPreventionSystem) {
        WriteLog "Enabling Intrusion Prevention System..."
        Set-MpPreference -DisableIntrusionPreventionSystem $false
    }

    if ($mpPrefs.EnableNetworkProtection -ne 1) {
        WriteLog "Enabling Network Protection..."
        Set-MpPreference -EnableNetworkProtection 1
    }

    if ($mpPrefs.EnableControlledFolderAccess -ne 1) {
        WriteLog "Enabling Controlled Folder Access..."
        Set-MpPreference -EnableControlledFolderAccess 1
    }

    WriteLog "All applicable modules are now enabled."
}

# Run the function
Enable-WindowsDefenderModules

