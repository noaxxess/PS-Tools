# Make surebPSWindowsUpdate is installed on the system.
if(!(Get-installedmodule PSWindowsUpdate)){

    # Install NuGet and PowershellGet if not already
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module PowershellGet -Force

    # Install PSWindowsUpdate
    Install-Module PSWindowsUpdate -Force
}
Import-Module PSWindowsUpdate -Force

# Initiate download and install of Windows updates
Install-WindowsUpdate -AcceptAll -ForceInstall -IgnoreReboot
