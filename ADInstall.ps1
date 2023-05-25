   
#Install AD DS, DNS and GPMC 
start-job -Name addFeature -ScriptBlock { 
Add-WindowsFeature -Name "ad-domain-services" -IncludeAllSubFeature -IncludeManagementTools -verbose >> 'C:\ADDSInstall.log'
Add-WindowsFeature -Name "dns" -IncludeAllSubFeature -IncludeManagementTools -verbose >> 'C:\ADDSInstall.log'
Add-WindowsFeature -Name "gpmc" -IncludeAllSubFeature -IncludeManagementTools -verbose >> 'C:\ADDSInstall.log'
}
#Wait for AD-Domain-Service to Install and Log Results
Wait-Job -Name addFeature
Get-WindowsFeature | Where installed >> 'C:\ADDSInstall.log'

#Import the ADDS Deployment Module
Import-Module ADDSDeployment



#Add a trusted host to the WSMan File
#Set-Item -Path WSMan:\localhost\Client\TrustedHosts –Value $MyIp -Force