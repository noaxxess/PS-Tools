param (	
	#Domain Name
	[Parameter(ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "Domain Name")]
	[String]$DomainName,
    #NetBios Name
	[Parameter(ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "NetBios Name")]
	[String]$NBName,
    #Safe Mode Password	
    [Parameter(ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "SafeMode Password")]
    [String]$SmPassword,
    [Parameter(ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "Drive Letter")]
    [String]$DrvLtr
    )

$NTDSPath = $DrvLtr + ":\NTDS"
$SysVolPath = $DrvLtr + ":\SYSVOL"

#Convert Password String to password hash
$SecPassword=(ConvertTo-SecureString -String $SMPassword -AsPlainText -Force)

#Install and Configure Forest
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath $NTDSPath`
-DomainName $DomainName `
-DomainNetbiosName $NBName `
-InstallDns:$true `
-LogPath $NTDSPath `
-SysvolPath $SysVolPath `
-SafeModeAdministratorPassword $SecPassword `
-NoRebootOnCompletion:$true `
-Verbose `
-Force:$true >> 'C:\AddForest.log'

#Enable PS-Remoting
Enable-PSRemoting -Force

Restart-Computer