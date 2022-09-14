<#This is a script to get Uninstall strings for apps from the registry.
It will search by app name and/or publisher. 
It will find uninstall strings in both x86 and 64-bit Registry Paths
The only required parameters is the csv path to save the output.
If no search parameters are specified it will output all uninstall strings.
#>

param (
    [Parameter(Mandatory = $False)][String]$Publisher,
    [Parameter(Mandatory = $False)][String]$Name,
    [Parameter(Mandatory = $True)][String]$CSVPath
    )

if ($PSBoundParameters.ContainsKey('Publisher') -eq $False){
    $Publisher = "*"
}
else{
    $Publisher = "*" + $Publisher + "*"
}
    
if ($PSBoundParameters.ContainsKey('Name') -eq $False){
    $Name = "*"
}    
else{    
    $Name = "*" + $Name + "*"
}


$RegPaths = @(
    'HKLM:\\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 
    'HKLM:\\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    

$RegPaths.foreach({
  
    Write-Host "$_" 
    Get-ChildItem -Path $_ | 
    ForEach-Object{Get-ItemProperty $_.PsPath} | 
    Select-Object Publisher,  PSChildName, DisplayName, DisplayVersion, UninstallString | 
    Where-Object { $_.Publisher -like $Publisher -and $_.DisplayName -like $Name} 
         
}) | Export-CSV -NoTypeInformation -Path $CSVPath

