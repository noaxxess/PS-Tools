
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
    

$UninstallStrings = ForEach ($RegPath IN $RegPaths){
  
    Write-Host "$RegPath" 
    Get-ChildItem -Path $RegPath | 
    ForEach-Object{Get-ItemProperty $_.PsPath} | 
    Select-Object Publisher,  PSChildName, DisplayName, DisplayVersion, UninstallString | 
    Where-Object { $_.Publisher -like $Publisher -and $_.Name -like $Name} 
         
}
  
    
$UninstallStrings | Export-Csv -Path $CSVPath

