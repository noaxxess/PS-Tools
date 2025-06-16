<#
.SYNOPSIS
	Removes Google Chrome history entries. Script adapted from function created by Theo Ros. 
 Added Logging Function and ability to automatically stop Chrome and continue running.
 Removed Passwords from "All" 
.DESCRIPTION
	Removes Google Chrome history entries.
.NOTES
	Author: NoAxxess
.PARAMETER DaysToKeep
	Specifies the number of days to keep history. Everything older that
	the given number of days (as seen from now) will be removed.
	Defaults to 7
.PARAMETER Kill
	Specifies whether or not to stop Chrome automatically
.PARAMETER Recommended
	This is a shorthand switch. When set, all ArchivedHistory, BrowsingHistory,
	Cookies, Favicons, MediaData and TemporaryFiles will be cleared.
	FormData, Passwords and TopSites will be left alone.
.PARAMETER All
	This is a shorthand switch. When set, ALL history items will be cleared.
.PARAMETER ArchivedHistory
	When set, Archived History (BrowsingHistory older than 90 days) will be removed.
.PARAMETER BrowsingHistory
	When set, History and History-journal and Visited Links will be removed.
.PARAMETER Cookies
	When set, Cookies and Cookies-journal will be removed.
.PARAMETER Favicons
	When set, Favicons and Favicons-journal will be removed.
.PARAMETER Passwords
	When set, Login Data and Login Data-journal will be removed.
.PARAMETER MediaData
	When set, the Media Cache will be emptied.
.PARAMETER TemporaryFiles
	When set, the Temporary Cache will be emptied.
.PARAMETER TopSites
	When set, Top Sites and Top Sites-journal will be removed.
.PARAMETER FormData
	When set, Web Data en Web Data-journal (among others Autocomplete) will be removed.
.PARAMETER OutputFolder
	Folder to save log In
.PARAMETER LogFile
	File name for Log
#>

[CmdletBinding(DefaultParameterSetName = 'Recommended', ConfirmImpact = 'None')]

param (

	[Parameter(Mandatory = $false, Position = 0)]
	[int] $DaysToKeep = 0,
	
	[switch] $Kill,

	[Parameter(ParameterSetName='Recommended')]
	[switch] $Recommended,

	[Parameter(ParameterSetName='ByAll')]
	[switch] $All,

	[Parameter(ParameterSetName='ByItem')]
	[switch] $ArchivedHistory,  # Archived History (BrowsingHistory older than 90 days)
	[Parameter(ParameterSetName='ByItem')]
	[switch] $BrowsingHistory,  # file: History and History-journal and Visited Links
	[Parameter(ParameterSetName='ByItem')]
	[switch] $Cookies,          # file: Cookies and Cookies-journal
	[Parameter(ParameterSetName='ByItem')]
	[switch] $Favicons,         # file: Favicons and Favicons-journal
	[Parameter(ParameterSetName='ByItem')]
	[switch] $Passwords,        # file: Login Data and Login Data-journal
	[Parameter(ParameterSetName='ByItem')]
	[switch] $MediaData,        # folder: Media Cache
	[Parameter(ParameterSetName='ByItem')]
	[switch] $TemporaryFiles,   # folder: Cache
	[Parameter(ParameterSetName='ByItem')]
	[switch] $TopSites,         # file: Top Sites and Top Sites-journal
	[Parameter(ParameterSetName='ByItem')]
	[switch] $FormData,          # file: Web Data en Web Data-journal (among others Autocomplete)
	
	[Parameter (Mandatory = $True)]
	[string] $OutputFolder,
	[Parameter (Mandatory = $True)]
	[string] $LogFile
	
)

function Write-Log {

param (
	[Parameter(Mandatory = $true)]
	[string]$LogString
)

$logFile = Join-Path $Global:OutputFolder $Global:LogFile
$Stamp = (Get-Date).ToString("yyyy/MM/dd HH:mm:ss")
$LogMessage = "$Stamp $LogString"
$LogMessage | Out-File -FilePath $logFile -Encoding utf8 -Append
}


$Global:LogFile = $LogFile
$Global:OutputFolder = $OutputFolder

if (Get-Process -Name chrome -ErrorAction SilentlyContinue) {
	
	Write-Log "Chrome process(es) are still running. Browser must be closed to clear the history."
	
	if ($psBoundParameters.ContainsKey('Kill')){
		
		Write-Log "Kill switch provided. Stopping Chrome..."
		Get-Process -Name chrome -ErrorAction SilentlyContinue | Stop-Process -ErrorAction SilentlyContinue
		Write-Log "Pausing for 1 second"
		Start-Sleep -Seconds 1
		
		if (Get-Process | Where-Object { $_.Name -eq "chrome" }){
			
			Write-Log "Chrome is still running. Stopping Process was unsuccessful"
			Write-Log "Stopping Script..."
			return
			
		} else {
			
			Write-Log "Chrome stopped. Continuing to clear Chrome Data..."
		} 
	} else {
			
			Write-Log "Kill switch not specified. Please try to run this script again when Chrome is not running."
			Write-Log "Stopping Script..."
			return
			
	}
}

$path = "$($env:LOCALAPPDATA)\Google\Chrome\User Data\Default"
if (!(Test-Path -Path $path -PathType Container)) {
	
	Write-Log "Chrome history path '$path' not found"
	return
	
}

if ($psCmdlet.ParameterSetName -eq 'Recommended') {
	
	# remove all these:
	$ArchivedHistory = $BrowsingHistory = $Cookies = $Favicons = $MediaData = $TemporaryFiles = $true
	
	# but leave these intact:
	$FormData = $Passwords = $TopSites = $false
	
}

$msg = @()
$items = @()
if ($ArchivedHistory -or $All) 	{ $items += "Archived History*"             ; $msg += "Archived History" }
if ($BrowsingHistory -or $All) 	{ $items += @("History*", "Visited Links*") ; $msg += @("History", "Visited Links") }
if ($Cookies -or $All)         	{ $items += "Cookies*"                      ; $msg += "Cookies" }
if ($Favicons -or $All)     	{ $items += "Favicons*"                     ; $msg += "Favicons" }
if ($FormData -or $All)		{ $items += "Web Data*"                     ; $msg += "Form Data" }
if ($MediaData -or $All)	{ $items += "Media Cache*"                  ; $msg += "Media Cache" }
if ($Passwords)       		{ $items += "Login Data*"                   ; $msg += "Passwords" }
if ($TemporaryFiles -or $All)  	{ $items += "Cache*"                        ; $msg += "Temporary Files Cache" }
if ($TopSites -or $All)        	{ $items += "Top Sites*"                    ; $msg += "Top Sites" }

#Save current Error Action Preference
$oldErrorActionPreference = $ErrorActionPreference

$ErrorActionPreference = 'SilentlyContinue'

#Create a reference date based on DaysToKeep Parameter
$refdate = (Get-Date).AddDays(-([Math]::Abs($DaysToKeep)))

$allItems = @()

if ($items.Length) {
	
	$allItems += $items | ForEach-Object {
		$name = $_
		Get-ChildItem $path -Recurse -Force |
		Where-Object { ($_.CreationTime -lt $refdate) -and $_.Name -like $name }
	}
	
}

if ($allItems.Length) {
	
 # List Items to be reomved
	$join = "`r`n "
	$msg = ($msg | Sort-Object) -join $join
	Write-Log ("$($MyInvocation.MyCommand) Clearing:$join$msg")

	foreach ($item in $allItems){ 
    
    #Remove Item and Log it.
		Remove-Item $item.FullName -Force -Recurse 
		Write-Log "$item removed."
  
		}
} else {

	Write-Log "$($MyInvocation.MyCommand): Nothing selected or older than $($refdate.ToString()) found"

}

$ErrorActionPreference = $oldErrorActionPreference
