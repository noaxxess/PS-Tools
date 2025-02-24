param(
	[parameter(mandatory = $true)]
	[string]$folderPath,
	[parameter(mandatory = $false)]
	[string]$logFile
	)

if (!($PSBoundParameters.ContainsKey('logFile'))){
	#Set today's date variable
	$todayTime = (Get-Date).toString("MMddyyHHmm")
	$logFile = "C:\Logs\EmptyFolder-$todayTime.log"
}

function WriteLog {
	Param ([string]$LogString)
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$LogMessage = "$Stamp $LogString"
	Add-content $logFile -value $LogMessage
}

try{
	# Get all files and subdirectories in the folder
	$items = Get-ChildItem -Path $folderPath
	
	# Remove all files and subdirectories
	foreach ($item in $items) {
	    if ($item.PSIsContainer) {
	      Remove-Item -Path $item.FullName -Recurse -Force
			  WriteLog "$item.Fullname removed."
	    } else {
	      Remove-Item -Path $item.FullName -Force
			  WriteLog "$item.Fullname removed."
	    }
	}
	
	WriteLog "Folder contents cleared, but the folder itself is retained."
 } catch {
 	WriteLog "An unexpected error occurred:$_"
  }
