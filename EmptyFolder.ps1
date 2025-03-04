#Script to delete contents of folder

param (
	[Parameter(mandatory = $true)]
	[string]$folderPath,
	[Parameter(mandatory = $false)]
	[string]$logFile
)
$logDir = "C:\Logs"

if (!($PSBoundParameters.ContainsKey('logFile'))){
	#Set today's date variable
	$todayTime = (Get-Date).toString("MMddyyHHmm")
 	#check if default log directory exists, if not create it
 	if(!(Test-Path $logDir)){
  		New-Item -ItemType "Directory" -Path $logDir
	}
	$logFile = "$logDir\EmptyFolder-$todayTime.log"
}

#Function to Log results
function WriteLog {
	Param (
 		[Parameter(mandatory = $false)]
 		[string]$logString
   	)
    	#Set timeStamp for Log Entries
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	#Combine TimeStamp and Log entry for logfile
 	$LogMessage = "$Stamp $LogString"
  	
	Add-Content -Path $logFile -Value $logMessage
}

WriteLog -logString "Executing Script"
try {
	# Get all files and subdirectories in the folder
 	$items = Get-ChildItem -Path $folderPath

 	#Check if the folder has any content
 	if ($items) {
		# Remove all files and subdirectories
		foreach ($item in $items) {
		    if ($item.PSIsContainer) {
		      Remove-Item -Path $item.FullName -Recurse -Force
				  WriteLog -logString "$item removed."
		    } else {
		      Remove-Item -Path $item.FullName -Force
				  WriteLog -logString "$item removed."
		    }
		}
  	} else {
   	WriteLog -logString "No Content found in $folderPath"
    	}
	
	WriteLog -logString "Folder contents cleared, but the folder itself is retained."
 } catch {
	WriteLog -logString "An unexpected error occurred:$_"
}
