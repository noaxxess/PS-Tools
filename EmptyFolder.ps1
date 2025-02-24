#Script to delete contents of folder

param (
	[Parameter(mandatory = $true)]
	[string]$folderPath,
	[Parameter(mandatory = $false)]
	[string]$logFile
)

if (!($PSBoundParameters.ContainsKey('logFile'))){
	#Set today's date variable
	$todayTime = (Get-Date).toString("MMddyyHHmm")
	$logFile = "C:\Logs\EmptyFolder-$todayTime.log"
}

#Function to Log results
function WriteLog {
	Param (
 		[Parameter(mandatory = $true)]
 		[string]$LogString
   	)
    	#Set tiemStamp for Log Entries
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	#Combine TimeStamp and Log entry for logfile
 	$LogMessage = "$Stamp $LogString"
	Add-content $logFile -value $LogMessage
}

WriteLog "Executing Script"
try {
	# Get all files and subdirectories in the folder
 	$items = Get-ChildItem -Path $folderPath

 	#Check if the folder has any content
 	if ($items) {
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
  	} else {
   	WriteLog "No Content found in $folderPath"
    	}
	
	WriteLog "Folder contents cleared, but the folder itself is retained."
 } catch {
	WriteLog "An unexpected error occurred:$_"
}
