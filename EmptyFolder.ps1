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
 		[Parameter(mandatory = $false)]
		[string]$logFile,
 		[Parameter(mandatory = $false)]
 		[string]$logString
   	)
    	#Set tiemStamp for Log Entries
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	#Combine TimeStamp and Log entry for logfile
 	$LogMessage = "$Stamp $LogString"
  	if (!(Get-Item -Path $logFile)){
   		New-Item $logFile
     	}
	Add-Content -Path $logFile -Value $logMessage
}

WriteLog -logFile $logFile -logString "Executing Script"
try {
	# Get all files and subdirectories in the folder
 	$items = Get-ChildItem -Path $folderPath

 	#Check if the folder has any content
 	if ($items) {
		# Remove all files and subdirectories
		foreach ($item in $items) {
		    if ($item.PSIsContainer) {
		      Remove-Item -Path $item.FullName -Recurse -Force
				  WriteLog -logFile $logFile -logString "$item.Fullname removed."
		    } else {
		      Remove-Item -Path $item.FullName -Force
				  WriteLog -logFile $logFile -logString "$item.Fullname removed."
		    }
		}
  	} else {
   	WriteLog -logFile $logFile -logString "No Content found in $folderPath"
    	}
	
	WriteLog -logFile $logFile -logString "Folder contents cleared, but the folder itself is retained."
 } catch {
	WriteLog -logFile $logFile -logString "An unexpected error occurred:$_"
}
