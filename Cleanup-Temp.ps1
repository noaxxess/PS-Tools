#This script cleans up temporary files and folders

param (
    [Parameter(Mandatory = $false)]
    [string]$logFile
)

# Define paths to temporary files and Windows Update cache
$tempPaths = @(
    "$env:LOCALAPPDATA\Temp",
    "$env:WINDIR\Temp",
    "$env:WINDIR\SoftwareDistribution\Download"
)

function WriteLog {
	Param (
 		[string]$LogString
   	)
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$LogMessage = "$Stamp $LogString"
	Add-content $logFile -value $LogMessage
}

# Function to delete files and folders
function Remove-TempFiles {
    param (
        [string]$path
    )
    if (Test-Path $path) {
        WriteLog "Cleaning up: $path"
        Get-ChildItem -Path $path -Recurse -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    } else {
        WriteLog "Path not found: $path"
    }
}

try{
    # Loop through each path and clean up
    foreach ($path in $tempPaths) {
        Remove-TempFiles -path $path
        WriteLog "Files and folder in $path removed."
    }
}
catch{
    WriteLog "An error occurred: $_"
	WriteLog "Remove-TempFiles Failed"
}

WriteLog "Temporary files cleanup completed."
