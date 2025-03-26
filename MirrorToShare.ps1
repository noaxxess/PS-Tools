param (
	[Parameter(Mandatory = $true)]
	[string]$sourceShare,
	[Parameter(Mandatory = $true)]
	[string]$destShare,
	[Parameter(Mandatory = $true)]
	[string]$credFile,
	[Parameter(Mandatory = $true)]
	[string]$logFile
)

if (!($PSBoundParameters.ContainsKey('logFile'))){
	#CreateLogFile
	$logFile = "C:\Temp\ShareCopy.log"
}

#Logging Function
function WriteLog {
	Param (
		[Parameter(ValueFromPipeline=$true)]
		[string]$LogString
	)
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$LogMessage = "$Stamp $LogString"
	Add-content $logFile -value $LogMessage
}

try{
	# Import a PSCredential object
	$credential = Import-CliXml -Path $credFile
	WriteLog "Credential Imported."
} catch {
	WriteLog "Could Not Import Credential"
	WriteLog "An error occurred: $_"
	throw 
}

try{
	# Map the source network drive
	New-PSDrive -Name "X" -PSProvider FileSystem -Root $sourceShare -Credential $credential -Persist | WriteLog
	WriteLog "$sourceShare mounted to Drive X"
	# Map the destination network drive
	New-PSDrive -Name "Z" -PSProvider FileSystem -Root $destShare -Credential $credential -Persist | WriteLog
	WriteLog "$destShare mounted to Drive Z"
} catch {
	WriteLog "Could Not Map Drives"
	WriteLog "An error occurred: $_"
	throw
}

try{
	# Use RoboCopy to mirror the local folder to the network share
	Start-Process -FilePath "robocopy.exe" -ArgumentList "X:\ Z:\ /MIR /LOG+:$logFile /NP /R:3 /W:5" -Wait
	WriteLog "Robocopy Complete."
} catch {
	WriteLog "Could not Complete Robocopy."
	WriteLog "An error occurred: $_"
}

try{
	# Remove the source network drive mapping
	Remove-PSDrive -Name "X"
	WriteLog "Drive X Removed."
	# Remove the destination network drive mapping
	Remove-PSDrive -Name "Z"
	WriteLog "Drive Z Removed."
} catch {
	WriteLog "Could Not Remove Drives."
	WriteLog "An error occurred: $_"
}