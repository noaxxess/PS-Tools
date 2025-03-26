param (
	[Parameter(Mandatory = $true)]
	[string]$sourceShare,
	[Parameter(Mandatory = $true)]
	[string]$destShare,
 	[Parameter(Mandatory = $true)]
	[string]$userName,
 	[Parameter(Mandatory = $true)]
	[string]$userPass,
	[Parameter(Mandatory = $false)]
	[string]$logPath,
	[Parameter(Mandatory = $false)]
	[string]$jobName
)


if (!($PSBoundParameters.ContainsKey('logPath'))){
	#CreateLogFile if not passed in
	$logPath = "C:\Temp"
}

if (!($PSBoundParameters.ContainsKey('jobName'))){
	#Create jobName if not passed in
	$jobName = "roboscript"
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
$dateStamp = (Get-Date).toString("yyyyMMddHHmmss")

$logFile = $jobName + $dateStamp
$logFile = "$logFile.log"
$logFile = $logPath + "\" + $logFile
WriteLog "Log File is $logFile"

$roboLog = $logPath + "\" + "RoboResult" + $dateStamp
$roboLog= "$roboLog.log"
WriteLog "Robocopy Results are saved as $roboLog"

try{
	$securePassword = ConvertTo-SecureString $userPass -AsPlainText -Force
	# Import a PSCredential object
	$credential = New-Object System.Management.Automation.PSCredential($userName,$securePassword)
	WriteLog "Credential Created."
} catch {
	WriteLog "Could Not Create Credential"
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
	Start-Process -FilePath "robocopy.exe" -ArgumentList "X:\ Z:\ /MIR /LOG+:$roboLog /NP /R:3 /W:5" -Wait
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
