param (
	#Disk Letter
	[Parameter(ValueFromPipeline = $true, Mandatory=$true, HelpMessage = "Drive Letter")]
	[String]$DrvLtr
)

#Initialize Data Disk on Local Machine
$DiskNum=(Get-Disk | Where PartitionStyle -eq 'raw').Number

Initialize-Disk -Number $diskNum -PartitionStyle MBR

New-Partition -DiskNumber $diskNum -UseMaximumSize -DriveLetter $DskLtr | Format-Volume -FileSystem NTFS -NewFileSystemLabel 'NTDS' -Confirm:$false
