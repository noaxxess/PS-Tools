# Define the newUser of the account to be deleted
param (
	[Parameter(Mandatory = $true)]
	[string]$oldUser,
	[Parameter(Mandatory = $true)]
	[string]$newUser,
	[Parameter(Mandatory = $false)]
	[string]$newUserName,
	[Parameter(Mandatory = $true)]
	[string]$newPass,
	[Parameter(Mandatory = $false)]
	[string]$logFile
)
#Set today's date variable
$todayTime(Get-Date).toString("MMddyyHHmm")

#set non-mandatory variables if not present
if (!($PSBoundParameters.ContainsKey('newUserName')){
	$newUserName = "New Admin User"
}
if (!($PSBoundParameters.ContainsKey('logFile')){
	$newUserName = "C:\Temp\RemoveAddAdminUser-$todayTime.log"
}

function WriteLog {
	Param ([string]$LogString)
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$LogMessage = "$Stamp $LogString"
	Add-content $LogFile -value $LogMessage
}

try {
    # Define the newUser and password for the new user
    $password = $newPass | ConvertTo-SecureString -AsPlainText -Force

    # Check if the user already exists
    if (Get-LocalUser -Name $newUser -ErrorAction SilentlyContinue) {
        throw "User $newUser already exists."
    }

    # Create the new local user
    New-LocalUser -Name $newUser -Password $password -FullName "New Admin User" -Description "Local Administrator Account"
    WriteLog "User $newUser has been created."

    # Add the new user to the Administrators group
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    WriteLog "User $newUser has been added to the Administrators group."
	$confirmation="Complete"
}
catch {
    Write-Error "An error occurred: $_"
	$confirmation="Failed"
}

# Confirm the action with the user

if ($confirmation -eq "Complete") {
    try {
		WriteLog "Attempting to remove $oldUser"
        # Attempt to remove the old admin user account
        Remove-LocalUser -Name $oldUser
        WriteLog "User account '$oldUser' has been successfully deleted."
		WriteLog "Removing $oldUser User Directory..."
		$oldUserDir = Get-ChildItem "C:\Users" | Where-Object {$_.Name -eq "$oldUser"}
		if($oldUserDir -ne $null){
			$oldUserDir | Remove-Item -Force
			WriteLog "$oldUser Directory Removed"
		} else {
			WriteLog "$oldUser Directory Not Present"
		}
    } catch {
        WriteLog "An error occurred: $_"
    }
} else {
    WriteLog "Operation cancelled."
}

