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
$todayTime = (Get-Date).toString("MMddyyyyHHmm")

#Create function to log results
function WriteLog {
	Param (
 		[string]$LogString
   	)
	$Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
	$LogMessage = "$Stamp $LogString"
	Add-content $logFile -value $LogMessage
}

#Set non-mandatory variables if not present
if (!($PSBoundParameters.ContainsKey('newUserName'))){
	$newUserName = "New Admin User"
 	WriteLog "$newUserName not passed in"
  	WriteLog "Setting newUserName to $newUserName"
}
if (!($PSBoundParameters.ContainsKey('logFile'))){
	$logFile = "C:\Temp\RemoveAddAdminUser-$todayTime.log"
 	WriteLog "$logFile not passed in"
  	WriteLog "Setting logFile to $logFile"
}



try {
    # Define the newUser and password for the new user
    $password = $newPass | ConvertTo-SecureString -AsPlainText -Force

    # Check if the user already exists
    if (Get-LocalUser -Name $newUser -ErrorAction SilentlyContinue) {
        WriteLog "User $newUser already exists."
    } else { 

    # Create the new local user
    New-LocalUser -Name $newUser -Password $password -FullName "New Admin User" -Description "Local Administrator Account" -PasswordNeverExpires
    WriteLog "User $newUser has been created."

    # Add the new user to the Administrators group
    Add-LocalGroupMember -Group "Administrators" -Member $newUser
    WriteLog "User $newUser has been added to the Administrators group."
    $confirmation="Complete"
    }
}
catch {
    WriteLog "An error occurred: $_"
	$confirmation="Failed"
}

# Confirm the action with the user

if ($confirmation -eq "Complete") {
    try {
	WriteLog "Attempting to remove $oldUser"
 	if(Get-LocalUser -Name $oldUser){
	        # Attempt to remove the old admin user account
	        $oldUserSID = Get-LocalUser -Name $oldUser | Select-Object -ExpandProperty SID
		Remove-LocalUser -Name $oldUser
	        WriteLog "User account '$oldUser' has been successfully deleted."
		WriteLog "Removing $oldUser Registry Key"
	 	Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$oldUserSID" -Recurse -Force 
	 	WriteLog "Removing $oldUser User Directory..."
		Get-ChildItem "C:\Users" | Where-Object {$_.Name -eq "$oldUser"} | Remove-Item -Force
 	} else {
  		WriteLog $oldUser "does not exist"
    	}
    } catch {
        WriteLog "An error occurred: $_"
    }
} else {
    WriteLog "New User Not Created. Operation cancelled."
}


