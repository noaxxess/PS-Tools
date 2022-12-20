Param(
  [string] $ACCOUNT = "testprofile",
  [string] $NEWPATH = "C:\users"
)


# Obtain all user profiles (excluding system profiles)
$USER_PROFILES = dir -LiteralPath "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" | ? {$_.name -match "S-1-5-21-"} 
 
# Loop to process all profiles
foreach ($USER_PROFILE in $USER_PROFILES) {

    # Obtain registry, profile path, user and profile new path
    $REGISTRY = $($($USER_PROFILE.pspath.tostring().split("::") | Select-Object -Last 1).Replace("HKEY_LOCAL_MACHINE","HKLM:"))
    
    $OLD_PROFILEPATH = $(Get-ItemProperty -LiteralPath $REGISTRY -name ProfileImagePath).ProfileImagePath.tostring()
    
    $USER=$OLD_PROFILEPATH.Split("\")[-1]
    $NEW_PROFILEPATH = "$NEWPATH\$USER"
	
    # Process all or the user passed as parameter?
    If ($ACCOUNT -eq "ALL" -or $USER -eq $ACCOUNT)
    {
        Write-Host "User:		$USER"
        Write-Host "Registry:	$REGISTRY"
        Write-Host "Old path:	$OLD_PROFILEPATH"
        Write-Host "New path:	$NEW_PROFILEPATH"
        Write-Host

        # Change the profile path in the registry
        Set-ItemProperty -LiteralPath $REGISTRY -Name ProfileImagePath -Value $NEW_PROFILEPATH
        
        Write-Host "- Modified Windows registry (ProfileImagePath)"
        Write-Host "- Copying folders to new location ($NEW_PROFILEPATH)..."

        # Move the profile folders to the new location
        $ROBOCOPY_COMMAND = "robocopy /e /MOVE /copyall /r:0 /mt:4 /b /nfl /xj /xjd /xjf $OLD_PROFILEPATH $NEW_PROFILEPATH > robocopy_$USER.log"
        
        Invoke-Expression $ROBOCOPY_COMMAND
        
        Write-Host "- Done!"
        Write-Host "-------------------------------"		
    }
}