<#
.SYNOPSIS
    A script to enumerate AD groups and members and populate an IT Glue configuration.

.DESCRIPTION
    Generate graphed report for all Active Directory objects.

.PARAMETER APIKey
    API Key Obtained from IT Glue in Account->Settings->API Keys

.PARAMETER OrgID
    Organization ID located at the end of the IT Glue URL for the organization.

.NOTES
    Script Originally Created by CyberDrain- Kelvin Tegelaar
    Modified By: Noaxxess
    Added: Parametrs, comments, formatting, logic to check if group member are users or computers, function to match configs and tag
    Date: 04/25/2023

#>


param (

    [Parameter(ValueFromPipeline = $true, HelpMessage = "API Key")]
    [String]$APIKey,
    #IT GLue API Key
    [Parameter(ValueFromPipeline = $true, HelpMessage = "Organization ID")]
    [String]$OrgID
    #IT GLue Organization ID

)

#Function to return IT Glue Configuration IDs based on Names
function Get-ITGlueConfigurationID {
    param (
        [string]$Name,
        [array]$Configurations
    )

    foreach ($config in $Configurations) {
        $ConfigName = ($Config.attributes.Name).Split('.')[0]
        if ($ConfigName -eq $Name) {
            return $Config.Id
        }
    }
}

#Set IT Glue Info
$APIEndpoint = "https://api.itglue.com"
$FlexAssetName = "ITGLue AutoDoc - Active Directory Groups v3"
$Description = "Lists all groups and users in them."
$ITGlueConfigs = (Get-ITGlueConfigurations -organization_id 5713007).data

#####################################################################

#Check if ITGlueAPI Module Exists, if not, install/import it
if (Get-Module -ListAvailable -Name "ITGlueAPI") {
    Import-Module ITGlueAPI
}
else {
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}

# Set IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKey


# Get all AD Groups
$AllGroups = Get-AdGroup -filter *
#Lopp Through Groups
foreach ($Group in $AllGroups) {
    
    #Set Arrays for Asset Tags
    $Contacts = @()
    $Configs = @()    
    
    #Loop through the Groups to get Members
    $Members = Get-AdGroupMember $Group
    
    #Save the members into a table
    $MembersTable = $Members | Select-Object Name, SamAccountName, distinguishedName | ConvertTo-Html -Fragment | Out-String 
    
    #Loop Through Members
    foreach ($Member in $Members) {
        #Get object type to see if the group contains users or computers
        $ObjType = (Get-ADObject -Filter { SamAccountName -eq $Member.SamAccountName }).ObjectClass
        #Test if Member is USer
        if ($ObjType -eq 'User') {
            #See if User in AD has an email address
            $Email = (Get-AdUser $Member -Properties EmailAddress).EmailAddress
            #If user exists in IT Glue, add it to Contacts array 
            if ($Email) {
                $Contacts += (Get-ITGlueContacts -organization_id $OrgID -filter_primary_email $Email).data.id
            }
        }
        #Check if Member is a Computer
        if ($ObjType -eq 'Computer') {
            #If it is get the computer name from AD
            $ComputerName = (Get-AdComputer $Member -Properties Name).Name
            #Check if the computer name exists
            if ($ComputerName) {
                #Get id using name and array of configurations from IT Glue, if there is a match add the ID to the Configs array
                $Configs += Get-ITGlueConfigurationID -Name $ComputerName -Configurations $ITGlueConfigs
            }     
        }
    }

    $FlexAssetBody = @{
        type       = 'flexible-assets'
        attributes = @{
            name   = $FlexAssetName
            traits = @{
                "group-name"   = $($Group.Name)
                "members"      = $MembersTable
                "guid"         = $($Group.ObjectGuid.Guid)
                "tagged-users" = $Contacts
                "tagged-configurations" = $Configs
            }
        }
    }

    # Checking if the FlexibleAsset exists.
    $FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data

    # If the Flexible Asset Type does not exist create a new one
    if (!$FilterID) {
        $NewFlexAssetData = @{
            type          = 'flexible-asset-types'
            attributes    = @{
                name        = $FlexAssetName
                icon        = 'sitemap'
                description = $description
            }
            relationships = @{
                "flexible-asset-fields" = @{
                    data = @(
                        @{
                            type       = "flexible_asset_fields"
                            attributes = @{
                                order           = 1
                                name            = "Group Name"
                                kind            = "Text"
                                required        = $true
                                "show-in-list"  = $true
                                "use-for-title" = $true
                            }
                        },
                        @{
                            type       = "flexible_asset_fields"
                            attributes = @{
                                order          = 2
                                name           = "Members"
                                kind           = "Textbox"
                                required       = $false
                                "show-in-list" = $true
                            }
                        },
                        @{
                            type       = "flexible_asset_fields"
                            attributes = @{
                                order          = 3
                                name           = "GUID"
                                kind           = "Text"
                                required       = $false
                                "show-in-list" = $false
                            }
                        },
                        @{
                            type       = "flexible_asset_fields"
                            attributes = @{
                                order          = 4
                                name           = "Tagged Users"
                                kind           = "Tag"
                                "tag-type"     = "Contacts"
                                required       = $false
                                "show-in-list" = $false
                            },
                            @{
                                type       = "flexible_asset_fields"
                                attributes = @{
                                    order          = 5
                                    name           = "Tagged Configurations"
                                    kind           = "Tag"
                                    "tag-type"     = "Configurations"
                                    required       = $false
                                    "show-in-list" = $false
                                }
                            }
                        }
                    )
                }
            }
        }
        New-ITGlueFlexibleAssetTypes -Data $NewFlexAssetData
        $FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
    }

    # Get Existing ITGlue Flex Asset Data and match our data
    $ExistingFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID).data | Where-Object { $_.attributes.traits.'group-name' -eq $($group.name) }

    # If the Asset does not exist, we edit the body to be in the form of a new asset
    if (!$ExistingFlexAsset) {
        $FlexAssetBody.attributes.add('organization-id', $orgID)
        $FlexAssetBody.attributes.add('flexible-asset-type-id', $FilterID.id)
        Write-Host "Creating new flexible asset"
        New-ITGlueFlexibleAssets -data $FlexAssetBody
    }
    #Otherwise Just Upload the data
    else {
        Write-Host "Updating Flexible Asset"
        $ExistingFlexAsset = $ExistingFlexAsset[-1]
        Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
    }
}
