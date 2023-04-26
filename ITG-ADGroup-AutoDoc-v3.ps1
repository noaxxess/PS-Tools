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


$APIEndpoint = "https://api.itglue.com"
$FlexAssetName = "ITGLue AutoDoc - Active Directory Groups v2"
$Description = "Lists all groups and users in them."

#####################################################################

if (Get-Module -ListAvailable -Name "ITGlueAPI") {
    Import-Module ITGlueAPI
} else {
    Install-Module ITGlueAPI -Force
    Import-Module ITGlueAPI
}

# Settings IT-Glue logon information
Add-ITGlueBaseURI -base_uri $APIEndpoint
Add-ITGlueAPIKey $APIKey

# Collect Data
$AllGroups = Get-AdGroup -filter *

foreach ($Group in $AllGroups) {
    $Contacts = @()
    $Members = Get-AdGroupMember $Group
    $MembersTable = $Members | Select-Object Name, distinguishedName | ConvertTo-Html -Fragment | Out-String

    foreach ($Member in $Members) {
        $ObjType = (Get-ADObject -Filter {SamAccountName -eq $Member.SamAccountName}).ObjectClass
        if($ObjType -eq 'User'){
            $Email = (Get-AdUser $Member -Properties EmailAddress).EmailAddress
            $Email
            }
        # if ($ObjType -eq 'Computer'){
        #     $ComputerName = 
        #     $Config = (Get-AdComputer $Member -Properties )
        # }
    }

    $FlexAssetBody = @{
        type       = 'flexible-assets'
        attributes = @{
            name   = $FlexAssetName
            traits = @{
                "group-name"   = $($group.name)
                "members"      = $MembersTable
                "guid"         = $($group.objectguid.guid)
                "tagged-users" = $Contacts.id
            }
        }
    }

    # Checking if the FlexibleAsset exists. If not, create a new one.
    $FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data

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
                            }
                        }
                    )
                }
            }
        }
        New-ITGlueFlexibleAssetTypes -Data $NewFlexAssetData
        $FilterID = (Get-ITGlueFlexibleAssetTypes -filter_name $FlexAssetName).data
    }

    # Upload data to IT-Glue. We try to match the Server name to the current computer name.
    $ExistingFlexAsset = (Get-ITGlueFlexibleAssets -filter_flexible_asset_type_id $Filterid.id -filter_organization_id $orgID).data | Where-Object { $_.attributes.traits.'group-name' -eq $($group.name) }

    # If the Asset does not exist, we edit the body to be in the form of a new asset, if not, we just upload.
    if (!$ExistingFlexAsset) {
        $FlexAssetBody.attributes.add('organization-id', $orgID)
        $FlexAssetBody.attributes.add('flexible-asset-type-id', $FilterID.id)
        Write-Host "Creating new flexible asset"
        New-ITGlueFlexibleAssets -data $FlexAssetBody
    } else {
        Write-Host "Updating Flexible Asset"
        $ExistingFlexAsset = $ExistingFlexAsset[-1]
        Set-ITGlueFlexibleAssets -id $ExistingFlexAsset.id -data $FlexAssetBody
    }
}
